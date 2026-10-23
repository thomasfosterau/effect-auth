/**
 * SCIM 2.0 provisioning — the identity provider's write path into this
 * directory (RFC 7643 / RFC 7644).
 *
 * Enterprise SSO answers "may this person sign in?". SCIM answers the other
 * half: "who exists, and who left?". An IdP (Okta, Entra ID, OneLogin, …)
 * pushes user and group lifecycle here over a small REST API, so an employee
 * who is deprovisioned in the IdP stops being able to sign in *without* anyone
 * waiting for a session to expire.
 *
 * ## Scoping
 *
 * A {@link ScimConnection} is **per organization**: it is the credential a
 * single tenant's IdP presents, and everything it can see or change is scoped
 * to `connection.organizationId`. A connection for org A cannot read, patch, or
 * even discover org B's members — cross-tenant reads answer `404`, exactly as
 * they would for an id that does not exist. That is the whole security model,
 * and every resource operation takes the authenticated connection as its first
 * argument so the scope can never be forgotten.
 *
 * The provisioning token is a bearer secret: it is returned **once**, from
 * {@link ScimService.createConnection}, and only its SHA-256 digest is stored
 * (the {@link module:token-hash} convention shared with API keys, magic links
 * and device codes).
 *
 * ## What SCIM resources map onto
 *
 * Nothing new is invented for SCIM; it is a projection of the core model.
 *
 * | SCIM                  | effect-auth                                          |
 * | --------------------- | ---------------------------------------------------- |
 * | `User.id`             | `User.id` (the surrogate key)                         |
 * | `User.userName`       | the primary email {@link Identifier}'s value          |
 * | `User.emails[]`       | the user's `email` identifiers                        |
 * | `User.displayName`    | `User.name`                                           |
 * | `User.active`         | NOT `attributes.scimDeactivated`                      |
 * | `User.externalId`     | `attributes.scimExternalId`                           |
 * | `Group`               | an organization {@link Team}                          |
 * | `Group.displayName`   | `Team.name`                                           |
 * | `Group.members[]`     | the team's members (`value` is the core user id)      |
 *
 * Users provisioned here are created with their email identifier **verified**:
 * the IdP is the system of record for that address, the same attestation an
 * OIDC `email_verified` claim or a signed SAML assertion carries.
 *
 * ## Deactivation is a soft disable
 *
 * `PATCH {"active": false}` and `DELETE /Users/:id` both **deactivate** rather
 * than delete: the user keeps their id, their identifiers and their audit
 * trail, gains `attributes.scimDeactivated = true`, and has every live session
 * revoked. Reactivation (`PATCH {"active": true}`) is then a single write, which
 * is what an IdP expects when someone returns from leave.
 *
 * Revoking sessions closes the door on anyone already signed in; to keep it
 * closed for *new* sign-ins, wire {@link ScimDeactivatedPlugin} into your hooks
 * stack. It mirrors `BannedUserPlugin` — a deactivated user fails session
 * validation instead of being silently let back in.
 *
 * @module scim
 */
import {
  Array as Arr,
  Clock,
  Context,
  Crypto,
  Data,
  DateTime,
  Effect,
  Layer,
  Option,
  Order,
  Predicate,
  Record as Rec,
  Schema,
  String as Str,
} from "effect";
import { flow } from "effect/Function";
import * as Errors from "./Errors.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";
import { Hooks, makePlugin } from "./Hooks.ts";
import {
  claimIdentifier,
  IdentifierStore,
  makeIdentifier,
  primaryEmail,
  type Identifier,
} from "./Identifier.ts";
import { OrganizationStore, type Member, type Team } from "./Organization.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
} from "./UserStore.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * A SCIM protocol failure, carrying the HTTP status and the RFC 7644 §3.12
 * `scimType` detail code the wire response must report.
 *
 * The status lives on the error rather than being inferred at the HTTP layer
 * because SCIM's status codes are part of its semantics: `409` with
 * `scimType: "uniqueness"` is how an IdP learns to reconcile rather than retry,
 * and `400` with `invalidPath` is how it learns to stop sending an operation.
 */
export class ScimError extends Data.TaggedError("ScimError")<{
  readonly message: string;
  /** HTTP status for this failure (400, 401, 404, 409, …). */
  readonly status: number;
  /** RFC 7644 §3.12 detail code, when one applies. */
  readonly scimType?: string;
  readonly cause?: unknown;
}> {}

const badRequest = (message: string, scimType?: string): ScimError =>
  new ScimError({ message, status: 400, ...(scimType !== undefined && { scimType }) });
const notFound = (message: string): ScimError => new ScimError({ message, status: 404 });
const conflict = (message: string): ScimError =>
  new ScimError({ message, status: 409, scimType: "uniqueness" });

// ---------------------------------------------------------------------------
// Attribute keys
// ---------------------------------------------------------------------------

/**
 * `User.attributes` key holding the SCIM-authoritative `userName`.
 *
 * `userName` is the user's **primary** email identifier. Which identifier that
 * is has to survive renames — after a `PATCH` of `userName`, the newly claimed
 * address is younger than the user's other emails, so "earliest verified email"
 * would silently hand `userName` back to a secondary address. Pinning it here
 * keeps the answer stable; when the key is absent (a user created outside SCIM)
 * the service falls back to {@link primaryEmail}.
 */
export const SCIM_USERNAME_ATTRIBUTE = "scimUserName";

/** `User.attributes` key set to `true` while a user is SCIM-deactivated. */
export const SCIM_DEACTIVATED_ATTRIBUTE = "scimDeactivated";

/** `User.attributes` key holding the IdP's own identifier for the user. */
export const SCIM_EXTERNAL_ID_ATTRIBUTE = "scimExternalId";

/**
 * Whether a user is currently deactivated by SCIM — the inverse of the SCIM
 * `active` attribute.
 *
 * Deactivation is deliberately a plain attribute rather than a column: it is
 * readable by any store, survives a round trip through JSON, and lets apps
 * gate on it without importing this module.
 */
export const isScimDeactivated = (user: Types.User): boolean =>
  user.attributes[SCIM_DEACTIVATED_ATTRIBUTE] === true;

/**
 * Hooks plugin that blocks SCIM-deactivated users at session validation.
 *
 * {@link ScimService} already revokes a user's sessions the moment the IdP
 * deactivates them, which handles everyone already signed in. This plugin
 * closes the other half — it stops a deactivated user from establishing a new
 * session at all, in exactly the way `BannedUserPlugin` stops a banned one.
 *
 * Zero-dependency, so compose it like any other plugin:
 * `ScimDeactivatedPlugin.pipe(Layer.provide(Hooks.Default))`, or as one entry
 * in a `composePlugins([...])` stack.
 */
export const ScimDeactivatedPlugin: Layer.Layer<Hooks, never, Hooks> = makePlugin({
  afterValidateSession: (sessionWithUser: Types.SessionWithUser) =>
    isScimDeactivated(sessionWithUser.user)
      ? Effect.fail(new Errors.UserBannedError({ message: "Your account has been deactivated" }))
      : Effect.succeed(sessionWithUser),
});

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/**
 * A tenant's SCIM connection: the provisioning credential one organization's
 * IdP presents, and the scope of everything it may do.
 */
export interface ScimConnection {
  readonly id: string;
  /** The only organization this connection can read or write. */
  readonly organizationId: string;
  /** SHA-256 hex digest of the bearer provisioning token; the raw token is never stored. */
  readonly tokenHash: string;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  /** Epoch milliseconds; refreshed on each authenticated request. */
  readonly lastUsedAt?: number;
}

/**
 * Persistent registry of SCIM connections.
 *
 * {@link getByTokenHash} is the authentication path, so index the `tokenHash`
 * column: it is looked up on every SCIM request. Conventions match the rest of
 * the library — `null` on a miss, no-op deletes, `AuthError` for infrastructure
 * failures.
 */
export class ScimConnectionStore extends Context.Service<
  ScimConnectionStore,
  {
    readonly create: (
      connection: ScimConnection,
    ) => Effect.Effect<ScimConnection, Errors.AuthError>;
    readonly getById: (id: string) => Effect.Effect<ScimConnection | null, Errors.AuthError>;
    /** Resolve a connection by the digest of its provisioning token. */
    readonly getByTokenHash: (
      tokenHash: string,
    ) => Effect.Effect<ScimConnection | null, Errors.AuthError>;
    readonly listByOrganization: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<ScimConnection>, Errors.AuthError>;
    readonly update: (
      connection: ScimConnection,
    ) => Effect.Effect<ScimConnection, Errors.AuthError>;
    /** Revoke a connection. A no-op for unknown ids. */
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/ScimConnectionStore") {}

/** Oldest first, by the epoch-millisecond `createdAt` every SCIM-listed record carries. */
const byCreatedAt: Order.Order<{ readonly createdAt: number }> = Order.mapInput(
  Order.Number,
  (record) => record.createdAt,
);

/**
 * In-memory {@link ScimConnectionStore}, keyed by connection id. Single-process
 * only — good for tests and single-instance deployments.
 *
 * Pass your own `Map` to inspect or pre-seed state in tests.
 */
export const memoryScimConnectionStore = (
  records: Map<string, ScimConnection> = new Map(),
): typeof ScimConnectionStore.Service => ({
  create: (connection) => Effect.sync(() => (records.set(connection.id, connection), connection)),
  getById: (id) => Effect.sync(() => records.get(id) ?? null),
  getByTokenHash: (tokenHash) =>
    Effect.sync(
      () => [...records.values()].find((record) => record.tokenHash === tokenHash) ?? null,
    ),
  listByOrganization: (organizationId) =>
    Effect.sync(() =>
      Arr.sort(
        Arr.filter([...records.values()], (record) => record.organizationId === organizationId),
        byCreatedAt,
      ),
    ),
  update: (connection) => Effect.sync(() => (records.set(connection.id, connection), connection)),
  delete: (id) => Effect.sync(() => void records.delete(id)),
});

/**
 * The slice of user persistence SCIM needs: create a user, read one back, and
 * write one whose profile or attributes changed.
 *
 * A dedicated tag rather than a reused one, following the same
 * module-declares-what-it-needs convention as `OAuthUserStore`,
 * `MagicLinkUserStore` and `AdminUserStore`. Back it with the same table as the
 * rest — it is the same `User` record.
 */
export class ScimUserStore extends Context.Service<
  ScimUserStore,
  {
    /**
     * Create a user. The store assigns `id`, `createdAt` and `updatedAt`.
     * `created` in the result is `true` only when this call inserted the user;
     * a user that already existed (as a find-or-create on the address returns)
     * reports `false`, and provisioning then fails with a conflict without
     * writing to it. The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly create: (input: {
      readonly name?: string;
      readonly image?: string;
      readonly attributes?: Types.Attributes;
      /**
       * The login handle the user is created with: a store that keeps it on
       * the user row writes it there on insert, and any other store ignores it
       * (see {@link NewUserIdentifier}).
       */
      readonly identifier?: NewUserIdentifier | undefined;
    }) => Effect.Effect<CreateUserResult, Errors.AuthError>;
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
    readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;
  }
>()("@effect-auth/ScimUserStore") {}

// ---------------------------------------------------------------------------
// Resource shapes
// ---------------------------------------------------------------------------

/** One entry of a SCIM `User.emails[]` multi-valued attribute. */
export interface ScimEmail {
  readonly value: string;
  /** `true` for the address that is also the `userName`. */
  readonly primary?: boolean;
  readonly type?: string;
}

/**
 * A SCIM `User` resource, in domain terms — the JSON envelope (`schemas`,
 * `meta`) is added at the HTTP layer.
 */
export interface ScimUserResource {
  /** The core user id; SCIM's `id` is this library's surrogate key verbatim. */
  readonly id: string;
  readonly userName: string;
  readonly displayName?: string;
  /** The IdP's own identifier, when it sent one. */
  readonly externalId?: string;
  readonly emails: ReadonlyArray<ScimEmail>;
  readonly active: boolean;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  /** Epoch milliseconds. */
  readonly updatedAt: number;
}

/**
 * A SCIM `Group` resource — an organization team.
 *
 * `members[].value` is a core user id. The optional `display` and `$ref`
 * members of RFC 7643 §4.2 are omitted: both are conveniences an IdP can
 * resolve itself, and populating them would cost a user read per member on
 * every list.
 */
export interface ScimGroupResource {
  readonly id: string;
  readonly displayName: string;
  readonly members: ReadonlyArray<{ readonly value: string }>;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  /** Epoch milliseconds. */
  readonly updatedAt: number;
}

/** A page of resources, shaped for the SCIM `ListResponse` envelope. */
export interface ScimListResult<A> {
  /** Matches *before* pagination. */
  readonly totalResults: number;
  /** 1-based index of the first returned resource. */
  readonly startIndex: number;
  readonly itemsPerPage: number;
  readonly resources: ReadonlyArray<A>;
}

/** Query parameters of a SCIM list request. */
export interface ScimListQuery {
  /** A `eq` filter, e.g. `userName eq "ada@acme.test"`. Nothing else is supported. */
  readonly filter?: string;
  /** 1-based; defaults to 1. */
  readonly startIndex?: number;
  /** Page size; defaults to (and is capped at) the configured maximum. */
  readonly count?: number;
}

/**
 * One entry of an RFC 7644 §3.5.2 `PATCH` request's `Operations` array.
 *
 * `path` admits an explicit `undefined` because that is what a decoded JSON
 * body hands over for an absent optional member, and the path-less form is a
 * dialect this service supports rather than an error.
 */
export interface ScimPatchOperation {
  /** `add`, `remove` or `replace` (case-insensitive). */
  readonly op: string;
  readonly path?: string | undefined;
  readonly value?: unknown;
}

/** The writable attributes of a SCIM `User`, as sent on `POST` or `PUT`. */
export interface ScimUserInput {
  readonly userName: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly emails?: ReadonlyArray<ScimEmail>;
  readonly active?: boolean;
}

/** The writable attributes of a SCIM `Group`. */
export interface ScimGroupInput {
  readonly displayName: string;
  readonly members?: ReadonlyArray<{ readonly value: string }>;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * Configuration for {@link ScimService}.
 */
export interface ScimConfig {
  /**
   * Organization role granted to users provisioned through SCIM, for every
   * connection. Unset, the provisioned organization's own `defaultRole`
   * decides (itself defaulting to `"member"`), which is what a tenant that
   * changed its default expects.
   */
  readonly defaultRole?: string;
  /**
   * Base path (or absolute URL) the SCIM endpoints are served under, used to
   * build each resource's `meta.location`. Default `"/scim/v2"`; set it to the
   * externally-visible URL (e.g. `"https://app.example.com/api/auth/scim/v2"`)
   * so an IdP can follow the locations it is handed.
   */
  readonly baseUrl?: string;
  /**
   * Largest page a list request may return, and the default page size.
   * Default `100`.
   */
  readonly maxPageSize?: number;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * SCIM 2.0 provisioning: per-organization bearer connections, and Users and Groups mapped onto users, identifiers and organization teams.
 *
 * Requires `ScimConnectionStore`, `ScimUserStore`, `OrganizationStore`, `IdentifierStore` and `SessionService`.
 */
export class ScimService extends Context.Service<
  ScimService,
  {
    /** Configured {@link ScimConfig.baseUrl}, for building `meta.location`. */
    readonly baseUrl: string;

    /**
     * Configured {@link ScimConfig.maxPageSize}. Advertised as `filter.maxResults`
     * in the `ServiceProviderConfig` document so an IdP can size its own pages.
     */
    readonly maxPageSize: number;

    /**
     * Mint a provisioning connection for an organization.
     *
     * The returned `token` is the bearer secret the IdP will present, and this
     * is the only time it exists in plaintext — store the digest, hand the
     * token to the administrator, forget it. Gate this behind an
     * organization-admin check at the HTTP layer.
     */
    readonly createConnection: (
      organizationId: string,
    ) => Effect.Effect<
      { readonly connection: ScimConnection; readonly token: string },
      Errors.AuthError
    >;

    /** Revoke a connection, immediately invalidating its token. */
    readonly revokeConnection: (connectionId: string) => Effect.Effect<void, Errors.AuthError>;

    /** The organization's connections (digests only — never the raw tokens). */
    readonly listConnections: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<ScimConnection>, Errors.AuthError>;

    /**
     * Resolve a raw bearer token to its connection, refreshing `lastUsedAt`.
     *
     * Fails with a `401` {@link ScimError} for an unknown or malformed token —
     * one uniform answer, so a caller cannot probe which tokens exist.
     */
    readonly authenticate: (
      token: string,
    ) => Effect.Effect<ScimConnection, ScimError | Errors.AuthError>;

    /**
     * Provision a user: create the account, claim its email identifiers as
     * IdP-verified, and add it to the connection's organization.
     *
     * A `userName` (or additional email) already claimed by another account
     * fails with `409 uniqueness`, which is what tells the IdP to reconcile
     * against the existing user instead of retrying.
     */
    readonly createUser: (
      connection: ScimConnection,
      input: ScimUserInput,
    ) => Effect.Effect<ScimUserResource, ScimError | Errors.AuthError>;

    /** Read one user. `404` when the id is unknown *or* outside the connection's org. */
    readonly getUser: (
      connection: ScimConnection,
      userId: string,
    ) => Effect.Effect<ScimUserResource, ScimError | Errors.AuthError>;

    /**
     * List the organization's users, newest last.
     *
     * Supports the one filter shape IdPs actually send —
     * `userName eq "…"` / `externalId eq "…"` — and rejects anything else with
     * `400 invalidFilter` rather than silently returning the whole directory.
     */
    readonly listUsers: (
      connection: ScimConnection,
      query?: ScimListQuery,
    ) => Effect.Effect<ScimListResult<ScimUserResource>, ScimError | Errors.AuthError>;

    /**
     * Replace a user (`PUT`). `emails` is authoritative when present: addresses
     * missing from it are unclaimed. When it is absent only `userName` is
     * reconciled, so a partial `PUT` cannot quietly delete addresses.
     */
    readonly replaceUser: (
      connection: ScimConnection,
      userId: string,
      input: ScimUserInput,
    ) => Effect.Effect<ScimUserResource, ScimError | Errors.AuthError>;

    /**
     * Apply an RFC 7644 §3.5.2 `PATCH`.
     *
     * The supported paths are the ones Okta and Entra ID actually send:
     * `replace` on `active`, `displayName`, `userName` and `externalId`, and
     * `add`/`remove` on `emails`. Entra's path-less form
     * (`{"op":"replace","value":{"active":false}}`) is expanded into the same
     * operations. Anything else fails with `400 invalidPath`.
     */
    readonly patchUser: (
      connection: ScimConnection,
      userId: string,
      operations: ReadonlyArray<ScimPatchOperation>,
    ) => Effect.Effect<ScimUserResource, ScimError | Errors.AuthError>;

    /**
     * `DELETE /Users/:id` — a soft disable, never a hard delete: the user is
     * marked deactivated and every live session is revoked.
     */
    readonly deactivateUser: (
      connection: ScimConnection,
      userId: string,
    ) => Effect.Effect<void, ScimError | Errors.AuthError>;

    /** Create a team from a SCIM `Group`. Members must already belong to the org. */
    readonly createGroup: (
      connection: ScimConnection,
      input: ScimGroupInput,
    ) => Effect.Effect<ScimGroupResource, ScimError | Errors.AuthError>;

    readonly getGroup: (
      connection: ScimConnection,
      groupId: string,
    ) => Effect.Effect<ScimGroupResource, ScimError | Errors.AuthError>;

    /** List the organization's teams; supports `displayName eq "…"`. */
    readonly listGroups: (
      connection: ScimConnection,
      query?: ScimListQuery,
    ) => Effect.Effect<ScimListResult<ScimGroupResource>, ScimError | Errors.AuthError>;

    /** Replace a group: rename it and set its membership to exactly `members`. */
    readonly replaceGroup: (
      connection: ScimConnection,
      groupId: string,
      input: ScimGroupInput,
    ) => Effect.Effect<ScimGroupResource, ScimError | Errors.AuthError>;

    /**
     * Apply a `PATCH` to a group: `replace` on `displayName`, and `add`/`remove`
     * on `members` (including the `members[value eq "…"]` path filter both
     * major IdPs use to remove one member).
     */
    readonly patchGroup: (
      connection: ScimConnection,
      groupId: string,
      operations: ReadonlyArray<ScimPatchOperation>,
    ) => Effect.Effect<ScimGroupResource, ScimError | Errors.AuthError>;

    /** Delete the team. Its members keep their organization membership. */
    readonly deleteGroup: (
      connection: ScimConnection,
      groupId: string,
    ) => Effect.Effect<void, ScimError | Errors.AuthError>;
  }
>()("@effect-auth/ScimService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: ScimConfig = {}) =>
    Layer.effect(ScimService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// ---------------------------------------------------------------------------
// Filter parsing
// ---------------------------------------------------------------------------

/**
 * The sliver of the RFC 7644 §3.4.2.2 filter grammar worth supporting:
 * `attribute eq "value"`. Okta and Entra ID send exactly this to look a
 * resource up before deciding whether to create it, and nothing else.
 */
const FILTER_PATTERN = /^\s*([A-Za-z][\w.]*)\s+([A-Za-z]+)\s+(?:"([^"]*)"|'([^']*)')\s*$/;

interface ParsedFilter {
  readonly attribute: string;
  readonly value: string;
}

const parseFilter = (
  filter: string,
  supported: ReadonlyArray<string>,
): Effect.Effect<ParsedFilter, ScimError> => {
  const match = FILTER_PATTERN.exec(filter);
  if (match === null) {
    return Effect.fail(
      badRequest(
        `Unsupported filter "${filter}": only \`attribute eq "value"\` is supported`,
        "invalidFilter",
      ),
    );
  }
  // The attribute and operator groups are not optional in FILTER_PATTERN, so
  // a match always fills them; the defaults only satisfy the index type.
  const [, attribute = "", operator = "", doubleQuoted, singleQuoted] = match;
  if (operator.toLowerCase() !== "eq") {
    return Effect.fail(
      badRequest(
        `Unsupported filter operator "${operator}": only \`eq\` is supported`,
        "invalidFilter",
      ),
    );
  }
  const canonical = supported.find((name) => name.toLowerCase() === attribute.toLowerCase());
  if (canonical === undefined) {
    return Effect.fail(
      badRequest(
        `Unsupported filter attribute "${attribute}": filter on ${supported.join(" or ")}`,
        "invalidFilter",
      ),
    );
  }
  return Effect.succeed({ attribute: canonical, value: doubleQuoted ?? singleQuoted ?? "" });
};

/** `members[value eq "abc"]` — the path filter both major IdPs use on removes. */
const MEMBER_PATH_PATTERN = /^members\[\s*value\s+eq\s+(?:"([^"]*)"|'([^']*)')\s*\]$/i;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

const normalizeEmail = (value: string): string => value.trim().toLowerCase();

const parseBooleanString = (value: string): Option.Option<boolean> => {
  const lowered = value.trim().toLowerCase();
  return lowered === "true"
    ? Option.some(true)
    : lowered === "false"
      ? Option.some(false)
      : Option.none();
};

/** SCIM sends booleans as JSON booleans; Entra ID sometimes sends strings. */
const asBoolean = flow(
  Schema.decodeUnknownOption(Schema.Union([Schema.Boolean, Schema.String])),
  Option.flatMap((value) =>
    Predicate.isBoolean(value) ? Option.some(value) : parseBooleanString(value),
  ),
  Option.getOrNull,
);

const asString = flow(
  Schema.decodeUnknownOption(Schema.String),
  Option.map(Str.trim),
  Option.filter(Str.isNonEmpty),
  Option.getOrNull,
);

/**
 * Read the strings out of a multi-valued patch value: an array, or a bare
 * entry, where each entry is a string or an object with a string `value`.
 */
const stringEntries = (value: unknown): ReadonlyArray<string> => {
  const entries: ReadonlyArray<unknown> = Array.isArray(value) ? value : [value];
  return Arr.flatMap(entries, (entry) =>
    Predicate.isString(entry)
      ? [entry]
      : Predicate.isObjectOrArray(entry) &&
          Predicate.hasProperty(entry, "value") &&
          Predicate.isString(entry.value)
        ? [entry.value]
        : [],
  );
};

/** Read `emails`-shaped patch values: an array, or a bare object/string. */
const emailValues = flow(stringEntries, Arr.map(normalizeEmail));

/** Read `members`-shaped patch values into core user ids. */
const memberValues = stringEntries;

/** The PATCH ops SCIM defines. */
type PatchOp = "add" | "remove" | "replace";

/** The operation's `op`, normalized, or a `400` for one SCIM does not define. */
const parsePatchOp = (operation: ScimPatchOperation): Effect.Effect<PatchOp, ScimError> => {
  const op = operation.op.trim().toLowerCase();
  return op === "add" || op === "remove" || op === "replace"
    ? Effect.succeed(op)
    : Effect.fail(badRequest(`Unsupported PATCH op "${operation.op}"`, "invalidSyntax"));
};

/** One `path`/`value` pair of a PATCH operation, after path-less expansion. */
interface PatchEntry {
  readonly path: string;
  readonly value: unknown;
}

export const make = (
  config: ScimConfig = {},
): Effect.Effect<
  typeof ScimService.Service,
  never,
  | ScimConnectionStore
  | ScimUserStore
  | IdentifierStore
  | OrganizationStore
  | SessionService
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const baseUrl = (config.baseUrl ?? "/scim/v2").replace(/\/+$/, "");
    const maxPageSize = config.maxPageSize ?? 100;

    const connections = yield* ScimConnectionStore;
    const users = yield* ScimUserStore;
    const identifiers = yield* IdentifierStore;
    const orgs = yield* OrganizationStore;
    const sessions = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    const randomId = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomUUIDv4.pipe(
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate id", cause }),
        ),
      );

    const randomToken = (): Effect.Effect<string, Errors.AuthError> => randomBase64UrlToken(crypto);

    /**
     * The organization role a SCIM-provisioned member receives: the SCIM
     * config's role when the app pinned one for every connection, else the
     * organization's own `defaultRole`, else `"member"`.
     */
    const provisioningRole = (organizationId: string): Effect.Effect<string, Errors.AuthError> =>
      config.defaultRole !== undefined
        ? Effect.succeed(config.defaultRole)
        : Effect.map(
            orgs.getOrganizationById(organizationId),
            (organization) => organization?.defaultRole ?? "member",
          );

    // --- Reads -------------------------------------------------------------

    const emailIdentifiers = (all: ReadonlyArray<Identifier>): ReadonlyArray<Identifier> =>
      all.filter((identifier) => identifier.type === "email");

    /**
     * Project a core user + its identifiers into a SCIM `User`.
     *
     * `userName` is the pinned primary address (see
     * {@link SCIM_USERNAME_ATTRIBUTE}), falling back to the earliest verified
     * email for users this module did not create, and finally to the user id so
     * the resource is always well-formed.
     */
    const toUserResource = (user: Types.User, all: ReadonlyArray<Identifier>): ScimUserResource => {
      const emails = emailIdentifiers(all);
      const pinned = user.attributes[SCIM_USERNAME_ATTRIBUTE];
      const userName =
        Predicate.isString(pinned) && emails.some((e) => e.value === pinned)
          ? pinned
          : (primaryEmail(all)?.value ?? emails[0]?.value ?? user.id);
      const externalId = user.attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
      return {
        id: user.id,
        userName,
        ...(user.name !== undefined && { displayName: user.name }),
        ...(Predicate.isString(externalId) && { externalId }),
        emails: emails.map((identifier) => ({
          value: identifier.value,
          ...(identifier.value === userName && { primary: true }),
          type: "work",
        })),
        active: !isScimDeactivated(user),
        createdAt: user.createdAt.getTime(),
        updatedAt: user.updatedAt.getTime(),
      };
    };

    const readUserResource = (user: Types.User) =>
      Effect.map(identifiers.listByUser(user.id), (all) => toUserResource(user, all));

    /**
     * Resolve a user *within the connection's organization*.
     *
     * The membership check is the tenant boundary: a user who exists but
     * belongs to another organization is reported as absent, so a connection
     * cannot use 404-vs-403 to enumerate the rest of the directory.
     */
    const requireUser = (connection: ScimConnection, userId: string) =>
      Effect.gen(function* () {
        const member = yield* orgs.getMember(connection.organizationId, userId);
        if (member === null) return yield* notFound(`User "${userId}" not found`);
        const user = yield* users.get(userId);
        if (user === null) return yield* notFound(`User "${userId}" not found`);
        return user;
      });

    const requireTeam = (connection: ScimConnection, groupId: string) =>
      Effect.gen(function* () {
        const team = yield* orgs.getTeam(groupId);
        if (team === null || team.organizationId !== connection.organizationId) {
          return yield* notFound(`Group "${groupId}" not found`);
        }
        return team;
      });

    const toGroupResource = (team: Team) =>
      Effect.map(orgs.listTeamMembers(team.id), (members) => ({
        id: team.id,
        displayName: team.name,
        members: members.map((member) => ({ value: member.userId })),
        createdAt: team.createdAt,
        updatedAt: team.updatedAt,
      }));

    /** Slice a filtered, ordered array into a SCIM `ListResponse` page. */
    const paginate = <A>(all: ReadonlyArray<A>, query?: ScimListQuery): ScimListResult<A> => {
      const startIndex = Math.max(1, Math.trunc(query?.startIndex ?? 1));
      const count = Math.max(0, Math.min(Math.trunc(query?.count ?? maxPageSize), maxPageSize));
      const resources = all.slice(startIndex - 1, startIndex - 1 + count);
      return {
        totalResults: all.length,
        startIndex,
        itemsPerPage: resources.length,
        resources,
      };
    };

    // --- Writes ------------------------------------------------------------

    /**
     * Claim an email for a user as IdP-verified, or report a SCIM conflict:
     * another user's address, or one this user cannot hold beside the ones it
     * has (a store that keeps one email per user), is `409 uniqueness`.
     */
    const claimEmail = (userId: string, email: string) =>
      DateTime.nowAsDate.pipe(
        Effect.flatMap((verifiedAt) =>
          claimIdentifier(
            identifiers,
            makeIdentifier({
              userId,
              type: "email",
              value: email,
              // The IdP is the system of record for its users' addresses.
              verified: true,
              verifiedAt,
            }),
          ),
        ),
        Effect.catchTags({
          IdentifierTakenError: () =>
            Effect.fail(conflict(`The email "${email}" is already in use`)),
          IdentifierRefusedError: (error) => Effect.fail(conflict(error.message)),
        }),
      );

    const writeAttributes = (user: Types.User, attributes: Types.Attributes) =>
      Effect.flatMap(DateTime.nowAsDate, (updatedAt) =>
        users.update({ ...user, attributes, updatedAt }),
      );

    /**
     * Flip a user's `active` state. Deactivation revokes every live session, so
     * the door closes now rather than whenever the session would have expired.
     */
    const setActive = (user: Types.User, active: boolean) =>
      Effect.gen(function* () {
        const attributes = { ...user.attributes };
        if (active) {
          delete attributes[SCIM_DEACTIVATED_ATTRIBUTE];
        } else {
          attributes[SCIM_DEACTIVATED_ATTRIBUTE] = true;
        }
        const updated = yield* writeAttributes(user, attributes);
        if (!active) yield* sessions.invalidateUserSessions(user.id);
        return updated;
      });

    /** Repoint `userName` at `email`, claiming it and unclaiming the old one. */
    const renameUserName = (user: Types.User, email: string) =>
      Effect.gen(function* () {
        const all = yield* identifiers.listByUser(user.id);
        const current = toUserResource(user, all).userName;
        if (current === email) return user;
        const existing = emailIdentifiers(all).find((identifier) => identifier.value === email);
        if (existing === undefined) yield* claimEmail(user.id, email);
        const previous = emailIdentifiers(all).find((identifier) => identifier.value === current);
        if (previous !== undefined) yield* identifiers.delete(previous.id);
        return yield* writeAttributes(user, {
          ...user.attributes,
          [SCIM_USERNAME_ATTRIBUTE]: email,
        });
      });

    const addTeamMemberScoped = (connection: ScimConnection, teamId: string, userId: string) =>
      Effect.gen(function* () {
        const member = yield* orgs.getMember(connection.organizationId, userId);
        if (member === null) {
          return yield* badRequest(
            `User "${userId}" is not a member of this organization`,
            "invalidValue",
          );
        }
        const existing = yield* orgs.listTeamMembers(teamId);
        if (existing.some((entry) => entry.userId === userId)) return;
        yield* orgs.addTeamMember(teamId, userId);
      });

    /**
     * Make a team's membership exactly `desiredIds`: remove each current member
     * not in it, then add the rest, in the order the IdP sent them.
     */
    const replaceTeamMembers = (
      connection: ScimConnection,
      teamId: string,
      desiredIds: ReadonlyArray<string>,
    ) =>
      Effect.gen(function* () {
        const existing = yield* orgs.listTeamMembers(teamId);
        const missing = yield* Effect.reduce(
          existing,
          () => Arr.dedupe(desiredIds),
          (remaining, member) =>
            Effect.as(
              Arr.contains(remaining, member.userId)
                ? Effect.void
                : orgs.removeTeamMember(teamId, member.userId),
              Arr.filter(remaining, (id) => id !== member.userId),
            ),
        );
        yield* Effect.forEach(
          missing,
          (userId) => addTeamMemberScoped(connection, teamId, userId),
          { concurrency: 1, discard: true },
        );
      });

    /** Set or clear the user's `externalId`; `remove` or a non-string value clears it. */
    const patchExternalId = (user: Types.User, op: PatchOp, { value }: PatchEntry) => {
      const externalId = asString(value);
      const attributes = { ...user.attributes };
      if (op === "remove" || externalId === null) {
        delete attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
      } else {
        attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = externalId;
      }
      return writeAttributes(user, attributes);
    };

    /**
     * Unclaim the listed email addresses (every address when `values` is
     * empty), keeping the one `userName` resolves to.
     */
    const removeUserEmails = (user: Types.User, values: ReadonlyArray<string>) =>
      Effect.gen(function* () {
        const all = yield* identifiers.listByUser(user.id);
        const userName = toUserResource(user, all).userName;
        yield* Effect.forEach(
          Arr.filter(
            emailIdentifiers(all),
            (identifier) =>
              // Never unclaim the address `userName` resolves to — that
              // would leave the resource without the handle it is keyed by.
              identifier.value !== userName &&
              (Arr.isReadonlyArrayEmpty(values) || values.includes(identifier.value)),
          ),
          (identifier) => identifiers.delete(identifier.id),
          { concurrency: 1, discard: true },
        );
      });

    /** Claim one email address for the user; another user's address is a `409`. */
    const addUserEmail = (user: Types.User, email: string) =>
      Effect.gen(function* () {
        const existing = yield* identifiers.getByValue("email", email);
        if (existing !== null) {
          if (existing.userId === user.id) return;
          return yield* conflict(`The email "${email}" is already in use`);
        }
        yield* claimEmail(user.id, email);
      });

    /** Apply an `emails` PATCH entry: unclaim on `remove`, else claim each address. */
    const patchUserEmails = (user: Types.User, op: PatchOp, { value }: PatchEntry) => {
      const values = emailValues(value);
      const applied =
        op === "remove"
          ? removeUserEmails(user, values)
          : Effect.forEach(
              Arr.filter(values, (email) => email !== ""),
              (email) => addUserEmail(user, email),
              { concurrency: 1, discard: true },
            );
      return Effect.as(applied, user);
    };

    /** Apply an `active` PATCH entry, revoking sessions on deactivation. */
    const patchActive = (user: Types.User, { value }: PatchEntry) => {
      const active = asBoolean(value);
      if (active === null) {
        return Effect.fail(badRequest("active must be a boolean", "invalidValue"));
      }
      return active === isScimDeactivated(user) ? setActive(user, active) : Effect.succeed(user);
    };

    /** Apply a `userName` PATCH entry. */
    const patchUserName = (user: Types.User, { value }: PatchEntry) => {
      const email = asString(value);
      if (email === null) {
        return Effect.fail(badRequest("userName must be a non-empty string", "invalidValue"));
      }
      return renameUserName(user, normalizeEmail(email));
    };

    /** Apply a `displayName` PATCH entry; a non-string value leaves the name as is. */
    const patchDisplayName = (user: Types.User, { value }: PatchEntry) => {
      const name = asString(value);
      return Effect.flatMap(DateTime.nowAsDate, (updatedAt) =>
        users.update({
          ...user,
          ...(name === null ? {} : { name }),
          updatedAt,
        }),
      );
    };

    /** Apply one expanded PATCH entry to a user, returning the updated user. */
    const patchUserEntry = (user: Types.User, op: PatchOp, entry: PatchEntry) => {
      const attribute = entry.path.toLowerCase();
      if (attribute === "active") return patchActive(user, entry);
      if (attribute === "displayname") return patchDisplayName(user, entry);
      if (attribute === "username") return patchUserName(user, entry);
      if (attribute === "externalid") return patchExternalId(user, op, entry);
      if (attribute === "emails" || attribute.startsWith("emails[")) {
        return patchUserEmails(user, op, entry);
      }
      return Effect.fail(badRequest(`Unsupported PATCH path "${entry.path}"`, "invalidPath"));
    };

    /** Apply one PATCH operation to a user, returning the updated user. */
    const patchUserOperation = (user: Types.User, operation: ScimPatchOperation) =>
      Effect.gen(function* () {
        const op = yield* parsePatchOp(operation);

        // Entra ID omits `path` and sends an attribute map as the value.
        // Expand it so both dialects go through one code path.
        const expanded: ReadonlyArray<PatchEntry> =
          operation.path === undefined || operation.path.trim() === ""
            ? Predicate.isObject(operation.value)
              ? Rec.collect(operation.value, (path, value) => ({ path, value }))
              : []
            : [{ path: operation.path.trim(), value: operation.value }];

        if (Arr.isReadonlyArrayEmpty(expanded)) {
          return yield* badRequest("PATCH operation has no usable path", "invalidPath");
        }

        return yield* Effect.reduce(
          expanded,
          () => user,
          (current, entry) => patchUserEntry(current, op, entry),
        );
      });

    /** Rename a team; a team that vanished meanwhile is a `404`. */
    const renameTeam = (groupId: string, team: Team, displayName: string) =>
      Effect.gen(function* () {
        const renamed = yield* orgs.updateTeam({
          ...team,
          name: displayName,
          updatedAt: yield* Clock.currentTimeMillis,
        });
        if (renamed === null) return yield* notFound(`Group "${groupId}" not found`);
        return renamed;
      });

    /** Remove the listed members, or every member when `ids` is empty. */
    const removeTeamMembers = (team: Team, ids: ReadonlyArray<string>) =>
      Effect.gen(function* () {
        // `remove` with no value clears the membership entirely.
        const targets = Arr.isReadonlyArrayEmpty(ids)
          ? Arr.map(yield* orgs.listTeamMembers(team.id), (member) => member.userId)
          : ids;
        yield* Effect.forEach(targets, (userId) => orgs.removeTeamMember(team.id, userId), {
          concurrency: 1,
          discard: true,
        });
      });

    /** Apply a `members` PATCH operation to a team. */
    const patchTeamMembers = (
      connection: ScimConnection,
      team: Team,
      op: PatchOp,
      operation: ScimPatchOperation,
    ) => {
      const ids = memberValues(operation.value);
      const applied =
        op === "remove"
          ? removeTeamMembers(team, ids)
          : op === "replace"
            ? replaceTeamMembers(connection, team.id, ids)
            : Effect.forEach(ids, (userId) => addTeamMemberScoped(connection, team.id, userId), {
                concurrency: 1,
                discard: true,
              });
      return Effect.as(applied, team);
    };

    /** Apply a path-less PATCH operation (an attribute map) to a team. */
    const patchTeamAttributes = (groupId: string, team: Team, { value }: ScimPatchOperation) => {
      if (!Predicate.isObject(value)) {
        return Effect.fail(badRequest("PATCH operation has no usable path", "invalidPath"));
      }
      const displayName = asString(value["displayName"]);
      if (displayName === null) {
        return Effect.fail(badRequest("Unsupported path-less PATCH value", "invalidPath"));
      }
      return renameTeam(groupId, team, displayName);
    };

    /** Apply one PATCH operation to a team, returning the updated team. */
    const patchGroupOperation = (
      connection: ScimConnection,
      groupId: string,
      team: Team,
      operation: ScimPatchOperation,
    ) =>
      Effect.gen(function* () {
        const op = yield* parsePatchOp(operation);
        const path = (operation.path ?? "").trim();

        // Path-less form: an attribute map, exactly as for users.
        if (path === "") {
          return yield* patchTeamAttributes(groupId, team, operation);
        }

        if (path.toLowerCase() === "displayname") {
          const displayName = asString(operation.value);
          if (displayName === null) {
            return yield* badRequest("displayName must be a non-empty string", "invalidValue");
          }
          return yield* renameTeam(groupId, team, displayName);
        }

        const pathFilter = MEMBER_PATH_PATTERN.exec(path);
        if (pathFilter !== null) {
          if (op !== "remove") {
            return yield* badRequest(`Only \`remove\` is supported on "${path}"`, "invalidPath");
          }
          yield* orgs.removeTeamMember(team.id, pathFilter[1] ?? pathFilter[2] ?? "");
          return team;
        }

        if (path.toLowerCase() === "members") {
          return yield* patchTeamMembers(connection, team, op, operation);
        }

        return yield* badRequest(`Unsupported PATCH path "${path}"`, "invalidPath");
      });

    return {
      baseUrl,
      maxPageSize,

      createConnection: Effect.fn("ScimService.createConnection")(function* (
        organizationId: string,
      ) {
        const token = yield* randomToken();
        const connection: ScimConnection = {
          id: yield* randomId(),
          organizationId,
          tokenHash: hashToken(token),
          createdAt: yield* Clock.currentTimeMillis,
        };
        return { connection: yield* connections.create(connection), token };
      }),

      revokeConnection: Effect.fn("ScimService.revokeConnection")((connectionId: string) =>
        connections.delete(connectionId),
      ),

      listConnections: Effect.fn("ScimService.listConnections")((organizationId: string) =>
        connections.listByOrganization(organizationId),
      ),

      authenticate: Effect.fn("ScimService.authenticate")(function* (token: string) {
        // One answer for "no token", "malformed token" and "unknown token": a
        // caller must not be able to tell them apart.
        const unauthorized = new ScimError({
          message: "Invalid SCIM provisioning token",
          status: 401,
        });
        if (token.trim() === "") return yield* unauthorized;
        const connection = yield* connections.getByTokenHash(hashToken(token));
        if (connection === null) return yield* unauthorized;
        // Best-effort activity stamp: a failed touch must not fail the request
        // the IdP actually made.
        yield* connections
          .update({ ...connection, lastUsedAt: yield* Clock.currentTimeMillis })
          .pipe(Effect.ignore);
        return connection;
      }),

      createUser: Effect.fn("ScimService.createUser")(function* (
        connection: ScimConnection,
        input: ScimUserInput,
      ) {
        const userName = normalizeEmail(input.userName);
        if (userName === "") {
          return yield* badRequest("userName is required", "invalidValue");
        }
        const extras = Arr.dedupe(
          (input.emails ?? [])
            .map((email) => normalizeEmail(email.value))
            .filter((email) => email !== "" && email !== userName),
        );

        // Check every address up front: a conflict discovered halfway through
        // would leave a user created with only some of its identifiers.
        const taken = yield* Effect.findFirst([userName, ...extras], (email) =>
          Effect.map(identifiers.getByValue("email", email), (existing) => existing !== null),
        );
        if (Option.isSome(taken)) {
          return yield* conflict(`The email "${taken.value}" is already in use`);
        }

        const attributes: Types.Attributes = {
          [SCIM_USERNAME_ATTRIBUTE]: userName,
          ...(input.externalId !== undefined && { [SCIM_EXTERNAL_ID_ATTRIBUTE]: input.externalId }),
          ...(input.active === false && { [SCIM_DEACTIVATED_ATTRIBUTE]: true }),
        };

        // `userName` is the user's primary address, created with the user;
        // the IdP is the system of record for its users' addresses.
        const { user } = yield* createUserWithIdentifier(
          identifiers,
          { type: "email", value: userName, verified: true, verifiedAt: yield* DateTime.nowAsDate },
          (identifier) =>
            users.create({
              ...(input.displayName !== undefined && { name: input.displayName }),
              attributes,
              identifier,
            }),
        ).pipe(
          Effect.catchTag("IdentifierTakenError", () =>
            Effect.fail(conflict(`The email "${userName}" is already in use`)),
          ),
        );

        yield* Effect.forEach(extras, (email) => claimEmail(user.id, email), {
          concurrency: 1,
          discard: true,
        });

        const existingMember = yield* orgs.getMember(connection.organizationId, user.id);
        if (existingMember === null) {
          const member: Member = {
            id: yield* randomId(),
            organizationId: connection.organizationId,
            userId: user.id,
            role: yield* provisioningRole(connection.organizationId),
            status: "active",
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* orgs.createMember(member);
        }

        return yield* readUserResource(user);
      }),

      getUser: Effect.fn("ScimService.getUser")(function* (
        connection: ScimConnection,
        userId: string,
      ) {
        return yield* readUserResource(yield* requireUser(connection, userId));
      }),

      listUsers: Effect.fn("ScimService.listUsers")(function* (
        connection: ScimConnection,
        query?: ScimListQuery,
      ) {
        const parsed =
          query?.filter === undefined
            ? null
            : yield* parseFilter(query.filter, ["userName", "externalId"]);

        const members = yield* orgs.listMembersByOrganization(connection.organizationId);
        const ordered = Arr.sort(members, byCreatedAt);

        const matched = yield* Effect.forEach(
          ordered,
          (member) =>
            Effect.gen(function* () {
              const user = yield* users.get(member.userId);
              // A membership row whose user is gone is stale, not an error.
              if (user === null) return Option.none<ScimUserResource>();
              const resource = yield* readUserResource(user);
              if (parsed === null) return Option.some(resource);
              const matches =
                parsed.attribute === "userName"
                  ? resource.userName.toLowerCase() === parsed.value.trim().toLowerCase()
                  : resource.externalId === parsed.value;
              return matches ? Option.some(resource) : Option.none<ScimUserResource>();
            }),
          { concurrency: 1 },
        );

        return paginate(Arr.getSomes(matched), query);
      }),

      replaceUser: Effect.fn("ScimService.replaceUser")(function* (
        connection: ScimConnection,
        userId: string,
        input: ScimUserInput,
      ) {
        const user = yield* requireUser(connection, userId);
        const userName = normalizeEmail(input.userName);
        if (userName === "") {
          return yield* badRequest("userName is required", "invalidValue");
        }

        let current = yield* renameUserName(user, userName);

        // `emails` is authoritative only when the IdP sent it; a PUT that omits
        // it is reconciling the profile, not clearing the address book.
        if (input.emails !== undefined) {
          const desired = Arr.dedupe([
            userName,
            ...input.emails.map((email) => normalizeEmail(email.value)).filter((e) => e !== ""),
          ]);
          const all = yield* identifiers.listByUser(current.id);
          const owner = current.id;
          const missing = yield* Effect.reduce(
            emailIdentifiers(all),
            () => desired,
            (remaining, identifier) =>
              Effect.as(
                Arr.contains(remaining, identifier.value)
                  ? Effect.void
                  : identifiers.delete(identifier.id),
                Arr.filter(remaining, (email) => email !== identifier.value),
              ),
          );
          yield* Effect.forEach(missing, (email) => claimEmail(owner, email), {
            concurrency: 1,
            discard: true,
          });
        }

        const attributes = { ...current.attributes };
        if (input.externalId === undefined) {
          delete attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
        } else {
          attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = input.externalId;
        }
        current = yield* users.update({
          ...current,
          ...(input.displayName !== undefined && { name: input.displayName }),
          attributes,
          updatedAt: yield* DateTime.nowAsDate,
        });

        if (input.active !== undefined && input.active === isScimDeactivated(current)) {
          current = yield* setActive(current, input.active);
        }

        return yield* readUserResource(current);
      }),

      patchUser: Effect.fn("ScimService.patchUser")(function* (
        connection: ScimConnection,
        userId: string,
        operations: ReadonlyArray<ScimPatchOperation>,
      ) {
        const user = yield* requireUser(connection, userId);
        const patched = yield* Effect.reduce(operations, () => user, patchUserOperation);
        return yield* readUserResource(patched);
      }),

      deactivateUser: Effect.fn("ScimService.deactivateUser")(function* (
        connection: ScimConnection,
        userId: string,
      ) {
        const user = yield* requireUser(connection, userId);
        yield* setActive(user, false);
      }),

      createGroup: Effect.fn("ScimService.createGroup")(function* (
        connection: ScimConnection,
        input: ScimGroupInput,
      ) {
        const displayName = input.displayName.trim();
        if (displayName === "") {
          return yield* badRequest("displayName is required", "invalidValue");
        }
        const now = yield* Clock.currentTimeMillis;
        const team = yield* orgs.createTeam({
          id: yield* randomId(),
          organizationId: connection.organizationId,
          name: displayName,
          createdAt: now,
          updatedAt: now,
        });
        yield* Effect.forEach(
          input.members ?? [],
          (member) => addTeamMemberScoped(connection, team.id, member.value),
          { concurrency: 1, discard: true },
        );
        return yield* toGroupResource(team);
      }),

      getGroup: Effect.fn("ScimService.getGroup")(function* (
        connection: ScimConnection,
        groupId: string,
      ) {
        return yield* toGroupResource(yield* requireTeam(connection, groupId));
      }),

      listGroups: Effect.fn("ScimService.listGroups")(function* (
        connection: ScimConnection,
        query?: ScimListQuery,
      ) {
        const parsed =
          query?.filter === undefined ? null : yield* parseFilter(query.filter, ["displayName"]);

        const teams = yield* orgs.listTeams(connection.organizationId);
        const ordered = Arr.sort(teams, byCreatedAt);

        const resources = yield* Effect.forEach(
          Arr.filter(ordered, (team) => parsed === null || team.name === parsed.value),
          (team) => toGroupResource(team),
          { concurrency: 1 },
        );
        return paginate(resources, query);
      }),

      replaceGroup: Effect.fn("ScimService.replaceGroup")(function* (
        connection: ScimConnection,
        groupId: string,
        input: ScimGroupInput,
      ) {
        const team = yield* requireTeam(connection, groupId);
        const displayName = input.displayName.trim();
        if (displayName === "") {
          return yield* badRequest("displayName is required", "invalidValue");
        }
        const renamed = yield* orgs.updateTeam({
          ...team,
          name: displayName,
          updatedAt: yield* Clock.currentTimeMillis,
        });
        if (renamed === null) return yield* notFound(`Group "${groupId}" not found`);

        if (input.members !== undefined) {
          yield* replaceTeamMembers(
            connection,
            team.id,
            input.members.map((member) => member.value),
          );
        }

        return yield* toGroupResource(renamed);
      }),

      patchGroup: Effect.fn("ScimService.patchGroup")(function* (
        connection: ScimConnection,
        groupId: string,
        operations: ReadonlyArray<ScimPatchOperation>,
      ) {
        const team = yield* requireTeam(connection, groupId);
        const patched = yield* Effect.reduce(
          operations,
          () => team,
          (current, operation) => patchGroupOperation(connection, groupId, current, operation),
        );
        return yield* toGroupResource(patched);
      }),

      deleteGroup: Effect.fn("ScimService.deleteGroup")(function* (
        connection: ScimConnection,
        groupId: string,
      ) {
        const team = yield* requireTeam(connection, groupId);
        yield* orgs.deleteTeam(team.id);
      }),
    } satisfies typeof ScimService.Service;
  });
