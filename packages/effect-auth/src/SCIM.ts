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
 * A {@link SCIMConnection} is **per organization**: it is the credential a
 * single tenant's IdP presents, and everything it can see or change is scoped
 * to `connection.organizationId`. A connection for org A cannot read, patch, or
 * even discover org B's members — cross-tenant reads answer `404`, exactly as
 * they would for an id that does not exist. That is the whole security model,
 * and every resource operation takes the authenticated connection as its first
 * argument so the scope can never be forgotten.
 *
 * The provisioning token is a bearer secret: it is returned **once**, from
 * {@link SCIMService.createConnection}, and only its SHA-256 digest is stored
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
 * closed for *new* sign-ins, wire {@link SCIMDeactivatedPlugin} into your hooks
 * stack. It mirrors `BannedUserPlugin` — a deactivated user fails session
 * validation instead of being silently let back in.
 *
 * @module scim
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { Hooks, makePlugin } from "./Hooks.ts";
import {
  claimIdentifier,
  IdentifierStore,
  makeIdentifier,
  primaryEmail,
  type Identifier,
} from "./Identifier.ts";
import { OrganizationStore, type Member, type Team } from "./Organization.ts";
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
export class SCIMError extends Data.TaggedError("SCIMError")<{
  readonly message: string;
  /** HTTP status for this failure (400, 401, 404, 409, …). */
  readonly status: number;
  /** RFC 7644 §3.12 detail code, when one applies. */
  readonly scimType?: string;
  readonly cause?: unknown;
}> {}

const badRequest = (message: string, scimType?: string): SCIMError =>
  new SCIMError({ message, status: 400, ...(scimType !== undefined && { scimType }) });
const notFound = (message: string): SCIMError => new SCIMError({ message, status: 404 });
const conflict = (message: string): SCIMError =>
  new SCIMError({ message, status: 409, scimType: "uniqueness" });

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
export const isSCIMDeactivated = (user: Types.User): boolean =>
  user.attributes[SCIM_DEACTIVATED_ATTRIBUTE] === true;

/**
 * Hooks plugin that blocks SCIM-deactivated users at session validation.
 *
 * {@link SCIMService} already revokes a user's sessions the moment the IdP
 * deactivates them, which handles everyone already signed in. This plugin
 * closes the other half — it stops a deactivated user from establishing a new
 * session at all, in exactly the way `BannedUserPlugin` stops a banned one.
 *
 * Zero-dependency, so compose it like any other plugin:
 * `SCIMDeactivatedPlugin.pipe(Layer.provide(Hooks.Default))`, or as one entry
 * in a `composePlugins([...])` stack.
 */
export const SCIMDeactivatedPlugin: Layer.Layer<Hooks, never, Hooks> = makePlugin({
  afterValidateSession: (sessionWithUser: Types.SessionWithUser) =>
    isSCIMDeactivated(sessionWithUser.user)
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
export interface SCIMConnection {
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
export class SCIMConnectionStore extends Context.Service<
  SCIMConnectionStore,
  {
    readonly create: (
      connection: SCIMConnection,
    ) => Effect.Effect<SCIMConnection, Errors.AuthError>;
    readonly getById: (id: string) => Effect.Effect<SCIMConnection | null, Errors.AuthError>;
    /** Resolve a connection by the digest of its provisioning token. */
    readonly getByTokenHash: (
      tokenHash: string,
    ) => Effect.Effect<SCIMConnection | null, Errors.AuthError>;
    readonly listByOrganization: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<SCIMConnection>, Errors.AuthError>;
    readonly update: (
      connection: SCIMConnection,
    ) => Effect.Effect<SCIMConnection, Errors.AuthError>;
    /** Revoke a connection. A no-op for unknown ids. */
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/SCIMConnectionStore") {}

/**
 * In-memory {@link SCIMConnectionStore}, keyed by connection id. Single-process
 * only — good for tests and single-instance deployments.
 *
 * Pass your own `Map` to inspect or pre-seed state in tests.
 */
export const memorySCIMConnectionStore = (
  records: Map<string, SCIMConnection> = new Map(),
): typeof SCIMConnectionStore.Service => ({
  create: (connection) => Effect.sync(() => (records.set(connection.id, connection), connection)),
  getById: (id) => Effect.sync(() => records.get(id) ?? null),
  getByTokenHash: (tokenHash) =>
    Effect.sync(
      () => [...records.values()].find((record) => record.tokenHash === tokenHash) ?? null,
    ),
  listByOrganization: (organizationId) =>
    Effect.sync(() =>
      [...records.values()]
        .filter((record) => record.organizationId === organizationId)
        .sort((a, b) => a.createdAt - b.createdAt),
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
export class SCIMUserStore extends Context.Service<
  SCIMUserStore,
  {
    /** Create a user. The store assigns `id`, `createdAt` and `updatedAt`. */
    readonly create: (input: {
      readonly name?: string;
      readonly image?: string;
      readonly attributes?: Record<string, unknown>;
    }) => Effect.Effect<Types.User, Errors.AuthError>;
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
    readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;
  }
>()("@effect-auth/SCIMUserStore") {}

// ---------------------------------------------------------------------------
// Resource shapes
// ---------------------------------------------------------------------------

/** One entry of a SCIM `User.emails[]` multi-valued attribute. */
export interface SCIMEmail {
  readonly value: string;
  /** `true` for the address that is also the `userName`. */
  readonly primary?: boolean;
  readonly type?: string;
}

/**
 * A SCIM `User` resource, in domain terms — the JSON envelope (`schemas`,
 * `meta`) is added at the HTTP layer.
 */
export interface SCIMUserResource {
  /** The core user id; SCIM's `id` is this library's surrogate key verbatim. */
  readonly id: string;
  readonly userName: string;
  readonly displayName?: string;
  /** The IdP's own identifier, when it sent one. */
  readonly externalId?: string;
  readonly emails: ReadonlyArray<SCIMEmail>;
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
export interface SCIMGroupResource {
  readonly id: string;
  readonly displayName: string;
  readonly members: ReadonlyArray<{ readonly value: string }>;
  /** Epoch milliseconds. */
  readonly createdAt: number;
  /** Epoch milliseconds. */
  readonly updatedAt: number;
}

/** A page of resources, shaped for the SCIM `ListResponse` envelope. */
export interface SCIMListResult<A> {
  /** Matches *before* pagination. */
  readonly totalResults: number;
  /** 1-based index of the first returned resource. */
  readonly startIndex: number;
  readonly itemsPerPage: number;
  readonly resources: ReadonlyArray<A>;
}

/** Query parameters of a SCIM list request. */
export interface SCIMListQuery {
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
export interface SCIMPatchOperation {
  /** `add`, `remove` or `replace` (case-insensitive). */
  readonly op: string;
  readonly path?: string | undefined;
  readonly value?: unknown;
}

/** The writable attributes of a SCIM `User`, as sent on `POST` or `PUT`. */
export interface SCIMUserInput {
  readonly userName: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly emails?: ReadonlyArray<SCIMEmail>;
  readonly active?: boolean;
}

/** The writable attributes of a SCIM `Group`. */
export interface SCIMGroupInput {
  readonly displayName: string;
  readonly members?: ReadonlyArray<{ readonly value: string }>;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface SCIMConfig {
  /**
   * Organization role granted to users provisioned through SCIM.
   * Default `"member"`.
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

export class SCIMService extends Context.Service<
  SCIMService,
  {
    /** Configured {@link SCIMConfig.baseUrl}, for building `meta.location`. */
    readonly baseUrl: string;

    /**
     * Configured {@link SCIMConfig.maxPageSize}. Advertised as `filter.maxResults`
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
      { readonly connection: SCIMConnection; readonly token: string },
      Errors.AuthError
    >;

    /** Revoke a connection, immediately invalidating its token. */
    readonly revokeConnection: (connectionId: string) => Effect.Effect<void, Errors.AuthError>;

    /** The organization's connections (digests only — never the raw tokens). */
    readonly listConnections: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<SCIMConnection>, Errors.AuthError>;

    /**
     * Resolve a raw bearer token to its connection, refreshing `lastUsedAt`.
     *
     * Fails with a `401` {@link SCIMError} for an unknown or malformed token —
     * one uniform answer, so a caller cannot probe which tokens exist.
     */
    readonly authenticate: (
      token: string,
    ) => Effect.Effect<SCIMConnection, SCIMError | Errors.AuthError>;

    /**
     * Provision a user: create the account, claim its email identifiers as
     * IdP-verified, and add it to the connection's organization.
     *
     * A `userName` (or additional email) already claimed by another account
     * fails with `409 uniqueness`, which is what tells the IdP to reconcile
     * against the existing user instead of retrying.
     */
    readonly createUser: (
      connection: SCIMConnection,
      input: SCIMUserInput,
    ) => Effect.Effect<SCIMUserResource, SCIMError | Errors.AuthError>;

    /** Read one user. `404` when the id is unknown *or* outside the connection's org. */
    readonly getUser: (
      connection: SCIMConnection,
      userId: string,
    ) => Effect.Effect<SCIMUserResource, SCIMError | Errors.AuthError>;

    /**
     * List the organization's users, newest last.
     *
     * Supports the one filter shape IdPs actually send —
     * `userName eq "…"` / `externalId eq "…"` — and rejects anything else with
     * `400 invalidFilter` rather than silently returning the whole directory.
     */
    readonly listUsers: (
      connection: SCIMConnection,
      query?: SCIMListQuery,
    ) => Effect.Effect<SCIMListResult<SCIMUserResource>, SCIMError | Errors.AuthError>;

    /**
     * Replace a user (`PUT`). `emails` is authoritative when present: addresses
     * missing from it are unclaimed. When it is absent only `userName` is
     * reconciled, so a partial `PUT` cannot quietly delete addresses.
     */
    readonly replaceUser: (
      connection: SCIMConnection,
      userId: string,
      input: SCIMUserInput,
    ) => Effect.Effect<SCIMUserResource, SCIMError | Errors.AuthError>;

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
      connection: SCIMConnection,
      userId: string,
      operations: ReadonlyArray<SCIMPatchOperation>,
    ) => Effect.Effect<SCIMUserResource, SCIMError | Errors.AuthError>;

    /**
     * `DELETE /Users/:id` — a soft disable, never a hard delete: the user is
     * marked deactivated and every live session is revoked.
     */
    readonly deactivateUser: (
      connection: SCIMConnection,
      userId: string,
    ) => Effect.Effect<void, SCIMError | Errors.AuthError>;

    /** Create a team from a SCIM `Group`. Members must already belong to the org. */
    readonly createGroup: (
      connection: SCIMConnection,
      input: SCIMGroupInput,
    ) => Effect.Effect<SCIMGroupResource, SCIMError | Errors.AuthError>;

    readonly getGroup: (
      connection: SCIMConnection,
      groupId: string,
    ) => Effect.Effect<SCIMGroupResource, SCIMError | Errors.AuthError>;

    /** List the organization's teams; supports `displayName eq "…"`. */
    readonly listGroups: (
      connection: SCIMConnection,
      query?: SCIMListQuery,
    ) => Effect.Effect<SCIMListResult<SCIMGroupResource>, SCIMError | Errors.AuthError>;

    /** Replace a group: rename it and set its membership to exactly `members`. */
    readonly replaceGroup: (
      connection: SCIMConnection,
      groupId: string,
      input: SCIMGroupInput,
    ) => Effect.Effect<SCIMGroupResource, SCIMError | Errors.AuthError>;

    /**
     * Apply a `PATCH` to a group: `replace` on `displayName`, and `add`/`remove`
     * on `members` (including the `members[value eq "…"]` path filter both
     * major IdPs use to remove one member).
     */
    readonly patchGroup: (
      connection: SCIMConnection,
      groupId: string,
      operations: ReadonlyArray<SCIMPatchOperation>,
    ) => Effect.Effect<SCIMGroupResource, SCIMError | Errors.AuthError>;

    /** Delete the team. Its members keep their organization membership. */
    readonly deleteGroup: (
      connection: SCIMConnection,
      groupId: string,
    ) => Effect.Effect<void, SCIMError | Errors.AuthError>;
  }
>()("@effect-auth/SCIMService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: SCIMConfig = {}) =>
    Layer.effect(SCIMService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
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
): Effect.Effect<ParsedFilter, SCIMError> => {
  const match = FILTER_PATTERN.exec(filter);
  if (match === null) {
    return Effect.fail(
      badRequest(
        `Unsupported filter "${filter}": only \`attribute eq "value"\` is supported`,
        "invalidFilter",
      ),
    );
  }
  const [, attribute, operator, doubleQuoted, singleQuoted] = match;
  if (operator!.toLowerCase() !== "eq") {
    return Effect.fail(
      badRequest(
        `Unsupported filter operator "${operator}": only \`eq\` is supported`,
        "invalidFilter",
      ),
    );
  }
  const canonical = supported.find((name) => name.toLowerCase() === attribute!.toLowerCase());
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

/** SCIM sends booleans as JSON booleans; Entra ID sometimes sends strings. */
const asBoolean = (value: unknown): boolean | null => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const lowered = value.trim().toLowerCase();
    if (lowered === "true") return true;
    if (lowered === "false") return false;
  }
  return null;
};

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

/** Read `emails`-shaped patch values: an array, or a bare object/string. */
const emailValues = (value: unknown): ReadonlyArray<string> => {
  const entries = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (const entry of entries) {
    if (typeof entry === "string") {
      out.push(normalizeEmail(entry));
      continue;
    }
    if (typeof entry === "object" && entry !== null) {
      const candidate = (entry as { value?: unknown }).value;
      if (typeof candidate === "string") out.push(normalizeEmail(candidate));
    }
  }
  return out;
};

/** Read `members`-shaped patch values into core user ids. */
const memberValues = (value: unknown): ReadonlyArray<string> => {
  const entries = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (const entry of entries) {
    if (typeof entry === "string") {
      out.push(entry);
      continue;
    }
    if (typeof entry === "object" && entry !== null) {
      const candidate = (entry as { value?: unknown }).value;
      if (typeof candidate === "string") out.push(candidate);
    }
  }
  return out;
};

export const make = (
  config: SCIMConfig = {},
): Effect.Effect<
  typeof SCIMService.Service,
  never,
  | SCIMConnectionStore
  | SCIMUserStore
  | IdentifierStore
  | OrganizationStore
  | SessionService
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const defaultRole = config.defaultRole ?? "member";
    const baseUrl = (config.baseUrl ?? "/scim/v2").replace(/\/+$/, "");
    const maxPageSize = config.maxPageSize ?? 100;

    const connections = yield* SCIMConnectionStore;
    const users = yield* SCIMUserStore;
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

    const randomToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate token", cause }),
        ),
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
    const toUserResource = (user: Types.User, all: ReadonlyArray<Identifier>): SCIMUserResource => {
      const emails = emailIdentifiers(all);
      const pinned = user.attributes[SCIM_USERNAME_ATTRIBUTE];
      const userName =
        typeof pinned === "string" && emails.some((e) => e.value === pinned)
          ? pinned
          : (primaryEmail(all)?.value ?? emails[0]?.value ?? user.id);
      const externalId = user.attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
      return {
        id: user.id,
        userName,
        ...(user.name !== undefined && { displayName: user.name }),
        ...(typeof externalId === "string" && { externalId }),
        emails: emails.map((identifier) => ({
          value: identifier.value,
          ...(identifier.value === userName && { primary: true }),
          type: "work",
        })),
        active: !isSCIMDeactivated(user),
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
    const requireUser = (connection: SCIMConnection, userId: string) =>
      Effect.gen(function* () {
        const member = yield* orgs.getMember(connection.organizationId, userId);
        if (member === null) return yield* notFound(`User "${userId}" not found`);
        const user = yield* users.get(userId);
        if (user === null) return yield* notFound(`User "${userId}" not found`);
        return user;
      });

    const requireTeam = (connection: SCIMConnection, groupId: string) =>
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
    const paginate = <A>(all: ReadonlyArray<A>, query?: SCIMListQuery): SCIMListResult<A> => {
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

    /** Claim an email for a user as IdP-verified, or report a SCIM conflict. */
    const claimEmail = (userId: string, email: string) =>
      claimIdentifier(
        identifiers,
        makeIdentifier({
          userId,
          type: "email",
          value: email,
          // The IdP is the system of record for its users' addresses.
          verified: true,
          verifiedAt: new Date(),
        }),
      ).pipe(
        Effect.catchTag("IdentifierTakenError", () =>
          Effect.fail(conflict(`The email "${email}" is already in use`)),
        ),
      );

    const writeAttributes = (user: Types.User, attributes: Record<string, unknown>) =>
      users.update({ ...user, attributes, updatedAt: new Date() });

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

    const addTeamMemberScoped = (connection: SCIMConnection, teamId: string, userId: string) =>
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

    return {
      baseUrl,
      maxPageSize,

      createConnection: Effect.fn("SCIMService.createConnection")(function* (
        organizationId: string,
      ) {
        const token = yield* randomToken();
        const connection: SCIMConnection = {
          id: yield* randomId(),
          organizationId,
          tokenHash: hashToken(token),
          createdAt: Date.now(),
        };
        return { connection: yield* connections.create(connection), token };
      }),

      revokeConnection: Effect.fn("SCIMService.revokeConnection")((connectionId: string) =>
        connections.delete(connectionId),
      ),

      listConnections: Effect.fn("SCIMService.listConnections")((organizationId: string) =>
        connections.listByOrganization(organizationId),
      ),

      authenticate: Effect.fn("SCIMService.authenticate")(function* (token: string) {
        // One answer for "no token", "malformed token" and "unknown token": a
        // caller must not be able to tell them apart.
        const unauthorized = new SCIMError({
          message: "Invalid SCIM provisioning token",
          status: 401,
        });
        if (token.trim() === "") return yield* unauthorized;
        const connection = yield* connections.getByTokenHash(hashToken(token));
        if (connection === null) return yield* unauthorized;
        // Best-effort activity stamp: a failed touch must not fail the request
        // the IdP actually made.
        yield* connections.update({ ...connection, lastUsedAt: Date.now() }).pipe(Effect.ignore);
        return connection;
      }),

      createUser: Effect.fn("SCIMService.createUser")(function* (
        connection: SCIMConnection,
        input: SCIMUserInput,
      ) {
        const userName = normalizeEmail(input.userName);
        if (userName === "") {
          return yield* badRequest("userName is required", "invalidValue");
        }
        const extras = [
          ...new Set(
            (input.emails ?? [])
              .map((email) => normalizeEmail(email.value))
              .filter((email) => email !== "" && email !== userName),
          ),
        ];

        // Check every address up front: a conflict discovered halfway through
        // would leave a user created with only some of its identifiers.
        for (const email of [userName, ...extras]) {
          const existing = yield* identifiers.getByValue("email", email);
          if (existing !== null) {
            return yield* conflict(`The email "${email}" is already in use`);
          }
        }

        const attributes: Record<string, unknown> = {
          [SCIM_USERNAME_ATTRIBUTE]: userName,
        };
        if (input.externalId !== undefined) {
          attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = input.externalId;
        }
        if (input.active === false) attributes[SCIM_DEACTIVATED_ATTRIBUTE] = true;

        const user = yield* users.create({
          ...(input.displayName !== undefined && { name: input.displayName }),
          attributes,
        });

        for (const email of [userName, ...extras]) {
          yield* claimEmail(user.id, email);
        }

        const existingMember = yield* orgs.getMember(connection.organizationId, user.id);
        if (existingMember === null) {
          const member: Member = {
            id: yield* randomId(),
            organizationId: connection.organizationId,
            userId: user.id,
            role: defaultRole,
            createdAt: Date.now(),
          };
          yield* orgs.createMember(member);
        }

        return yield* readUserResource(user);
      }),

      getUser: Effect.fn("SCIMService.getUser")(function* (
        connection: SCIMConnection,
        userId: string,
      ) {
        return yield* readUserResource(yield* requireUser(connection, userId));
      }),

      listUsers: Effect.fn("SCIMService.listUsers")(function* (
        connection: SCIMConnection,
        query?: SCIMListQuery,
      ) {
        const parsed =
          query?.filter === undefined
            ? null
            : yield* parseFilter(query.filter, ["userName", "externalId"]);

        const members = yield* orgs.listMembersByOrganization(connection.organizationId);
        const ordered = [...members].sort((a, b) => a.createdAt - b.createdAt);

        const resources: SCIMUserResource[] = [];
        for (const member of ordered) {
          const user = yield* users.get(member.userId);
          // A membership row whose user is gone is stale, not an error.
          if (user === null) continue;
          const resource = yield* readUserResource(user);
          if (parsed !== null) {
            const actual =
              parsed.attribute === "userName" ? resource.userName : resource.externalId;
            if (parsed.attribute === "userName") {
              if (actual?.toLowerCase() !== parsed.value.trim().toLowerCase()) continue;
            } else if (actual !== parsed.value) {
              continue;
            }
          }
          resources.push(resource);
        }

        return paginate(resources, query);
      }),

      replaceUser: Effect.fn("SCIMService.replaceUser")(function* (
        connection: SCIMConnection,
        userId: string,
        input: SCIMUserInput,
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
          const desired = new Set([
            userName,
            ...input.emails.map((email) => normalizeEmail(email.value)).filter((e) => e !== ""),
          ]);
          const all = yield* identifiers.listByUser(current.id);
          for (const identifier of emailIdentifiers(all)) {
            if (!desired.has(identifier.value)) yield* identifiers.delete(identifier.id);
            desired.delete(identifier.value);
          }
          for (const email of desired) {
            yield* claimEmail(current.id, email);
          }
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
          updatedAt: new Date(),
        });

        if (input.active !== undefined && input.active === isSCIMDeactivated(current)) {
          current = yield* setActive(current, input.active);
        }

        return yield* readUserResource(current);
      }),

      patchUser: Effect.fn("SCIMService.patchUser")(function* (
        connection: SCIMConnection,
        userId: string,
        operations: ReadonlyArray<SCIMPatchOperation>,
      ) {
        let user = yield* requireUser(connection, userId);

        for (const operation of operations) {
          const op = operation.op.trim().toLowerCase();
          if (op !== "add" && op !== "remove" && op !== "replace") {
            return yield* badRequest(`Unsupported PATCH op "${operation.op}"`, "invalidSyntax");
          }

          // Entra ID omits `path` and sends an attribute map as the value.
          // Expand it so both dialects go through one code path.
          const expanded: ReadonlyArray<{ path: string; value: unknown }> =
            operation.path === undefined || operation.path.trim() === ""
              ? typeof operation.value === "object" &&
                operation.value !== null &&
                !Array.isArray(operation.value)
                ? Object.entries(operation.value as Record<string, unknown>).map(
                    ([path, value]) => ({ path, value }),
                  )
                : []
              : [{ path: operation.path.trim(), value: operation.value }];

          if (expanded.length === 0) {
            return yield* badRequest("PATCH operation has no usable path", "invalidPath");
          }

          for (const { path, value } of expanded) {
            const attribute = path.toLowerCase();

            if (attribute === "active") {
              const active = asBoolean(value);
              if (active === null) {
                return yield* badRequest("active must be a boolean", "invalidValue");
              }
              if (active === isSCIMDeactivated(user)) user = yield* setActive(user, active);
              continue;
            }

            if (attribute === "displayname") {
              const name = asString(value);
              user = yield* users.update({
                ...user,
                ...(name === null ? {} : { name }),
                updatedAt: new Date(),
              });
              continue;
            }

            if (attribute === "username") {
              const email = asString(value);
              if (email === null) {
                return yield* badRequest("userName must be a non-empty string", "invalidValue");
              }
              user = yield* renameUserName(user, normalizeEmail(email));
              continue;
            }

            if (attribute === "externalid") {
              const externalId = asString(value);
              const attributes = { ...user.attributes };
              if (op === "remove" || externalId === null) {
                delete attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
              } else {
                attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = externalId;
              }
              user = yield* writeAttributes(user, attributes);
              continue;
            }

            if (attribute === "emails" || attribute.startsWith("emails[")) {
              const values = emailValues(value);
              if (op === "remove") {
                const all = yield* identifiers.listByUser(user.id);
                const userName = toUserResource(user, all).userName;
                for (const identifier of emailIdentifiers(all)) {
                  // Never unclaim the address `userName` resolves to — that
                  // would leave the resource without the handle it is keyed by.
                  if (identifier.value === userName) continue;
                  if (values.length === 0 || values.includes(identifier.value)) {
                    yield* identifiers.delete(identifier.id);
                  }
                }
                continue;
              }
              for (const email of values) {
                if (email === "") continue;
                const existing = yield* identifiers.getByValue("email", email);
                if (existing !== null) {
                  if (existing.userId === user.id) continue;
                  return yield* conflict(`The email "${email}" is already in use`);
                }
                yield* claimEmail(user.id, email);
              }
              continue;
            }

            return yield* badRequest(`Unsupported PATCH path "${path}"`, "invalidPath");
          }
        }

        return yield* readUserResource(user);
      }),

      deactivateUser: Effect.fn("SCIMService.deactivateUser")(function* (
        connection: SCIMConnection,
        userId: string,
      ) {
        const user = yield* requireUser(connection, userId);
        yield* setActive(user, false);
      }),

      createGroup: Effect.fn("SCIMService.createGroup")(function* (
        connection: SCIMConnection,
        input: SCIMGroupInput,
      ) {
        const displayName = input.displayName.trim();
        if (displayName === "") {
          return yield* badRequest("displayName is required", "invalidValue");
        }
        const now = Date.now();
        const team = yield* orgs.createTeam({
          id: yield* randomId(),
          organizationId: connection.organizationId,
          name: displayName,
          createdAt: now,
          updatedAt: now,
        });
        for (const member of input.members ?? []) {
          yield* addTeamMemberScoped(connection, team.id, member.value);
        }
        return yield* toGroupResource(team);
      }),

      getGroup: Effect.fn("SCIMService.getGroup")(function* (
        connection: SCIMConnection,
        groupId: string,
      ) {
        return yield* toGroupResource(yield* requireTeam(connection, groupId));
      }),

      listGroups: Effect.fn("SCIMService.listGroups")(function* (
        connection: SCIMConnection,
        query?: SCIMListQuery,
      ) {
        const parsed =
          query?.filter === undefined ? null : yield* parseFilter(query.filter, ["displayName"]);

        const teams = yield* orgs.listTeams(connection.organizationId);
        const ordered = [...teams].sort((a, b) => a.createdAt - b.createdAt);

        const resources: SCIMGroupResource[] = [];
        for (const team of ordered) {
          if (parsed !== null && team.name !== parsed.value) continue;
          resources.push(yield* toGroupResource(team));
        }
        return paginate(resources, query);
      }),

      replaceGroup: Effect.fn("SCIMService.replaceGroup")(function* (
        connection: SCIMConnection,
        groupId: string,
        input: SCIMGroupInput,
      ) {
        const team = yield* requireTeam(connection, groupId);
        const displayName = input.displayName.trim();
        if (displayName === "") {
          return yield* badRequest("displayName is required", "invalidValue");
        }
        const renamed = yield* orgs.updateTeam({
          ...team,
          name: displayName,
          updatedAt: Date.now(),
        });
        if (renamed === null) return yield* notFound(`Group "${groupId}" not found`);

        if (input.members !== undefined) {
          const desired = new Set(input.members.map((member) => member.value));
          const existing = yield* orgs.listTeamMembers(team.id);
          for (const member of existing) {
            if (!desired.has(member.userId)) yield* orgs.removeTeamMember(team.id, member.userId);
            desired.delete(member.userId);
          }
          for (const userId of desired) {
            yield* addTeamMemberScoped(connection, team.id, userId);
          }
        }

        return yield* toGroupResource(renamed);
      }),

      patchGroup: Effect.fn("SCIMService.patchGroup")(function* (
        connection: SCIMConnection,
        groupId: string,
        operations: ReadonlyArray<SCIMPatchOperation>,
      ) {
        let team = yield* requireTeam(connection, groupId);

        for (const operation of operations) {
          const op = operation.op.trim().toLowerCase();
          if (op !== "add" && op !== "remove" && op !== "replace") {
            return yield* badRequest(`Unsupported PATCH op "${operation.op}"`, "invalidSyntax");
          }
          const path = (operation.path ?? "").trim();

          // Path-less form: an attribute map, exactly as for users.
          if (path === "") {
            if (
              typeof operation.value !== "object" ||
              operation.value === null ||
              Array.isArray(operation.value)
            ) {
              return yield* badRequest("PATCH operation has no usable path", "invalidPath");
            }
            const entries = operation.value as Record<string, unknown>;
            const displayName = asString(entries["displayName"]);
            if (displayName === null) {
              return yield* badRequest("Unsupported path-less PATCH value", "invalidPath");
            }
            const renamed = yield* orgs.updateTeam({
              ...team,
              name: displayName,
              updatedAt: Date.now(),
            });
            if (renamed === null) return yield* notFound(`Group "${groupId}" not found`);
            team = renamed;
            continue;
          }

          if (path.toLowerCase() === "displayname") {
            const displayName = asString(operation.value);
            if (displayName === null) {
              return yield* badRequest("displayName must be a non-empty string", "invalidValue");
            }
            const renamed = yield* orgs.updateTeam({
              ...team,
              name: displayName,
              updatedAt: Date.now(),
            });
            if (renamed === null) return yield* notFound(`Group "${groupId}" not found`);
            team = renamed;
            continue;
          }

          const pathFilter = MEMBER_PATH_PATTERN.exec(path);
          if (pathFilter !== null) {
            if (op !== "remove") {
              return yield* badRequest(`Only \`remove\` is supported on "${path}"`, "invalidPath");
            }
            yield* orgs.removeTeamMember(team.id, pathFilter[1] ?? pathFilter[2] ?? "");
            continue;
          }

          if (path.toLowerCase() === "members") {
            const ids = memberValues(operation.value);
            if (op === "remove") {
              if (ids.length === 0) {
                // `remove` with no value clears the membership entirely.
                const existing = yield* orgs.listTeamMembers(team.id);
                for (const member of existing) {
                  yield* orgs.removeTeamMember(team.id, member.userId);
                }
                continue;
              }
              for (const userId of ids) {
                yield* orgs.removeTeamMember(team.id, userId);
              }
              continue;
            }
            if (op === "replace") {
              const existing = yield* orgs.listTeamMembers(team.id);
              const desired = new Set(ids);
              for (const member of existing) {
                if (!desired.has(member.userId)) {
                  yield* orgs.removeTeamMember(team.id, member.userId);
                }
                desired.delete(member.userId);
              }
              for (const userId of desired) {
                yield* addTeamMemberScoped(connection, team.id, userId);
              }
              continue;
            }
            for (const userId of ids) {
              yield* addTeamMemberScoped(connection, team.id, userId);
            }
            continue;
          }

          return yield* badRequest(`Unsupported PATCH path "${path}"`, "invalidPath");
        }

        return yield* toGroupResource(team);
      }),

      deleteGroup: Effect.fn("SCIMService.deleteGroup")(function* (
        connection: SCIMConnection,
        groupId: string,
      ) {
        const team = yield* requireTeam(connection, groupId);
        yield* orgs.deleteTeam(team.id);
      }),
    } satisfies typeof SCIMService.Service;
  });
