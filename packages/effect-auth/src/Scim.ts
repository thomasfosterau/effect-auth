/**
 * SCIM 2.0 provisioning (RFC 7643 / RFC 7644): an organization's identity
 * provider creates, updates and deactivates users, and manages groups as teams.
 * Each {@link ScimConnection} is scoped to one organization, and deactivation
 * is a soft disable. See `docs/guides/scim.md`.
 *
 * @module scim
 */
import { Clock, Context, Data, DateTime, Effect, Layer, MutableHashMap, Order } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import * as Str from "effect/String";
import { Digest, SecureRandom } from "effect/crypto";
import { flow } from "effect/Function";
import * as Errors from "./Errors.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";
import { Hooks, makePlugin } from "./Hooks.ts";
import {
  claimIdentifier,
  IdentifierStore,
  lookupIdentifier,
  makeIdentifier,
  primaryEmail,
  type Identifier,
} from "./Identifier.ts";
import {
  isManagedBy,
  isOnDomains,
  provisionedByAttributes,
  verifiedDomains,
} from "./ManagedUser.ts";
import {
  isActiveMember,
  OrganizationDomainStore,
  OrganizationStore,
  type Member,
  type Team,
} from "./Organization.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
} from "./UserStore.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { tokenHasher } from "./TokenHash.ts";
import { revokeStandingAccess, userCredentialStores } from "./UserCredentials.ts";
import { isScimDeactivated, SCIM_DEACTIVATED_ATTRIBUTE } from "./UserStanding.ts";
import type * as Types from "./Types.ts";
import { normalizeEmail } from "./utils.ts";

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

// The deactivation flag and its read live in `UserStanding.ts`, which
// `ApiKey.ts` reads without a cycle.
export { SCIM_DEACTIVATED_ATTRIBUTE, isScimDeactivated };

/** `User.attributes` key holding the IdP's own identifier for the user. */
export const SCIM_EXTERNAL_ID_ATTRIBUTE = "scimExternalId";

/**
 * A no-op, kept so existing hook stacks still compose: `SessionService`
 * refuses a SCIM-deactivated user's sessions itself.
 *
 * @deprecated Drop it from your hook stack; deactivation is enforced without it.
 */
export const ScimDeactivatedPlugin: Layer.Layer<Hooks, never, Hooks> = makePlugin({});

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
 * Pass your own `MutableHashMap` to inspect or pre-seed state in tests.
 */
export const memoryScimConnectionStore = (
  records: MutableHashMap.MutableHashMap<string, ScimConnection> = MutableHashMap.empty(),
): typeof ScimConnectionStore.Service => ({
  create: (connection) =>
    Effect.sync(() => (MutableHashMap.set(records, connection.id, connection), connection)),
  getById: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, id))),
  getByTokenHash: (tokenHash) =>
    Effect.sync(
      () =>
        Arr.fromIterable(MutableHashMap.values(records)).find(
          (record) => record.tokenHash === tokenHash,
        ) ?? null,
    ),
  listByOrganization: (organizationId) =>
    Effect.sync(() =>
      Arr.sort(
        Arr.filter(
          Arr.fromIterable(MutableHashMap.values(records)),
          (record) => record.organizationId === organizationId,
        ),
        byCreatedAt,
      ),
    ),
  update: (connection) =>
    Effect.sync(() => (MutableHashMap.set(records, connection.id, connection), connection)),
  delete: (id) => Effect.sync(() => void MutableHashMap.remove(records, id)),
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
  Option.flatMap((value) => (P.isBoolean(value) ? Option.some(value) : parseBooleanString(value))),
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
    P.isString(entry)
      ? [entry]
      : P.isObjectOrArray(entry) && P.hasProperty(entry, "value") && P.isString(entry.value)
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

/**
 * A user as one connection sees them: their membership in its organization,
 * the organization's verified domains, and whether it manages them
 * ({@link module:managed-user}).
 */
interface ScimTarget {
  readonly user: Types.User;
  readonly member: Member;
  readonly domains: ReadonlyArray<string>;
  readonly managed: boolean;
}

/**
 * Whether the user is active as this connection sees them: a managed
 * user's account, else their membership in the connection's organization.
 */
const isActive = (target: ScimTarget): boolean =>
  target.managed ? !isScimDeactivated(target.user) : isActiveMember(target.member);

/** Refuse to change anything but `active` on a user the organization does not manage. */
const requireManaged = (target: ScimTarget): Effect.Effect<void, ScimError> =>
  target.managed
    ? Effect.void
    : Effect.fail(
        badRequest(
          "This organization does not manage this user: only `active` may change",
          "mutability",
        ),
      );

/** Refuse an address outside the organization's verified domains. */
const requireOnDomains = (
  email: string,
  domains: ReadonlyArray<string>,
): Effect.Effect<void, ScimError> =>
  isOnDomains(email, domains)
    ? Effect.void
    : Effect.fail(
        badRequest(
          `The email "${email}" is not on a verified domain of this organization`,
          "invalidValue",
        ),
      );

/** Replace the target's user, keeping the rest. */
const withUser = (target: ScimTarget, user: Types.User): ScimTarget => ({ ...target, user });

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
  | SecureRandom.SecureRandom
  | Digest.Digest
> =>
  Effect.gen(function* () {
    const baseUrl = (config.baseUrl ?? "/scim/v2").replace(/\/+$/, "");
    const maxPageSize = config.maxPageSize ?? 100;

    const connections = yield* ScimConnectionStore;
    const hashToken = yield* tokenHasher;
    const users = yield* ScimUserStore;
    const identifiers = yield* IdentifierStore;
    const orgs = yield* OrganizationStore;
    const sessions = yield* SessionService;
    const credentials = yield* userCredentialStores;
    const crypto = yield* SecureRandom.SecureRandom;
    // Without domain claims an organization manages only the users it created.
    const domainStore = Option.getOrUndefined(yield* Effect.serviceOption(OrganizationDomainStore));

    const randomId = (): Effect.Effect<string> => crypto.uuidV4();

    const randomToken = (): Effect.Effect<string> => randomBase64UrlToken(crypto);

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
    const toUserResource = (
      user: Types.User,
      all: ReadonlyArray<Identifier>,
      active: boolean = !isScimDeactivated(user),
    ): ScimUserResource => {
      const emails = emailIdentifiers(all);
      const pinned = user.attributes[SCIM_USERNAME_ATTRIBUTE];
      const userName =
        P.isString(pinned) && emails.some((e) => e.value === pinned)
          ? pinned
          : (primaryEmail(all)?.value ?? emails[0]?.value ?? user.id);
      const externalId = user.attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
      return {
        id: user.id,
        userName,
        ...(user.name !== undefined && { displayName: user.name }),
        ...(P.isString(externalId) && { externalId }),
        emails: emails.map((identifier) =>
          identifier.value === userName
            ? { value: identifier.value, primary: true, type: "work" }
            : { value: identifier.value, type: "work" },
        ),
        active,
        createdAt: user.createdAt.getTime(),
        updatedAt: user.updatedAt.getTime(),
      };
    };

    const readUserResource = (target: ScimTarget) =>
      Effect.map(identifiers.listByUser(target.user.id), (all) =>
        toUserResource(target.user, all, isActive(target)),
      );

    /** A member and their user, with whether the connection's organization manages them. */
    const targetOf = (
      connection: ScimConnection,
      member: Member,
      user: Types.User,
      domains: ReadonlyArray<string>,
    ) =>
      Effect.map(identifiers.listByUser(user.id), (all): ScimTarget => ({
        user,
        member,
        domains,
        managed: isManagedBy({
          user,
          identifiers: all,
          organizationId: connection.organizationId,
          verifiedDomains: domains,
        }),
      }));

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
        const domains = yield* verifiedDomains(domainStore, connection.organizationId);
        return yield* targetOf(connection, member, user, domains);
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

    /** A membership's user as a SCIM `User`; none for a stale row whose user is gone. */
    const memberResource = (
      connection: ScimConnection,
      member: Member,
      domains: ReadonlyArray<string>,
    ) =>
      Effect.flatMap(users.get(member.userId), (user) =>
        user === null
          ? Effect.succeed(Option.none<ScimUserResource>())
          : Effect.map(
              Effect.flatMap(targetOf(connection, member, user, domains), readUserResource),
              Option.some,
            ),
      );

    /**
     * The organization's user whose `userName` is `userName` (normalized):
     * the email identifier holding it, then a membership check, so a user of
     * another organization is not found.
     */
    const findByUserName = (
      connection: ScimConnection,
      userName: string,
      domains: ReadonlyArray<string>,
    ) =>
      Effect.gen(function* () {
        const identifier = yield* lookupIdentifier(identifiers, "email", userName);
        if (identifier === null) return Option.none<ScimUserResource>();
        const member = yield* orgs.getMember(connection.organizationId, identifier.userId);
        if (member === null) return Option.none<ScimUserResource>();
        const resource = yield* memberResource(connection, member, domains);
        // The address may be one of the user's other emails, not its userName.
        return Option.filter(resource, (found) => found.userName.toLowerCase() === userName);
      });

    /** A list request's 1-based `startIndex` and its `count`, capped at `maxPageSize`. */
    const pageWindow = (query?: ScimListQuery) => ({
      startIndex: Math.max(1, Math.trunc(query?.startIndex ?? 1)),
      count: Math.max(0, Math.min(Math.trunc(query?.count ?? maxPageSize), maxPageSize)),
    });

    /** Slice a filtered, ordered array into a SCIM `ListResponse` page. */
    const paginate = <A>(all: ReadonlyArray<A>, query?: ScimListQuery): ScimListResult<A> => {
      const { startIndex, count } = pageWindow(query);
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
              now: verifiedAt,
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
     * Flip a managed user's `active` state. Deactivation revokes every live
     * session, API key and OIDC grant, so the door closes now rather than
     * whenever they would have expired; `SessionService` refuses the user a new
     * session.
     */
    const setAccountActive = (user: Types.User, active: boolean) =>
      Effect.gen(function* () {
        const attributes = { ...user.attributes };
        if (active) {
          delete attributes[SCIM_DEACTIVATED_ATTRIBUTE];
        } else {
          attributes[SCIM_DEACTIVATED_ATTRIBUTE] = true;
        }
        const updated = yield* writeAttributes(user, attributes);
        if (!active) {
          yield* sessions.invalidateUserSessions(user.id);
          yield* revokeStandingAccess(credentials, user.id);
        }
        return updated;
      });

    /**
     * Flip a membership's status, as `OrganizationService.deactivateMember`
     * and `reactivateMember` do: the role is parked in `previousRole` and
     * restored on reactivation.
     */
    const setMembershipActive = (member: Member, active: boolean) =>
      Effect.gen(function* () {
        if (active) {
          const { previousRole, ...rest } = member;
          return yield* orgs.updateMember({
            ...rest,
            status: "active",
            role: previousRole ?? member.role,
          });
        }
        const organization = yield* orgs.getOrganizationById(member.organizationId);
        return yield* orgs.updateMember({
          ...member,
          status: "inactive",
          previousRole: member.role,
          role: organization?.defaultRole ?? "member",
        });
      });

    /**
     * Set whether the user is active: a managed user's account, or only the
     * membership of a user the organization does not manage.
     */
    const setActive = (target: ScimTarget, active: boolean) =>
      Effect.gen(function* () {
        if (isActive(target) === active) return target;
        if (target.managed) return withUser(target, yield* setAccountActive(target.user, active));
        const member = yield* setMembershipActive(target.member, active);
        return { ...target, member };
      });

    /**
     * Repoint `userName` at `email`, claiming it and unclaiming the old one
     * (kept when it is off the verified domains, which SCIM never unclaims).
     */
    const renameUserName = (target: ScimTarget, email: string) =>
      Effect.gen(function* () {
        const { user } = target;
        const all = yield* identifiers.listByUser(user.id);
        const current = toUserResource(user, all).userName;
        if (current === email) return target;
        yield* requireManaged(target);
        const existing = emailIdentifiers(all).find((identifier) => identifier.value === email);
        if (existing === undefined) {
          yield* requireOnDomains(email, target.domains);
          yield* claimEmail(user.id, email);
        }
        const previous = emailIdentifiers(all).find((identifier) => identifier.value === current);
        if (previous !== undefined && isOnDomains(previous.value, target.domains)) {
          yield* identifiers.delete(previous.id);
        }
        return withUser(
          target,
          yield* writeAttributes(user, {
            ...user.attributes,
            [SCIM_USERNAME_ATTRIBUTE]: email,
          }),
        );
      });

    /**
     * Whether a `PUT` body only restates the user's current profile: the same
     * `userName`, `displayName`, `externalId` and (when sent) email set.
     */
    const restatesProfile = (user: Types.User, userName: string, input: ScimUserInput) =>
      Effect.map(identifiers.listByUser(user.id), (all) => {
        const current = toUserResource(user, all);
        const sent = Arr.dedupe([
          userName,
          ...(input.emails ?? [])
            .map((email) => normalizeEmail(email.value))
            .filter((e) => e !== ""),
        ]);
        const held = current.emails.map((email) => email.value);
        const sameEmails =
          input.emails === undefined ||
          (Arr.isReadonlyArrayEmpty(Arr.difference(sent, held)) &&
            Arr.isReadonlyArrayEmpty(Arr.difference(held, sent)));
        return (
          current.userName === userName &&
          (input.displayName === undefined || input.displayName === current.displayName) &&
          input.externalId === current.externalId &&
          sameEmails
        );
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
        if (!existing.some((entry) => entry.userId === userId)) {
          yield* orgs.addTeamMember({
            id: yield* randomId(),
            teamId,
            userId,
            createdAt: yield* Clock.currentTimeMillis,
          });
        }
        return yield* Effect.void;
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
    const patchExternalId = (target: ScimTarget, op: PatchOp, { value }: PatchEntry) =>
      Effect.gen(function* () {
        yield* requireManaged(target);
        const externalId = asString(value);
        const attributes = { ...target.user.attributes };
        if (op === "remove" || externalId === null) {
          delete attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
        } else {
          attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = externalId;
        }
        return withUser(target, yield* writeAttributes(target.user, attributes));
      });

    /**
     * Unclaim the listed email addresses (every address on the verified
     * domains when `values` is empty), keeping the one `userName` resolves to.
     * An address off the verified domains is never SCIM's to unclaim.
     */
    const removeUserEmails = (target: ScimTarget, values: ReadonlyArray<string>) =>
      Effect.gen(function* () {
        yield* Effect.forEach(values, (email) => requireOnDomains(email, target.domains), {
          concurrency: 1,
          discard: true,
        });
        const all = yield* identifiers.listByUser(target.user.id);
        const userName = toUserResource(target.user, all).userName;
        yield* Effect.forEach(
          Arr.filter(
            emailIdentifiers(all),
            (identifier) =>
              // Never unclaim the address `userName` resolves to — that
              // would leave the resource without the handle it is keyed by.
              identifier.value !== userName &&
              isOnDomains(identifier.value, target.domains) &&
              (Arr.isReadonlyArrayEmpty(values) || values.includes(identifier.value)),
          ),
          (identifier) => identifiers.delete(identifier.id),
          { concurrency: 1, discard: true },
        );
      });

    /** Claim one email address for the user; another user's address is a `409`. */
    const addUserEmail = (target: ScimTarget, email: string) =>
      Effect.gen(function* () {
        const existing = yield* lookupIdentifier(identifiers, "email", email);
        if (existing !== null) {
          if (existing.userId === target.user.id) return yield* Effect.void;
          return yield* conflict(`The email "${email}" is already in use`);
        }
        yield* requireOnDomains(email, target.domains);
        return yield* Effect.asVoid(claimEmail(target.user.id, email));
      });

    /** Apply an `emails` PATCH entry: unclaim on `remove`, else claim each address. */
    const patchUserEmails = (target: ScimTarget, op: PatchOp, { value }: PatchEntry) => {
      const values = emailValues(value);
      const applied =
        op === "remove"
          ? removeUserEmails(target, values)
          : Effect.forEach(
              Arr.filter(values, (email) => email !== ""),
              (email) => addUserEmail(target, email),
              { concurrency: 1, discard: true },
            );
      return Effect.as(Effect.andThen(requireManaged(target), applied), target);
    };

    /** Apply an `active` PATCH entry. */
    const patchActive = (target: ScimTarget, { value }: PatchEntry) => {
      const active = asBoolean(value);
      if (active === null) {
        return Effect.fail(badRequest("active must be a boolean", "invalidValue"));
      }
      return setActive(target, active);
    };

    /** Apply a `userName` PATCH entry. */
    const patchUserName = (target: ScimTarget, { value }: PatchEntry) => {
      const email = asString(value);
      if (email === null) {
        return Effect.fail(badRequest("userName must be a non-empty string", "invalidValue"));
      }
      return renameUserName(target, normalizeEmail(email));
    };

    /** Apply a `displayName` PATCH entry; a non-string value leaves the name as is. */
    const patchDisplayName = (target: ScimTarget, { value }: PatchEntry) =>
      Effect.gen(function* () {
        yield* requireManaged(target);
        const name = asString(value);
        const updated = yield* users.update({
          ...target.user,
          ...(name === null ? {} : { name }),
          updatedAt: yield* DateTime.nowAsDate,
        });
        return withUser(target, updated);
      });

    /** Apply one expanded PATCH entry to a user, returning the updated target. */
    const patchUserEntry = (
      target: ScimTarget,
      op: PatchOp,
      entry: PatchEntry,
    ): Effect.Effect<ScimTarget, ScimError | Errors.AuthError> => {
      const attribute = entry.path.toLowerCase();
      if (attribute === "active") return patchActive(target, entry);
      if (attribute === "displayname") return patchDisplayName(target, entry);
      if (attribute === "username") return patchUserName(target, entry);
      if (attribute === "externalid") return patchExternalId(target, op, entry);
      if (attribute === "emails" || attribute.startsWith("emails[")) {
        return patchUserEmails(target, op, entry);
      }
      return Effect.fail(badRequest(`Unsupported PATCH path "${entry.path}"`, "invalidPath"));
    };

    /** Apply one PATCH operation to a user, returning the updated target. */
    const patchUserOperation = (target: ScimTarget, operation: ScimPatchOperation) =>
      Effect.gen(function* () {
        const op = yield* parsePatchOp(operation);

        // Entra ID omits `path` and sends an attribute map as the value.
        // Expand it so both dialects go through one code path.
        const expanded: ReadonlyArray<PatchEntry> =
          operation.path === undefined || operation.path.trim() === ""
            ? P.isObject(operation.value)
              ? R.collect(operation.value, (path, value) => ({ path, value }))
              : []
            : [{ path: operation.path.trim(), value: operation.value }];

        if (Arr.isReadonlyArrayEmpty(expanded)) {
          return yield* badRequest("PATCH operation has no usable path", "invalidPath");
        }

        return yield* Effect.reduce(
          expanded,
          () => target,
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
      if (!P.isObject(value)) {
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
          tokenHash: yield* hashToken(token),
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
        const connection = yield* connections.getByTokenHash(yield* hashToken(token));
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
        const domains = yield* verifiedDomains(domainStore, connection.organizationId);
        yield* Effect.forEach([userName, ...extras], (email) => requireOnDomains(email, domains), {
          concurrency: 1,
          discard: true,
        });
        const taken = yield* Effect.findFirst([userName, ...extras], (email) =>
          Effect.map(
            lookupIdentifier(identifiers, "email", email),
            (existing) => existing !== null,
          ),
        );
        if (Option.isSome(taken)) {
          return yield* conflict(`The email "${taken.value}" is already in use`);
        }

        const attributes: Types.Attributes = {
          ...provisionedByAttributes({
            kind: "scim",
            connectionId: connection.id,
            organizationId: connection.organizationId,
          }),
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
        const member: Member =
          existingMember ??
          (yield* orgs.createMember({
            id: yield* randomId(),
            organizationId: connection.organizationId,
            userId: user.id,
            role: yield* provisioningRole(connection.organizationId),
            status: "active",
            createdAt: yield* Clock.currentTimeMillis,
          }));

        return yield* readUserResource({ user, member, domains, managed: true });
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

        const organizationId = connection.organizationId;
        const domains = yield* verifiedDomains(domainStore, organizationId);

        // IdPs send `userName eq` on every sync: one identifier lookup and one
        // membership check, never a scan of the directory.
        if (parsed?.attribute === "userName") {
          const found = yield* findByUserName(connection, normalizeEmail(parsed.value), domains);
          return paginate(Option.toArray(found), query);
        }

        if (parsed !== null) {
          const members = Arr.sort(
            yield* orgs.listMembersByOrganization(organizationId),
            byCreatedAt,
          );
          const matched = yield* Effect.forEach(
            members,
            (member) =>
              Effect.map(memberResource(connection, member, domains), (resource) =>
                Option.filter(resource, ({ externalId }) => externalId === parsed.value),
              ),
            { concurrency: 1 },
          );
          return paginate(Arr.getSomes(matched), query);
        }

        // Unfiltered: read one page of memberships, and only that page's users.
        const { startIndex, count } = pageWindow(query);
        const page = { offset: startIndex - 1, limit: count };
        const totalResults = yield* orgs.countMembersByOrganization(organizationId);
        const members =
          count === 0
            ? []
            : orgs.listMembersByOrganizationPage !== undefined
              ? yield* orgs.listMembersByOrganizationPage(organizationId, page)
              : Arr.take(
                  Arr.drop(
                    Arr.sort(yield* orgs.listMembersByOrganization(organizationId), byCreatedAt),
                    page.offset,
                  ),
                  page.limit,
                );
        const resources = Arr.getSomes(
          yield* Effect.forEach(
            Arr.take(members, count),
            (member) => memberResource(connection, member, domains),
            { concurrency: 1 },
          ),
        );
        return { totalResults, startIndex, itemsPerPage: resources.length, resources };
      }),

      replaceUser: Effect.fn("ScimService.replaceUser")(function* (
        connection: ScimConnection,
        userId: string,
        input: ScimUserInput,
      ) {
        const target = yield* requireUser(connection, userId);
        const userName = normalizeEmail(input.userName);
        if (userName === "") {
          return yield* badRequest("userName is required", "invalidValue");
        }
        // A user the organization does not manage keeps their profile: a PUT
        // that only restates it may still flip `active`.
        if (!target.managed && !(yield* restatesProfile(target.user, userName, input))) {
          yield* requireManaged(target);
        }

        // `emails` is authoritative only when the IdP sent it; a PUT that omits
        // it is reconciling the profile, not clearing the address book.
        const desired =
          input.emails === undefined
            ? undefined
            : Arr.dedupe([
                userName,
                ...input.emails.map((email) => normalizeEmail(email.value)).filter((e) => e !== ""),
              ]);
        if (desired !== undefined) {
          // Check every address it would claim before writing anything.
          const held = Arr.map(
            emailIdentifiers(yield* identifiers.listByUser(target.user.id)),
            (identifier) => identifier.value,
          );
          yield* Effect.forEach(
            Arr.filter(desired, (email) => !Arr.contains(held, email)),
            (email) => requireOnDomains(email, target.domains),
            { concurrency: 1, discard: true },
          );
        }

        let current = yield* renameUserName(target, userName);

        if (desired !== undefined && current.managed) {
          const all = yield* identifiers.listByUser(current.user.id);
          const owner = current.user.id;
          const missing = yield* Effect.reduce(
            emailIdentifiers(all),
            () => desired,
            (remaining, identifier) =>
              Effect.as(
                Arr.contains(remaining, identifier.value) ||
                  !isOnDomains(identifier.value, current.domains)
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

        if (current.managed) {
          const attributes = { ...current.user.attributes };
          if (input.externalId === undefined) {
            delete attributes[SCIM_EXTERNAL_ID_ATTRIBUTE];
          } else {
            attributes[SCIM_EXTERNAL_ID_ATTRIBUTE] = input.externalId;
          }
          current = withUser(
            current,
            yield* users.update({
              ...current.user,
              ...(input.displayName !== undefined && { name: input.displayName }),
              attributes,
              updatedAt: yield* DateTime.nowAsDate,
            }),
          );
        }

        if (input.active !== undefined) {
          current = yield* setActive(current, input.active);
        }

        return yield* readUserResource(current);
      }),

      patchUser: Effect.fn("ScimService.patchUser")(function* (
        connection: ScimConnection,
        userId: string,
        operations: ReadonlyArray<ScimPatchOperation>,
      ) {
        const target = yield* requireUser(connection, userId);
        const patched = yield* Effect.reduce(operations, () => target, patchUserOperation);
        return yield* readUserResource(patched);
      }),

      deactivateUser: Effect.fn("ScimService.deactivateUser")(function* (
        connection: ScimConnection,
        userId: string,
      ) {
        yield* setActive(yield* requireUser(connection, userId), false);
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
