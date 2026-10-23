/**
 * Driver-agnostic SQL implementations of effect-auth's storage interfaces.
 *
 * Each `make*Store` is an Effect that reads the `SqlClient` service from
 * `effect/sql` out of the context and builds a plain store object,
 * and each `*StoreLayer` lifts it into an Effect `Layer` keyed by the
 * matching effect-auth `Context.Service` tag. {@link layer} bundles all of
 * them so a single `Layer.provide` wires up the entire auth stack on top of
 * a `SqlClient` layer for a supported dialect (SQLite, Cloudflare D1 and
 * PostgreSQL; see the package README). MySQL is not supported (#260).
 *
 * Data codecs: dates as epoch milliseconds, booleans as `0`/`1`, attribute
 * bags and other structured values as JSON `TEXT`, binary values (WebAuthn
 * keys/challenges) as base64 `TEXT`.
 *
 * Concurrency: single-row upserts (`rateLimit.set`, `oauthAccount`,
 * `multiFactor`) and counters (`rateLimit.increment`,
 * `emailOtp.incrementAttempts`) use a single `ON CONFLICT … DO UPDATE` /
 * `UPDATE … RETURNING` statement for true atomicity — no read-modify-write
 * races. Multi-step writes (challenge, oauthState, emailOtp.upsert, and
 * identifier.replace's claim-then-release) run inside `sql.withTransaction`.
 * `ON CONFLICT` targets a declared primary key or unique index. MySQL has no
 * `ON CONFLICT` clause, so these statements fail there, and MySQL is not a
 * supported dialect (#260). For MySQL, use `@thomasfosterau/effect-auth-drizzle`'s
 * MySQL tables.
 *
 * Token columns store SHA-256 hashes computed by the service layer (the
 * `auth_sessions.id` primary key included) — the database never sees a raw
 * bearer token.
 */

import { Array as Arr, Clock, DateTime, Effect, Layer, Order, Record as Rec, Schema } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const fromBase64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64"));

const AttributesJson = Schema.fromJsonString(Auth.Attributes);
const StringListJson = Schema.fromJsonString(Schema.Array(Schema.String));
const PermissionsJson = Schema.fromJsonString(
  Schema.Record(Schema.String, Schema.Array(Schema.String)),
);

const encodeAttributes = Schema.encodeSync(AttributesJson);
const decodeAttributesJson = Schema.decodeSync(AttributesJson);
const encodeStringList = Schema.encodeSync(StringListJson);
const decodeStringList = Schema.decodeSync(StringListJson);
const encodePermissions = Schema.encodeSync(PermissionsJson);
const decodePermissions = Schema.decodeSync(PermissionsJson);

const decodeAttributes = (
  text: string | null,
  label: string,
): Effect.Effect<Auth.Attributes, Auth.AuthError> =>
  Effect.try({
    try: () => (text == null ? {} : decodeAttributesJson(text)),
    catch: (cause) =>
      new Auth.AuthError({ message: `${label}: attributes JSON parse failed`, cause }),
  });

const dateToMs = (date: Date): number => date.getTime();
const msToDate = (ms: number): Date => new Date(ms);

/**
 * Map a `SqlError` (or any defect from the driver) to the `AuthError` the
 * store interfaces expose, preserving the underlying cause.
 */
const toAuthError =
  (label: string) =>
  (cause: unknown): Auth.AuthError =>
    new Auth.AuthError({ message: `sql ${label} failed`, cause });

const asVoid = <A, E>(label: string, statement: Effect.Effect<A, E>) =>
  statement.pipe(Effect.asVoid, Effect.mapError(toAuthError(label)));

const allRows = <A>(label: string, statement: Effect.Effect<ReadonlyArray<A>, unknown>) =>
  statement.pipe(Effect.mapError(toAuthError(label)));

const firstRow = <A>(label: string, statement: Effect.Effect<ReadonlyArray<A>, unknown>) =>
  allRows(label, statement).pipe(Effect.map((rows) => rows[0] ?? null));

/**
 * Wraps an effect in a SQL transaction, mapping any transaction-level SQL
 * errors (BEGIN/COMMIT failures) to `AuthError`.
 */
const makeTx =
  (sql: SqlClient.SqlClient) =>
  <A>(label: string, effect: Effect.Effect<A, Auth.AuthError>): Effect.Effect<A, Auth.AuthError> =>
    sql
      .withTransaction(effect)
      .pipe(
        Effect.mapError((e): Auth.AuthError =>
          e instanceof Auth.AuthError
            ? e
            : new Auth.AuthError({ message: `sql ${label} failed`, cause: e }),
        ),
      );

// ---------------------------------------------------------------------------
// Shared user row (auth_users backs UserStore, UserServiceStore,
// EmailPasswordStore, PasswordResetUserStore, OAuthUserStore,
// MagicLinkUserStore and EmailOtpUserStore)
// ---------------------------------------------------------------------------

interface UserRow {
  readonly id: string;
  readonly name: string | null;
  readonly image: string | null;
  readonly password_hash: string | null;
  readonly attributes: string | null;
  readonly created_at: number;
  readonly updated_at: number;
}

const rowToUser = (row: UserRow, label: string): Effect.Effect<Auth.User, Auth.AuthError> =>
  decodeAttributes(row.attributes, label).pipe(
    Effect.map((attributes) => ({
      id: row.id,
      createdAt: msToDate(row.created_at),
      updatedAt: msToDate(row.updated_at),
      attributes,
      ...(row.name != null ? { name: row.name } : {}),
      ...(row.image != null ? { image: row.image } : {}),
    })),
  );

/** User-facing helpers shared by every store that reads/creates users. */
const userQueries = (sql: SqlClient.SqlClient) => {
  const getById = (userId: string, label: string) =>
    firstRow(label, sql<UserRow>`SELECT * FROM auth_users WHERE id = ${userId}`);

  const findById = (userId: string, label: string) =>
    getById(userId, label).pipe(
      Effect.flatMap((row) => (row ? rowToUser(row, label) : Effect.succeed(null))),
    );

  const requireById = (userId: string, label: string) =>
    getById(userId, label).pipe(
      Effect.flatMap((row): Effect.Effect<Auth.User, Auth.AuthError | Auth.UserNotFoundError> =>
        row
          ? rowToUser(row, label)
          : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    );

  const insert = (user: Auth.User, label: string) =>
    asVoid(
      label,
      sql`INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
          VALUES (${user.id}, ${user.name ?? null}, ${user.image ?? null}, ${null}, ${encodeAttributes(user.attributes)}, ${dateToMs(user.createdAt)}, ${dateToMs(user.updatedAt)})`,
    );

  const create = (
    input: {
      readonly name?: string;
      readonly image?: string;
      readonly attributes?: Auth.Attributes;
    },
    label: string,
  ): Effect.Effect<Auth.CreateUserResult, Auth.AuthError> =>
    Effect.gen(function* () {
      const now = yield* DateTime.nowAsDate;
      const user: Auth.User = {
        id: globalThis.crypto.randomUUID(),
        createdAt: now,
        updatedAt: now,
        attributes: input.attributes ?? {},
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.image !== undefined ? { image: input.image } : {}),
      };
      // A plain INSERT with a fresh id: every success is a new user.
      yield* insert(user, label);
      return { user, created: true };
    });

  const setPasswordHash = (userId: string, hash: string, label: string) =>
    asVoid(label, sql`UPDATE auth_users SET password_hash = ${hash} WHERE id = ${userId}`);

  const clearPasswordHash = (userId: string, label: string) =>
    asVoid(label, sql`UPDATE auth_users SET password_hash = NULL WHERE id = ${userId}`);

  const hasPassword = (userId: string, label: string) =>
    getById(userId, label).pipe(Effect.map((row) => row?.password_hash != null));

  return {
    getById,
    findById,
    requireById,
    create,
    setPasswordHash,
    clearPasswordHash,
    hasPassword,
  };
};

// ---------------------------------------------------------------------------
// SessionStore + UserStore
// ---------------------------------------------------------------------------

interface SessionRow {
  readonly id: string;
  readonly user_id: string;
  readonly expires_at: number;
  readonly created_at: number;
  readonly last_activity_at: number;
  readonly attributes: string | null;
}

const rowToSession = (
  row: SessionRow,
  label: string,
): Effect.Effect<Auth.Session, Auth.AuthError> =>
  decodeAttributes(row.attributes, label).pipe(
    Effect.map((attributes) => ({
      id: row.id,
      userId: row.user_id,
      expiresAt: msToDate(row.expires_at),
      createdAt: msToDate(row.created_at),
      lastActivityAt: msToDate(row.last_activity_at),
      attributes,
    })),
  );

/** `Auth.SessionStore` over the `auth_sessions` table; requires `SqlClient`. */
export const makeSessionStore: Effect.Effect<
  typeof Auth.SessionStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    create: (session) =>
      asVoid(
        "session.create",
        sql`INSERT INTO auth_sessions (id, user_id, expires_at, created_at, last_activity_at, attributes)
            VALUES (${session.id}, ${session.userId}, ${dateToMs(session.expiresAt)}, ${dateToMs(session.createdAt)}, ${dateToMs(session.lastActivityAt)}, ${encodeAttributes(session.attributes)})`,
      ).pipe(Effect.as(session)),
    get: (sessionId) =>
      firstRow(
        "session.get",
        sql<SessionRow>`SELECT * FROM auth_sessions WHERE id = ${sessionId}`,
      ).pipe(
        Effect.flatMap((row) => (row ? rowToSession(row, "session.get") : Effect.succeed(null))),
      ),
    update: (session) =>
      asVoid(
        "session.update",
        sql`UPDATE auth_sessions SET expires_at = ${dateToMs(session.expiresAt)}, last_activity_at = ${dateToMs(session.lastActivityAt)}, attributes = ${encodeAttributes(session.attributes)} WHERE id = ${session.id}`,
      ).pipe(Effect.as(session)),
    delete: (sessionId) =>
      asVoid("session.delete", sql`DELETE FROM auth_sessions WHERE id = ${sessionId}`),
    deleteByUserId: (userId) =>
      asVoid("session.deleteByUserId", sql`DELETE FROM auth_sessions WHERE user_id = ${userId}`),
    listByUserId: (userId) =>
      allRows(
        "session.listByUserId",
        sql<SessionRow>`SELECT * FROM auth_sessions WHERE user_id = ${userId}`,
      ).pipe(
        Effect.flatMap((rows) =>
          Effect.forEach(rows, (row) => rowToSession(row, "session.listByUserId"), {
            concurrency: 1,
          }),
        ),
      ),
  } satisfies typeof Auth.SessionStore.Service;
});

/** `Auth.UserStore` over the `auth_users` table; requires `SqlClient`. */
export const makeUserStore: Effect.Effect<
  typeof Auth.UserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    get: (userId) => users.findById(userId, "user.get"),
  } satisfies typeof Auth.UserStore.Service;
});

// ---------------------------------------------------------------------------
// UserServiceStore
// ---------------------------------------------------------------------------

/** `Auth.UserServiceStore` over the `auth_users` table; requires `SqlClient`. */
export const makeUserServiceStore: Effect.Effect<
  typeof Auth.UserServiceStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    get: (userId) => users.findById(userId, "userService.get"),
    update: (user) =>
      asVoid(
        "userService.update",
        sql`UPDATE auth_users SET name = ${user.name ?? null}, image = ${user.image ?? null}, attributes = ${encodeAttributes(user.attributes)}, updated_at = ${dateToMs(user.updatedAt)} WHERE id = ${user.id}`,
      ).pipe(Effect.as(user)),
    delete: (userId) =>
      asVoid("userService.delete", sql`DELETE FROM auth_users WHERE id = ${userId}`),
  } satisfies typeof Auth.UserServiceStore.Service;
});

// ---------------------------------------------------------------------------
// EmailPasswordStore + PasswordResetUserStore (auth_users)
// ---------------------------------------------------------------------------

/** `Auth.Email.EmailPasswordStore` over the `auth_users` table; requires `SqlClient`. */
export const makeEmailPasswordStore: Effect.Effect<
  typeof Auth.Email.EmailPasswordStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    createUser: (input) => users.create(input, "emailPassword.createUser"),
    getPasswordHash: (userId) =>
      users
        .getById(userId, "emailPassword.getPasswordHash")
        .pipe(Effect.map((row) => row?.password_hash ?? null)),
    setPasswordHash: (userId, hash) =>
      users.setPasswordHash(userId, hash, "emailPassword.setPasswordHash"),
    clearPasswordHash: (userId) =>
      users.clearPasswordHash(userId, "emailPassword.clearPasswordHash"),
  } satisfies typeof Auth.Email.EmailPasswordStore.Service;
});

/** `Auth.Password.PasswordResetUserStore` over the `auth_users` table; requires `SqlClient`. */
export const makePasswordResetUserStore: Effect.Effect<
  typeof Auth.Password.PasswordResetUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    setPasswordHash: (userId, hash) =>
      users.setPasswordHash(userId, hash, "passwordResetUser.setPasswordHash"),
  } satisfies typeof Auth.Password.PasswordResetUserStore.Service;
});

// ---------------------------------------------------------------------------
// RBAC (fails closed: storage errors become defects, never empty grants)
// ---------------------------------------------------------------------------
//
// `auth_user_roles` and `auth_role_permissions` feed the one authorization
// kernel, in its two halves (ADR 0018): role *assignment* is entity hierarchy,
// so it becomes an `EntityResolver`; role *grants* are policy, so they become
// declarative permits. There is no `RoleStore` service and no second
// evaluation path — both halves flow into `Authorizer`/`Policy.decide`.

interface RoleRow {
  readonly role: string;
}

interface RolePermissionRow {
  readonly role: string;
  readonly resource: string;
  readonly action: string;
}

/**
 * An {@link Auth.EntityResolver} projecting `auth_user_roles` into the entity
 * graph: `User::"<userId>"` with a `Role::"<role>"` parent per assigned role,
 * which is what `principal in Role::"admin"` decides over.
 *
 * Only `User::` references are answered; every other reference is omitted (the
 * kernel reads an absent entity as "no attributes, no parents"), so compose
 * this with an application's own resolver when policies also name domain
 * entities. The table carries no role-to-role edges, so this resolver
 * contributes no role inheritance — author that with `Auth.Rbac.entities` or
 * an application resolver.
 */
export const makeRbacEntityResolver: Effect.Effect<
  typeof Auth.EntityResolver.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const rolesFor = (userId: string) =>
    sql<RoleRow>`SELECT role FROM auth_user_roles WHERE user_id = ${userId}`.pipe(
      Effect.map((rows) => rows.map((row) => row.role)),
      Effect.orDie,
    );
  return {
    resolve: Effect.fn("Sql.rbacEntityResolver.resolve")(function* (
      refs: ReadonlyArray<Auth.Entity.EntityRef>,
    ) {
      const users = refs.filter((ref) => ref.type === Auth.Rbac.DefaultPrincipalType);
      return yield* Effect.forEach(
        users,
        (ref) =>
          Effect.map(rolesFor(ref.id), (roles) =>
            Auth.Entity.entity(ref, { parents: roles.map(Auth.Rbac.roleRef) }),
          ),
        { concurrency: 1 },
      );
    }),
  } satisfies typeof Auth.EntityResolver.Service;
});

/**
 * Read `auth_role_permissions` into declarative permits — the policy half of
 * the RBAC data, compiled by {@link Auth.Rbac.policies} so the SQL rows and a
 * hand-written `Auth.Rbac` configuration produce byte-identical policies.
 *
 * Policies are read once, where they are needed: pass the result to
 * `Auth.Authorizer.layer({ policies })` at startup, or re-read it behind a
 * `PolicyStore` if tenant edits must apply without a restart.
 */
export const readRbacPolicies: Effect.Effect<
  ReadonlyArray<Auth.Policy.DeclarativePolicy>,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.use((sql) =>
  sql<RolePermissionRow>`SELECT role, resource, action FROM auth_role_permissions`.pipe(
    Effect.orDie,
    Effect.map((rows) => {
      const rolePermissions = Rec.map(
        Arr.groupBy(rows, (row) => row.role),
        (grants) => grants.map((row) => ({ resource: row.resource, action: row.action })),
      );
      return Auth.Rbac.policies({ userRoles: {}, rolePermissions });
    }),
  ),
);

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

interface RateLimitRow {
  readonly key: string;
  readonly count: number;
  readonly reset_at: number;
  readonly blocked_until: number | null;
}

const rowToRateLimit = (row: RateLimitRow): Auth.RateLimitEntry =>
  row.blocked_until == null
    ? { key: row.key, count: row.count, resetAt: row.reset_at }
    : { key: row.key, count: row.count, resetAt: row.reset_at, blockedUntil: row.blocked_until };

/** `Auth.RateLimitStore` over the `auth_rate_limits` table; requires `SqlClient`. */
export const makeRateLimitStore: Effect.Effect<
  typeof Auth.RateLimitStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const readEntry = (key: string, label: string) =>
    firstRow(label, sql<RateLimitRow>`SELECT * FROM auth_rate_limits WHERE key = ${key}`).pipe(
      Effect.map((row) => (row ? rowToRateLimit(row) : null)),
    );

  return {
    get: (key) => readEntry(key, "rateLimit.get"),
    // Atomic single-statement upsert: no read-modify-write race.
    set: (key, entry, _ttl) =>
      asVoid(
        "rateLimit.set",
        sql`INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until)
              VALUES (${key}, ${entry.count}, ${entry.resetAt}, ${entry.blockedUntil ?? null})
              ON CONFLICT(key) DO UPDATE SET
                count = ${entry.count},
                reset_at = ${entry.resetAt},
                blocked_until = ${entry.blockedUntil ?? null}`,
      ),
    increment: (key, ttlSeconds) =>
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        const resetAt = now + ttlSeconds * 1000;
        // Single atomic upsert+increment: if the row is new or the window has
        // expired, reset count to 1; otherwise increment by 1. RETURNING
        // avoids a separate SELECT and prevents TOCTOU undercounting. The
        // right-hand side names the target table's columns explicitly:
        // unqualified, PostgreSQL reports them as ambiguous (#348).
        const rows = yield* allRows(
          "rateLimit.increment",
          sql<{ count: number }>`
            INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until)
              VALUES (${key}, 1, ${resetAt}, NULL)
              ON CONFLICT(key) DO UPDATE SET
                count = CASE WHEN ${now} >= auth_rate_limits.reset_at THEN 1 ELSE auth_rate_limits.count + 1 END,
                reset_at = CASE WHEN ${now} >= auth_rate_limits.reset_at THEN ${resetAt} ELSE auth_rate_limits.reset_at END,
                blocked_until = CASE WHEN ${now} >= auth_rate_limits.reset_at THEN NULL ELSE auth_rate_limits.blocked_until END
              RETURNING count`,
        );
        return rows[0]?.count ?? 1;
      }),
    delete: (key) =>
      asVoid("rateLimit.delete", sql`DELETE FROM auth_rate_limits WHERE key = ${key}`),
  } satisfies typeof Auth.RateLimitStore.Service;
});

// ---------------------------------------------------------------------------
// EmailVerificationStore
// ---------------------------------------------------------------------------

interface EmailVerificationRow {
  readonly token: string;
  readonly user_id: string;
  readonly email: string;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToEmailVerification = (row: EmailVerificationRow): Auth.Email.EmailVerification => ({
  token: row.token,
  userId: row.user_id,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

/** `Auth.Email.EmailVerificationStore` over the `auth_email_verifications` table; requires `SqlClient`. */
export const makeEmailVerificationStore: Effect.Effect<
  typeof Auth.Email.EmailVerificationStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    create: (verification) =>
      asVoid(
        "emailVerification.create",
        sql`INSERT INTO auth_email_verifications (token, user_id, email, created_at, expires_at)
            VALUES (${verification.token}, ${verification.userId}, ${verification.email}, ${verification.createdAt}, ${verification.expiresAt})`,
      ).pipe(Effect.as(verification)),
    get: (token) =>
      firstRow(
        "emailVerification.get",
        sql<EmailVerificationRow>`SELECT * FROM auth_email_verifications WHERE token = ${token}`,
      ).pipe(Effect.map((row) => (row ? rowToEmailVerification(row) : null))),
    delete: (token) =>
      asVoid(
        "emailVerification.delete",
        sql`DELETE FROM auth_email_verifications WHERE token = ${token}`,
      ),
    deleteByUserId: (userId) =>
      asVoid(
        "emailVerification.deleteByUserId",
        sql`DELETE FROM auth_email_verifications WHERE user_id = ${userId}`,
      ),
  } satisfies typeof Auth.Email.EmailVerificationStore.Service;
});

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore + CredentialStore
// ---------------------------------------------------------------------------

interface ChallengeRow {
  readonly challenge: string;
  readonly expires_at: number;
  readonly user_id: string | null;
}

const rowToChallenge = (row: ChallengeRow): Auth.MultiFactor.WebAuthnChallenge =>
  row.user_id == null
    ? { challenge: fromBase64(row.challenge), expiresAt: row.expires_at }
    : { challenge: fromBase64(row.challenge), expiresAt: row.expires_at, userId: row.user_id };

/** `Auth.MultiFactor.ChallengeStore` over the `auth_webauthn_challenges` table; requires `SqlClient`. */
export const makeChallengeStore: Effect.Effect<
  typeof Auth.MultiFactor.ChallengeStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);
  return {
    create: (challenge) =>
      withTx(
        "challenge.create",
        Effect.gen(function* () {
          const encoded = toBase64(challenge.challenge);
          yield* asVoid(
            "challenge.create",
            sql`DELETE FROM auth_webauthn_challenges WHERE challenge = ${encoded}`,
          );
          yield* asVoid(
            "challenge.create",
            sql`INSERT INTO auth_webauthn_challenges (challenge, expires_at, user_id)
                  VALUES (${encoded}, ${challenge.expiresAt}, ${challenge.userId ?? null})`,
          );
          return challenge;
        }),
      ),
    get: (challenge) =>
      firstRow(
        "challenge.get",
        sql<ChallengeRow>`SELECT * FROM auth_webauthn_challenges WHERE challenge = ${toBase64(challenge)}`,
      ).pipe(Effect.map((row) => (row ? rowToChallenge(row) : null))),
    delete: (challenge) =>
      asVoid(
        "challenge.delete",
        sql`DELETE FROM auth_webauthn_challenges WHERE challenge = ${toBase64(challenge)}`,
      ),
  } satisfies typeof Auth.MultiFactor.ChallengeStore.Service;
});

interface CredentialRow {
  readonly id: string;
  readonly user_id: string;
  readonly public_key: string;
  readonly algorithm: number;
  readonly counter: number;
  readonly created_at: number;
  readonly name: string | null;
  readonly transports: string | null;
}

const rowToCredential = (
  row: CredentialRow,
): Effect.Effect<Auth.MultiFactor.WebAuthnCredential, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      id: row.id,
      userId: row.user_id,
      publicKey: fromBase64(row.public_key),
      algorithm: row.algorithm,
      counter: row.counter,
      createdAt: row.created_at,
      ...(row.name != null ? { name: row.name } : {}),
      ...(row.transports != null ? { transports: decodeStringList(row.transports) } : {}),
    }),
    catch: (cause) => new Auth.AuthError({ message: "credential decode failed", cause }),
  });

/** `Auth.MultiFactor.CredentialStore` over the `auth_webauthn_credentials` table; requires `SqlClient`. */
export const makeCredentialStore: Effect.Effect<
  typeof Auth.MultiFactor.CredentialStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const getById = (credentialId: string, label: string) =>
    firstRow(
      label,
      sql<CredentialRow>`SELECT * FROM auth_webauthn_credentials WHERE id = ${credentialId}`,
    ).pipe(Effect.flatMap((row) => (row ? rowToCredential(row) : Effect.succeed(null))));

  return {
    create: (credential) =>
      asVoid(
        "credential.create",
        sql`INSERT INTO auth_webauthn_credentials (id, user_id, public_key, algorithm, counter, created_at, name, transports)
              VALUES (${credential.id}, ${credential.userId}, ${toBase64(credential.publicKey)}, ${credential.algorithm}, ${credential.counter}, ${credential.createdAt}, ${credential.name ?? null}, ${credential.transports ? encodeStringList(credential.transports) : null})`,
      ).pipe(Effect.as(credential)),
    get: (credentialId) => getById(credentialId, "credential.get"),
    // The credential `id` IS the base64url-encoded WebAuthn credential ID, so
    // the discoverable-login lookup is the same query.
    getByCredentialId: (credentialId) => getById(credentialId, "credential.getByCredentialId"),
    update: (credential) =>
      asVoid(
        "credential.update",
        sql`UPDATE auth_webauthn_credentials
              SET user_id = ${credential.userId}, public_key = ${toBase64(credential.publicKey)}, algorithm = ${credential.algorithm}, counter = ${credential.counter}, created_at = ${credential.createdAt}, name = ${credential.name ?? null}, transports = ${credential.transports ? encodeStringList(credential.transports) : null}
              WHERE id = ${credential.id}`,
      ).pipe(Effect.as(credential)),
    delete: (credentialId) =>
      asVoid(
        "credential.delete",
        sql`DELETE FROM auth_webauthn_credentials WHERE id = ${credentialId}`,
      ),
    listByUserId: (userId) =>
      allRows(
        "credential.listByUserId",
        sql<CredentialRow>`SELECT * FROM auth_webauthn_credentials WHERE user_id = ${userId}`,
      ).pipe(
        Effect.flatMap((rows) =>
          Effect.forEach(rows, (row) => rowToCredential(row), { concurrency: 1 }),
        ),
      ),
  } satisfies typeof Auth.MultiFactor.CredentialStore.Service;
});

// ---------------------------------------------------------------------------
// OAuthStateStore + OAuthAccountStore + OAuthUserStore
// ---------------------------------------------------------------------------

interface OAuthStateRow {
  readonly state: string;
  readonly provider: string;
  readonly code_verifier: string | null;
  readonly nonce: string | null;
  readonly return_to: string | null;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToOAuthState = (row: OAuthStateRow): Auth.OAuth.OAuthState => ({
  state: row.state,
  provider: row.provider,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
  ...(row.code_verifier != null ? { codeVerifier: row.code_verifier } : {}),
  ...(row.nonce != null ? { nonce: row.nonce } : {}),
  ...(row.return_to != null ? { returnTo: row.return_to } : {}),
});

/** `Auth.OAuth.OAuthStateStore` over the `auth_oauth_states` table; requires `SqlClient`. */
export const makeOAuthStateStore: Effect.Effect<
  typeof Auth.OAuth.OAuthStateStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);
  return {
    create: (state) =>
      withTx(
        "oauthState.create",
        Effect.gen(function* () {
          yield* asVoid(
            "oauthState.create",
            sql`DELETE FROM auth_oauth_states WHERE state = ${state.state}`,
          );
          yield* asVoid(
            "oauthState.create",
            sql`INSERT INTO auth_oauth_states (state, provider, code_verifier, nonce, return_to, created_at, expires_at)
                  VALUES (${state.state}, ${state.provider}, ${state.codeVerifier ?? null}, ${state.nonce ?? null}, ${state.returnTo ?? null}, ${state.createdAt}, ${state.expiresAt})`,
          );
          return state;
        }),
      ),
    get: (state) =>
      firstRow(
        "oauthState.get",
        sql<OAuthStateRow>`SELECT * FROM auth_oauth_states WHERE state = ${state}`,
      ).pipe(Effect.map((row) => (row ? rowToOAuthState(row) : null))),
    delete: (state) =>
      asVoid("oauthState.delete", sql`DELETE FROM auth_oauth_states WHERE state = ${state}`),
  } satisfies typeof Auth.OAuth.OAuthStateStore.Service;
});

interface OAuthAccountRow {
  readonly id: string;
  readonly user_id: string;
  readonly provider: string;
  readonly provider_id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly picture: string | null;
  readonly access_token: string;
  readonly refresh_token: string | null;
  readonly expires_at: number | null;
  readonly created_at: number;
  readonly updated_at: number;
}

const rowToOAuthAccount = (row: OAuthAccountRow): Auth.OAuth.OAuthAccount => ({
  id: row.id,
  userId: row.user_id,
  provider: row.provider,
  providerId: row.provider_id,
  accessToken: row.access_token,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  ...(row.email != null ? { email: row.email } : {}),
  ...(row.name != null ? { name: row.name } : {}),
  ...(row.picture != null ? { picture: row.picture } : {}),
  ...(row.refresh_token != null ? { refreshToken: row.refresh_token } : {}),
  ...(row.expires_at != null ? { expiresAt: row.expires_at } : {}),
});

/** `Auth.OAuth.OAuthAccountStore` over the `auth_oauth_accounts` table; requires `SqlClient`. */
export const makeOAuthAccountStore: Effect.Effect<
  typeof Auth.OAuth.OAuthAccountStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);

  const read = (provider: string, providerId: string, label: string) =>
    firstRow(
      label,
      sql<OAuthAccountRow>`SELECT * FROM auth_oauth_accounts WHERE provider = ${provider} AND provider_id = ${providerId}`,
    );

  /**
   * Atomic upsert keyed by the (provider, provider_id) unique index — a
   * single statement, so concurrent upserts can't lose each other's writes.
   */
  const upsert = (account: Auth.OAuth.OAuthAccount, label: string) =>
    asVoid(
      label,
      sql`INSERT INTO auth_oauth_accounts (id, user_id, provider, provider_id, email, name, picture, access_token, refresh_token, expires_at, created_at, updated_at)
          VALUES (${account.id}, ${account.userId}, ${account.provider}, ${account.providerId}, ${account.email ?? null}, ${account.name ?? null}, ${account.picture ?? null}, ${account.accessToken}, ${account.refreshToken ?? null}, ${account.expiresAt ?? null}, ${account.createdAt}, ${account.updatedAt})
          ON CONFLICT(provider, provider_id) DO UPDATE SET
            user_id = ${account.userId},
            email = ${account.email ?? null},
            name = ${account.name ?? null},
            picture = ${account.picture ?? null},
            access_token = ${account.accessToken},
            refresh_token = ${account.refreshToken ?? null},
            expires_at = ${account.expiresAt ?? null},
            updated_at = ${account.updatedAt}`,
    );

  return {
    create: (account) => upsert(account, "oauthAccount.create").pipe(Effect.as(account)),
    get: (provider, providerId) =>
      read(provider, providerId, "oauthAccount.get").pipe(
        Effect.map((row) => (row ? rowToOAuthAccount(row) : null)),
      ),
    getByUserId: (userId) =>
      allRows(
        "oauthAccount.getByUserId",
        sql<OAuthAccountRow>`SELECT * FROM auth_oauth_accounts WHERE user_id = ${userId}`,
      ).pipe(Effect.map((rows) => rows.map(rowToOAuthAccount))),
    update: (account) => upsert(account, "oauthAccount.update").pipe(Effect.as(account)),
    linkToUser: (userId, account) => upsert({ ...account, userId }, "oauthAccount.linkToUser"),
    unlinkFromUser: (userId, provider) =>
      asVoid(
        "oauthAccount.unlinkFromUser",
        sql`DELETE FROM auth_oauth_accounts WHERE user_id = ${userId} AND provider = ${provider}`,
      ),
    delete: (provider, providerId) =>
      asVoid(
        "oauthAccount.delete",
        sql`DELETE FROM auth_oauth_accounts WHERE provider = ${provider} AND provider_id = ${providerId}`,
      ),
    // Backed by auth_users.password_hash — enables the last-credential
    // unlinking guard without a separate store.
    hasPassword: (userId) => users.hasPassword(userId, "oauthAccount.hasPassword"),
  } satisfies typeof Auth.OAuth.OAuthAccountStore.Service;
});

/** `Auth.OAuth.OAuthUserStore` over the `auth_users` table; requires `SqlClient`. */
export const makeOAuthUserStore: Effect.Effect<
  typeof Auth.OAuth.OAuthUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    getUser: (userId) => users.requireById(userId, "oauthUser.getUser"),
    createUser: (input) => users.create(input, "oauthUser.createUser"),
    // Supports `updateUserInfoOnLink`: refresh profile fields from the provider.
    updateUser: (userId, update) =>
      Effect.gen(function* () {
        yield* asVoid(
          "oauthUser.updateUser",
          sql`UPDATE auth_users SET
                name = COALESCE(${update.name ?? null}, name),
                image = COALESCE(${update.image ?? null}, image),
                updated_at = ${yield* Clock.currentTimeMillis}
              WHERE id = ${userId}`,
        );
        return yield* users
          .requireById(userId, "oauthUser.updateUser")
          .pipe(
            Effect.catchTag("UserNotFoundError", (e) =>
              Effect.fail(new Auth.AuthError({ message: "User not found after update", cause: e })),
            ),
          );
      }),
  } satisfies typeof Auth.OAuth.OAuthUserStore.Service;
});

// ---------------------------------------------------------------------------
// PasswordResetStore
// ---------------------------------------------------------------------------

interface PasswordResetRow {
  readonly token: string;
  readonly user_id: string;
  readonly email: string;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToPasswordReset = (row: PasswordResetRow): Auth.Password.PasswordResetToken => ({
  token: row.token,
  userId: row.user_id,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

/** `Auth.Password.PasswordResetStore` over the `auth_password_resets` table; requires `SqlClient`. */
export const makePasswordResetStore: Effect.Effect<
  typeof Auth.Password.PasswordResetStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    create: (reset) =>
      asVoid(
        "passwordReset.create",
        sql`INSERT INTO auth_password_resets (token, user_id, email, created_at, expires_at)
            VALUES (${reset.token}, ${reset.userId}, ${reset.email}, ${reset.createdAt}, ${reset.expiresAt})`,
      ).pipe(Effect.as(reset)),
    get: (token) =>
      firstRow(
        "passwordReset.get",
        sql<PasswordResetRow>`SELECT * FROM auth_password_resets WHERE token = ${token}`,
      ).pipe(Effect.map((row) => (row ? rowToPasswordReset(row) : null))),
    delete: (token) =>
      asVoid("passwordReset.delete", sql`DELETE FROM auth_password_resets WHERE token = ${token}`),
    deleteByUserId: (userId) =>
      asVoid(
        "passwordReset.deleteByUserId",
        sql`DELETE FROM auth_password_resets WHERE user_id = ${userId}`,
      ),
  } satisfies typeof Auth.Password.PasswordResetStore.Service;
});

// ---------------------------------------------------------------------------
// MagicLinkStore + MagicLinkUserStore
// ---------------------------------------------------------------------------

interface MagicLinkRow {
  readonly token: string;
  readonly email: string;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToMagicLink = (row: MagicLinkRow): Auth.MagicLinkToken => ({
  token: row.token,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

/** `Auth.MagicLinkStore` over the `auth_magic_links` table; requires `SqlClient`. */
export const makeMagicLinkStore: Effect.Effect<
  typeof Auth.MagicLinkStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    create: (token) =>
      asVoid(
        "magicLink.create",
        sql`INSERT INTO auth_magic_links (token, email, created_at, expires_at)
              VALUES (${token.token}, ${token.email}, ${token.createdAt}, ${token.expiresAt})`,
      ).pipe(Effect.as(token)),
    get: (token) =>
      firstRow(
        "magicLink.get",
        sql<MagicLinkRow>`SELECT * FROM auth_magic_links WHERE token = ${token}`,
      ).pipe(Effect.map((row) => (row ? rowToMagicLink(row) : null))),
    getByEmail: (email) =>
      firstRow(
        "magicLink.getByEmail",
        sql<MagicLinkRow>`SELECT * FROM auth_magic_links WHERE email = ${email}`,
      ).pipe(Effect.map((row) => (row ? rowToMagicLink(row) : null))),
    delete: (token) =>
      asVoid("magicLink.delete", sql`DELETE FROM auth_magic_links WHERE token = ${token}`),
    deleteByEmail: (email) =>
      asVoid("magicLink.deleteByEmail", sql`DELETE FROM auth_magic_links WHERE email = ${email}`),
  } satisfies typeof Auth.MagicLinkStore.Service;
});

/** `Auth.MagicLinkUserStore` over the `auth_users` table; requires `SqlClient`. */
export const makeMagicLinkUserStore: Effect.Effect<
  typeof Auth.MagicLinkUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    createUser: (input) => users.create(input, "magicLinkUser.createUser"),
  } satisfies typeof Auth.MagicLinkUserStore.Service;
});

// ---------------------------------------------------------------------------
// EmailOtpStore + EmailOtpUserStore
// ---------------------------------------------------------------------------

interface EmailOtpRow {
  readonly email: string;
  readonly purpose: string;
  readonly otp_hash: string;
  readonly attempts: number;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToEmailOtp = (row: EmailOtpRow): Auth.Email.EmailOtpRecord => ({
  email: row.email,
  // SAFETY: `purpose` is only ever written from an `EmailOtpRecord`'s `purpose`
  // (see `upsert`), so every stored value is an `EmailOtpPurpose`.
  purpose: row.purpose as Auth.Email.EmailOtpPurpose,
  otpHash: row.otp_hash,
  attempts: row.attempts,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

/** `Auth.Email.EmailOtpStore` over the `auth_email_otps` table; requires `SqlClient`. */
export const makeEmailOtpStore: Effect.Effect<
  typeof Auth.Email.EmailOtpStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);

  const read = (email: string, purpose: Auth.Email.EmailOtpPurpose, label: string) =>
    firstRow(
      label,
      sql<EmailOtpRow>`SELECT * FROM auth_email_otps WHERE email = ${email} AND purpose = ${purpose}`,
    );

  return {
    upsert: (record) =>
      withTx(
        "emailOtp.upsert",
        Effect.gen(function* () {
          yield* asVoid(
            "emailOtp.upsert",
            sql`DELETE FROM auth_email_otps WHERE email = ${record.email} AND purpose = ${record.purpose}`,
          );
          yield* asVoid(
            "emailOtp.upsert",
            sql`INSERT INTO auth_email_otps (email, purpose, otp_hash, attempts, created_at, expires_at)
              VALUES (${record.email}, ${record.purpose}, ${record.otpHash}, ${record.attempts}, ${record.createdAt}, ${record.expiresAt})`,
          );
          return record;
        }),
      ),
    get: (email, purpose) =>
      read(email, purpose, "emailOtp.get").pipe(
        Effect.map((row) => (row ? rowToEmailOtp(row) : null)),
      ),
    delete: (email, purpose) =>
      asVoid(
        "emailOtp.delete",
        sql`DELETE FROM auth_email_otps WHERE email = ${email} AND purpose = ${purpose}`,
      ),
    incrementAttempts: (email, purpose) =>
      Effect.gen(function* () {
        // Single atomic UPDATE + RETURNING avoids a read-modify-write race.
        const rows = yield* allRows(
          "emailOtp.incrementAttempts",
          sql<{ attempts: number }>`
            UPDATE auth_email_otps
              SET attempts = attempts + 1
            WHERE email = ${email} AND purpose = ${purpose}
            RETURNING attempts`,
        );
        const attempts = rows[0]?.attempts;
        if (attempts == null) {
          return yield* new Auth.AuthError({ message: "OTP record not found" });
        }
        return attempts;
      }),
  } satisfies typeof Auth.Email.EmailOtpStore.Service;
});

/** `Auth.Email.EmailOtpUserStore` over the `auth_users` table; requires `SqlClient`. */
export const makeEmailOtpUserStore: Effect.Effect<
  typeof Auth.Email.EmailOtpUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  return {
    createUser: (input) => users.create(input, "emailOtpUser.createUser"),
  } satisfies typeof Auth.Email.EmailOtpUserStore.Service;
});

// ---------------------------------------------------------------------------
// purgeExpired
// ---------------------------------------------------------------------------

/**
 * How many expired rows one {@link purgeExpired} run deleted, per table.
 */
export interface PurgeExpiredResult {
  /** Rows deleted from `auth_magic_links`. */
  readonly magicLinks: number;
  /** Rows deleted from `auth_email_otps`. */
  readonly emailOtps: number;
}

/**
 * Delete the magic-link and email-OTP rows whose `expires_at` has passed;
 * requires `SqlClient`.
 *
 * No store deletes these rows on its own: a record nobody redeems stays until
 * a later send for the same address replaces it, and the sends that hide
 * whether an account exists write one for any address. Schedule this from the
 * host (a cron trigger on Workers, a timer on a long-lived server) so the
 * tables stay bounded. An expired row is already refused by the services, so a
 * purge changes no outcome; it only reclaims the space. Expiry is read from the
 * `Clock`.
 */
export const purgeExpired: Effect.Effect<PurgeExpiredResult, Auth.AuthError, SqlClient.SqlClient> =
  SqlClient.SqlClient.use((sql) =>
    Clock.currentTimeMillis.pipe(
      Effect.flatMap((now) =>
        Effect.all(
          {
            magicLinks: allRows(
              "purgeExpired.magicLinks",
              sql<{
                token: string;
              }>`DELETE FROM auth_magic_links WHERE expires_at <= ${now} RETURNING token`,
            ),
            emailOtps: allRows(
              "purgeExpired.emailOtps",
              sql<{
                email: string;
              }>`DELETE FROM auth_email_otps WHERE expires_at <= ${now} RETURNING email`,
            ),
          },
          { concurrency: 1 },
        ),
      ),
      Effect.map(({ magicLinks, emailOtps }) => ({
        magicLinks: magicLinks.length,
        emailOtps: emailOtps.length,
      })),
    ),
  );

// ---------------------------------------------------------------------------
// MultiFactorStore + PendingMultiFactorStore
// ---------------------------------------------------------------------------

interface MultiFactorRow {
  readonly user_id: string;
  readonly secret: string;
  readonly backup_codes: string;
  readonly verified: number;
  readonly created_at: number;
  readonly last_used_counter: number | null;
}

const rowToMultiFactor = (
  row: MultiFactorRow,
): Effect.Effect<Auth.MultiFactor.MultiFactorRecord, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      userId: row.user_id,
      secret: row.secret,
      backupCodes: decodeStringList(row.backup_codes),
      verified: row.verified !== 0,
      createdAt: row.created_at,
      ...(row.last_used_counter != null ? { lastUsedCounter: row.last_used_counter } : {}),
    }),
    catch: (cause) => new Auth.AuthError({ message: "multiFactor decode failed", cause }),
  });

/** `Auth.MultiFactor.MultiFactorStore` over the `auth_multi_factor` table; requires `SqlClient`. */
export const makeMultiFactorStore: Effect.Effect<
  typeof Auth.MultiFactor.MultiFactorStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const read = (userId: string, label: string) =>
    firstRow(label, sql<MultiFactorRow>`SELECT * FROM auth_multi_factor WHERE user_id = ${userId}`);

  return {
    get: (userId) =>
      read(userId, "multiFactor.get").pipe(
        Effect.flatMap((row) => (row ? rowToMultiFactor(row) : Effect.succeed(null))),
      ),
    // Atomic single-statement upsert keyed by the user_id primary key.
    upsert: (record) =>
      asVoid(
        "multiFactor.upsert",
        sql`INSERT INTO auth_multi_factor (user_id, secret, backup_codes, verified, created_at, last_used_counter)
              VALUES (${record.userId}, ${record.secret}, ${encodeStringList(record.backupCodes)}, ${record.verified ? 1 : 0}, ${record.createdAt}, ${record.lastUsedCounter ?? null})
              ON CONFLICT(user_id) DO UPDATE SET
                secret = ${record.secret},
                backup_codes = ${encodeStringList(record.backupCodes)},
                verified = ${record.verified ? 1 : 0},
                created_at = ${record.createdAt},
                last_used_counter = ${record.lastUsedCounter ?? null}`,
      ).pipe(Effect.as(record)),
    delete: (userId) =>
      asVoid("multiFactor.delete", sql`DELETE FROM auth_multi_factor WHERE user_id = ${userId}`),
  } satisfies typeof Auth.MultiFactor.MultiFactorStore.Service;
});

interface PendingMultiFactorRow {
  readonly token: string;
  readonly user_id: string;
  readonly expires_at: number;
  readonly created_at: number;
}

const rowToPendingMultiFactor = (
  row: PendingMultiFactorRow,
): Auth.MultiFactor.PendingMultiFactor => ({
  token: row.token,
  userId: row.user_id,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
});

/** `Auth.MultiFactor.PendingMultiFactorStore` over the `auth_pending_multi_factor` table; requires `SqlClient`. */
export const makePendingMultiFactorStore: Effect.Effect<
  typeof Auth.MultiFactor.PendingMultiFactorStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    create: (pending) =>
      asVoid(
        "pendingMultiFactor.create",
        sql`INSERT INTO auth_pending_multi_factor (token, user_id, expires_at, created_at)
            VALUES (${pending.token}, ${pending.userId}, ${pending.expiresAt}, ${pending.createdAt})`,
      ).pipe(Effect.as(pending)),
    get: (token) =>
      firstRow(
        "pendingMultiFactor.get",
        sql<PendingMultiFactorRow>`SELECT * FROM auth_pending_multi_factor WHERE token = ${token}`,
      ).pipe(Effect.map((row) => (row ? rowToPendingMultiFactor(row) : null))),
    delete: (token) =>
      asVoid(
        "pendingMultiFactor.delete",
        sql`DELETE FROM auth_pending_multi_factor WHERE token = ${token}`,
      ),
  } satisfies typeof Auth.MultiFactor.PendingMultiFactorStore.Service;
});

// ---------------------------------------------------------------------------
// IdentifierStore
// ---------------------------------------------------------------------------

interface IdentifierRow {
  readonly id: string;
  readonly user_id: string;
  readonly type: string;
  readonly value: string;
  readonly verified: number;
  readonly verified_at: number | null;
  readonly created_at: number;
}

const rowToIdentifier = (row: IdentifierRow): Auth.Identifier => ({
  id: row.id,
  userId: row.user_id,
  // SAFETY: `type` is only ever written from an `Identifier`'s `type` (see
  // `insert`), so every stored value is an `IdentifierType`.
  type: row.type as Auth.IdentifierType,
  value: row.value,
  verified: row.verified !== 0,
  ...(row.verified_at != null ? { verifiedAt: msToDate(row.verified_at) } : {}),
  createdAt: msToDate(row.created_at),
});

/** `Auth.IdentifierStore` over the `auth_identifiers` table; requires `SqlClient`. */
export const makeIdentifierStore: Effect.Effect<
  typeof Auth.IdentifierStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);

  const insert = (identifier: Auth.Identifier, label: string) =>
    asVoid(
      label,
      sql`INSERT INTO auth_identifiers (id, user_id, type, value, verified, verified_at, created_at)
          VALUES (${identifier.id}, ${identifier.userId}, ${identifier.type}, ${identifier.value}, ${identifier.verified ? 1 : 0}, ${identifier.verifiedAt != null ? dateToMs(identifier.verifiedAt) : null}, ${dateToMs(identifier.createdAt)})`,
    ).pipe(Effect.as(identifier));

  return {
    getByValue: (type, value) =>
      firstRow(
        "identifier.getByValue",
        sql<IdentifierRow>`SELECT * FROM auth_identifiers WHERE type = ${type} AND value = ${value}`,
      ).pipe(Effect.map((row) => (row ? rowToIdentifier(row) : null))),

    listByUser: (userId) =>
      allRows(
        "identifier.listByUser",
        sql<IdentifierRow>`SELECT * FROM auth_identifiers WHERE user_id = ${userId} ORDER BY created_at ASC`,
      ).pipe(Effect.map((rows) => rows.map(rowToIdentifier))),

    create: (identifier) => insert(identifier, "identifier.create"),

    // Claim, then release, in one transaction. A `to` another user holds fails
    // the INSERT on the `(type, value)` unique index and rolls back, so `from`
    // stays. The release is a compare-and-swap: the DELETE matches `from` by id,
    // user, type and value, so a `from` that is gone (another replace released
    // it first) deletes nothing, the claim is removed again and the call
    // resolves to null. On PostgreSQL a concurrent second DELETE waits for the
    // first to commit and then matches nothing (at PostgreSQL's default READ
    // COMMITTED isolation; stricter levels fail with a serialization error,
    // surfaced as `AuthError`), so of two replaces of one `from` one succeeds.
    // D1 has no transactions: the statements autocommit in the same order, so
    // a failure between them leaves both rows, never neither, and the removal
    // of a stale claim is a statement of its own.
    replace: (from, to) => {
      const invalid = Auth.replaceInputError(from, to);
      if (invalid !== null) return Effect.fail(invalid);
      return withTx(
        "identifier.replace",
        Effect.gen(function* () {
          yield* insert(to, "identifier.replace");
          const released = yield* allRows(
            "identifier.replace",
            sql<{
              readonly id: string;
            }>`DELETE FROM auth_identifiers WHERE id = ${from.id} AND user_id = ${from.userId} AND type = ${from.type} AND value = ${from.value} RETURNING id`,
          );
          if (Arr.isReadonlyArrayNonEmpty(released)) return to;
          // `from` was not held: take the claim back. A DELETE rather than a
          // ROLLBACK, so D1, where a ROLLBACK does nothing, ends unchanged too.
          yield* asVoid(
            "identifier.replace.undo",
            sql`DELETE FROM auth_identifiers WHERE id = ${to.id}`,
          );
          return null;
        }),
      );
    },

    setVerified: (id, verifiedAt) =>
      Effect.gen(function* () {
        yield* asVoid(
          "identifier.setVerified",
          sql`UPDATE auth_identifiers SET verified = 1, verified_at = ${dateToMs(verifiedAt)} WHERE id = ${id}`,
        );
        return yield* firstRow(
          "identifier.setVerified",
          sql<IdentifierRow>`SELECT * FROM auth_identifiers WHERE id = ${id}`,
        ).pipe(Effect.map((row) => (row ? rowToIdentifier(row) : null)));
      }),

    delete: (id) => asVoid("identifier.delete", sql`DELETE FROM auth_identifiers WHERE id = ${id}`),

    deleteByUser: (userId) =>
      asVoid(
        "identifier.deleteByUser",
        sql`DELETE FROM auth_identifiers WHERE user_id = ${userId}`,
      ),
  } satisfies typeof Auth.IdentifierStore.Service;
});

// ---------------------------------------------------------------------------
// AccountLockoutStore
// ---------------------------------------------------------------------------

interface AccountLockoutRow {
  readonly key: string;
  readonly failures: number;
  readonly locked_until: number | null;
}

const rowToLockout = (row: AccountLockoutRow): Auth.Plugins.AccountLockoutRecord =>
  row.locked_until == null
    ? { failures: row.failures }
    : { failures: row.failures, lockedUntil: row.locked_until };

/** `Auth.Plugins.AccountLockoutStore` over the `auth_account_lockouts` table; requires `SqlClient`. */
export const makeAccountLockoutStore: Effect.Effect<
  typeof Auth.Plugins.AccountLockoutStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  return {
    get: (key) =>
      firstRow(
        "accountLockout.get",
        sql<AccountLockoutRow>`SELECT * FROM auth_account_lockouts WHERE key = ${key}`,
      ).pipe(Effect.map((row) => (row ? rowToLockout(row) : null))),
    // The whole transition is one statement, so concurrent attempts can't
    // lose increments: an active lock is returned unchanged; an expired lock
    // (or missing row) resets to 1; otherwise increment; crossing the
    // threshold sets locked_until.
    registerAttempt: (key, { maxAttempts, lockoutDurationMs, now }) =>
      Effect.gen(function* () {
        const lockedUntil = now + lockoutDurationMs;
        const rows = yield* allRows(
          "accountLockout.registerAttempt",
          sql<AccountLockoutRow>`
            INSERT INTO auth_account_lockouts (key, failures, locked_until)
              VALUES (${key}, 1, ${1 >= maxAttempts ? lockedUntil : null})
              ON CONFLICT(key) DO UPDATE SET
                failures = CASE
                  WHEN auth_account_lockouts.locked_until IS NOT NULL AND auth_account_lockouts.locked_until > ${now} THEN auth_account_lockouts.failures
                  WHEN auth_account_lockouts.locked_until IS NOT NULL AND auth_account_lockouts.locked_until <= ${now} THEN 1
                  ELSE auth_account_lockouts.failures + 1 END,
                locked_until = CASE
                  WHEN auth_account_lockouts.locked_until IS NOT NULL AND auth_account_lockouts.locked_until > ${now} THEN auth_account_lockouts.locked_until
                  WHEN (CASE
                    WHEN auth_account_lockouts.locked_until IS NOT NULL AND auth_account_lockouts.locked_until <= ${now} THEN 1
                    ELSE auth_account_lockouts.failures + 1 END) >= ${maxAttempts} THEN ${lockedUntil}
                  ELSE NULL END
              RETURNING key, failures, locked_until`,
        );
        const row = rows[0];
        if (row === undefined) {
          return yield* new Auth.AuthError({
            message: "accountLockout.registerAttempt returned no row",
          });
        }
        return rowToLockout(row);
      }),
    delete: (key) =>
      asVoid("accountLockout.delete", sql`DELETE FROM auth_account_lockouts WHERE key = ${key}`),
  } satisfies typeof Auth.Plugins.AccountLockoutStore.Service;
});

// ---------------------------------------------------------------------------
// ApiKeyStore
// ---------------------------------------------------------------------------

interface ApiKeyRow {
  readonly id: string;
  readonly name: string | null;
  readonly prefix: string | null;
  readonly start: string;
  readonly key_hash: string;
  readonly user_id: string;
  readonly enabled: number;
  readonly expires_at: number | null;
  readonly last_used_at: number | null;
  readonly permissions: string | null;
  readonly metadata: string | null;
  readonly remaining: number | null;
  readonly refill_amount: number | null;
  readonly refill_interval: number | null;
  readonly refill_max: number | null;
  readonly last_refill_at: number | null;
  readonly rate_limit_max_requests: number | null;
  readonly rate_limit_window_ms: number | null;
  readonly created_at: number;
  readonly updated_at: number;
}

const rowToApiKey = (row: ApiKeyRow): Effect.Effect<Auth.ApiKey, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      id: row.id,
      ...(row.name != null ? { name: row.name } : {}),
      ...(row.prefix != null ? { prefix: row.prefix } : {}),
      start: row.start,
      keyHash: row.key_hash,
      userId: row.user_id,
      enabled: row.enabled !== 0,
      ...(row.expires_at != null ? { expiresAt: row.expires_at } : {}),
      ...(row.last_used_at != null ? { lastUsedAt: row.last_used_at } : {}),
      ...(row.permissions != null ? { permissions: decodePermissions(row.permissions) } : {}),
      metadata: row.metadata != null ? decodeAttributesJson(row.metadata) : {},
      ...(row.remaining != null ? { remaining: row.remaining } : {}),
      ...(row.refill_amount != null ? { refillAmount: row.refill_amount } : {}),
      ...(row.refill_interval != null ? { refillInterval: row.refill_interval } : {}),
      ...(row.refill_max != null ? { refillMax: row.refill_max } : {}),
      ...(row.last_refill_at != null ? { lastRefillAt: row.last_refill_at } : {}),
      ...(row.rate_limit_max_requests != null && row.rate_limit_window_ms != null
        ? {
            rateLimit: {
              maxRequests: row.rate_limit_max_requests,
              windowMs: row.rate_limit_window_ms,
            },
          }
        : {}),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }),
    catch: (cause) => new Auth.AuthError({ message: "api key decode failed", cause }),
  });

/** `Auth.ApiKeyStore` over the `auth_api_keys` table; requires `SqlClient`. */
export const makeApiKeyStore: Effect.Effect<
  typeof Auth.ApiKeyStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const getById = (id: string, label: string) =>
    firstRow(label, sql<ApiKeyRow>`SELECT * FROM auth_api_keys WHERE id = ${id}`).pipe(
      Effect.flatMap((row) => (row ? rowToApiKey(row) : Effect.succeed(null))),
    );

  return {
    create: (apiKey) =>
      asVoid(
        "apiKey.create",
        sql`INSERT INTO auth_api_keys (id, name, prefix, start, key_hash, user_id, enabled, expires_at, last_used_at, permissions, metadata, remaining, refill_amount, refill_interval, refill_max, last_refill_at, rate_limit_max_requests, rate_limit_window_ms, created_at, updated_at)
              VALUES (${apiKey.id}, ${apiKey.name ?? null}, ${apiKey.prefix ?? null}, ${apiKey.start}, ${apiKey.keyHash}, ${apiKey.userId}, ${apiKey.enabled ? 1 : 0}, ${apiKey.expiresAt ?? null}, ${apiKey.lastUsedAt ?? null}, ${apiKey.permissions ? encodePermissions(apiKey.permissions) : null}, ${encodeAttributes(apiKey.metadata)}, ${apiKey.remaining ?? null}, ${apiKey.refillAmount ?? null}, ${apiKey.refillInterval ?? null}, ${apiKey.refillMax ?? null}, ${apiKey.lastRefillAt ?? null}, ${apiKey.rateLimit?.maxRequests ?? null}, ${apiKey.rateLimit?.windowMs ?? null}, ${apiKey.createdAt}, ${apiKey.updatedAt})`,
      ).pipe(Effect.as(apiKey)),
    get: (id) => getById(id, "apiKey.get"),
    getByHash: (keyHash) =>
      firstRow(
        "apiKey.getByHash",
        sql<ApiKeyRow>`SELECT * FROM auth_api_keys WHERE key_hash = ${keyHash}`,
      ).pipe(Effect.flatMap((row) => (row ? rowToApiKey(row) : Effect.succeed(null)))),
    update: (apiKey) =>
      asVoid(
        "apiKey.update",
        sql`UPDATE auth_api_keys SET
              name = ${apiKey.name ?? null},
              prefix = ${apiKey.prefix ?? null},
              start = ${apiKey.start},
              key_hash = ${apiKey.keyHash},
              user_id = ${apiKey.userId},
              enabled = ${apiKey.enabled ? 1 : 0},
              expires_at = ${apiKey.expiresAt ?? null},
              last_used_at = ${apiKey.lastUsedAt ?? null},
              permissions = ${apiKey.permissions ? encodePermissions(apiKey.permissions) : null},
              metadata = ${encodeAttributes(apiKey.metadata)},
              remaining = ${apiKey.remaining ?? null},
              refill_amount = ${apiKey.refillAmount ?? null},
              refill_interval = ${apiKey.refillInterval ?? null},
              refill_max = ${apiKey.refillMax ?? null},
              last_refill_at = ${apiKey.lastRefillAt ?? null},
              rate_limit_max_requests = ${apiKey.rateLimit?.maxRequests ?? null},
              rate_limit_window_ms = ${apiKey.rateLimit?.windowMs ?? null},
              updated_at = ${apiKey.updatedAt}
            WHERE id = ${apiKey.id}`,
      ).pipe(Effect.as(apiKey)),
    delete: (id) => asVoid("apiKey.delete", sql`DELETE FROM auth_api_keys WHERE id = ${id}`),
    listByUserId: (userId) =>
      allRows(
        "apiKey.listByUserId",
        sql<ApiKeyRow>`SELECT * FROM auth_api_keys WHERE user_id = ${userId}`,
      ).pipe(
        Effect.flatMap((rows) =>
          Effect.forEach(rows, (row) => rowToApiKey(row), { concurrency: 1 }),
        ),
      ),
  } satisfies typeof Auth.ApiKeyStore.Service;
});

// ---------------------------------------------------------------------------
// AdminUserStore (reuses auth_users + auth_identifiers — no dedicated table)
// ---------------------------------------------------------------------------

interface UserRowWithEmail extends UserRow {
  readonly primary_email: string | null;
}

/** Orders by `email` with `localeCompare`, the order `listUsers` pages in. */
const byEmail: Order.Order<{ readonly email: string }> = Order.make((a, b) => {
  const compared = a.email.localeCompare(b.email);
  return compared < 0 ? -1 : compared > 0 ? 1 : 0;
});

/** `Auth.AdminUserStore` over the `auth_users` and `auth_identifiers` tables; requires `SqlClient`. */
export const makeAdminUserStore: Effect.Effect<
  typeof Auth.AdminUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);

  return {
    // No SQL-side pagination: matches/sorts on each user's earliest email
    // identifier, which lives in a different table and isn't indexable as a
    // plain column, so the candidate set is materialized once and paged in
    // memory (mirrors the reference semantics in Admin.test.ts's test store).
    listUsers: (query) =>
      Effect.gen(function* () {
        const rows = yield* allRows(
          "adminUser.listUsers",
          sql<UserRowWithEmail>`
            SELECT u.*, (
              SELECT value FROM auth_identifiers ie
              WHERE ie.user_id = u.id AND ie.type = 'email'
              ORDER BY ie.created_at ASC LIMIT 1
            ) AS primary_email
            FROM auth_users u`,
        );
        const decorated = yield* Effect.forEach(
          rows,
          (row) =>
            rowToUser(row, "adminUser.listUsers").pipe(
              Effect.map((user) => ({ user, email: row.primary_email ?? "" })),
            ),
          { concurrency: 1 },
        );
        const search = query.searchEmail?.toLowerCase();
        const matching = Arr.sort(
          decorated.filter(({ email }) => (search ? email.toLowerCase().includes(search) : true)),
          byEmail,
        );
        const offset = query.offset ?? 0;
        const limit = query.limit ?? matching.length;
        return {
          users: matching.slice(offset, offset + limit).map(({ user }) => user),
          total: matching.length,
        } satisfies Auth.ListUsersResult;
      }),
    createUser: (input) => users.create(input, "adminUser.createUser"),
    setPasswordHash: (userId, hash) =>
      users.setPasswordHash(userId, hash, "adminUser.setPasswordHash"),
  } satisfies typeof Auth.AdminUserStore.Service;
});

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/** Provides `Auth.SessionStore` from {@link makeSessionStore}; requires `SqlClient`. */
export const SessionStoreLayer: Layer.Layer<Auth.SessionStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.SessionStore, makeSessionStore);
/** Provides `Auth.UserStore` from {@link makeUserStore}; requires `SqlClient`. */
export const UserStoreLayer: Layer.Layer<Auth.UserStore, never, SqlClient.SqlClient> = Layer.effect(
  Auth.UserStore,
  makeUserStore,
);
/** Provides `Auth.UserServiceStore` from {@link makeUserServiceStore}; requires `SqlClient`. */
export const UserServiceStoreLayer: Layer.Layer<Auth.UserServiceStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.UserServiceStore, makeUserServiceStore);
/** Provides `Auth.Email.EmailPasswordStore` from {@link makeEmailPasswordStore}; requires `SqlClient`. */
export const EmailPasswordStoreLayer: Layer.Layer<
  Auth.Email.EmailPasswordStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Email.EmailPasswordStore, makeEmailPasswordStore);
/** Provides `Auth.Password.PasswordResetUserStore` from {@link makePasswordResetUserStore}; requires `SqlClient`. */
export const PasswordResetUserStoreLayer: Layer.Layer<
  Auth.Password.PasswordResetUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Password.PasswordResetUserStore, makePasswordResetUserStore);
/**
 * Layer providing {@link Auth.EntityResolver} from `auth_user_roles`.
 *
 * Deliberately outside {@link layer}: `EntityResolver` is a single slot an
 * application usually fills with a composed resolver (its own entities, the
 * organization bridge, this one), not a storage interface to bundle.
 */
export const RbacEntityResolverLayer: Layer.Layer<Auth.EntityResolver, never, SqlClient.SqlClient> =
  Layer.effect(Auth.EntityResolver, makeRbacEntityResolver);
/** Provides `Auth.RateLimitStore` from {@link makeRateLimitStore}; requires `SqlClient`. */
export const RateLimitStoreLayer: Layer.Layer<Auth.RateLimitStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.RateLimitStore, makeRateLimitStore);
/** Provides `Auth.Email.EmailVerificationStore` from {@link makeEmailVerificationStore}; requires `SqlClient`. */
export const EmailVerificationStoreLayer: Layer.Layer<
  Auth.Email.EmailVerificationStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Email.EmailVerificationStore, makeEmailVerificationStore);
/** Provides `Auth.MultiFactor.ChallengeStore` from {@link makeChallengeStore}; requires `SqlClient`. */
export const ChallengeStoreLayer: Layer.Layer<
  Auth.MultiFactor.ChallengeStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MultiFactor.ChallengeStore, makeChallengeStore);
/** Provides `Auth.MultiFactor.CredentialStore` from {@link makeCredentialStore}; requires `SqlClient`. */
export const CredentialStoreLayer: Layer.Layer<
  Auth.MultiFactor.CredentialStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MultiFactor.CredentialStore, makeCredentialStore);
/** Provides `Auth.OAuth.OAuthStateStore` from {@link makeOAuthStateStore}; requires `SqlClient`. */
export const OAuthStateStoreLayer: Layer.Layer<
  Auth.OAuth.OAuthStateStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.OAuth.OAuthStateStore, makeOAuthStateStore);
/** Provides `Auth.OAuth.OAuthAccountStore` from {@link makeOAuthAccountStore}; requires `SqlClient`. */
export const OAuthAccountStoreLayer: Layer.Layer<
  Auth.OAuth.OAuthAccountStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.OAuth.OAuthAccountStore, makeOAuthAccountStore);
/** Provides `Auth.OAuth.OAuthUserStore` from {@link makeOAuthUserStore}; requires `SqlClient`. */
export const OAuthUserStoreLayer: Layer.Layer<
  Auth.OAuth.OAuthUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.OAuth.OAuthUserStore, makeOAuthUserStore);
/** Provides `Auth.Password.PasswordResetStore` from {@link makePasswordResetStore}; requires `SqlClient`. */
export const PasswordResetStoreLayer: Layer.Layer<
  Auth.Password.PasswordResetStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Password.PasswordResetStore, makePasswordResetStore);
/** Provides `Auth.MagicLinkStore` from {@link makeMagicLinkStore}; requires `SqlClient`. */
export const MagicLinkStoreLayer: Layer.Layer<Auth.MagicLinkStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.MagicLinkStore, makeMagicLinkStore);
/** Provides `Auth.MagicLinkUserStore` from {@link makeMagicLinkUserStore}; requires `SqlClient`. */
export const MagicLinkUserStoreLayer: Layer.Layer<
  Auth.MagicLinkUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MagicLinkUserStore, makeMagicLinkUserStore);
/** Provides `Auth.Email.EmailOtpStore` from {@link makeEmailOtpStore}; requires `SqlClient`. */
export const EmailOtpStoreLayer: Layer.Layer<Auth.Email.EmailOtpStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.Email.EmailOtpStore, makeEmailOtpStore);
/** Provides `Auth.Email.EmailOtpUserStore` from {@link makeEmailOtpUserStore}; requires `SqlClient`. */
export const EmailOtpUserStoreLayer: Layer.Layer<
  Auth.Email.EmailOtpUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Email.EmailOtpUserStore, makeEmailOtpUserStore);
/** Provides `Auth.MultiFactor.MultiFactorStore` from {@link makeMultiFactorStore}; requires `SqlClient`. */
export const MultiFactorStoreLayer: Layer.Layer<
  Auth.MultiFactor.MultiFactorStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MultiFactor.MultiFactorStore, makeMultiFactorStore);
/** Provides `Auth.MultiFactor.PendingMultiFactorStore` from {@link makePendingMultiFactorStore}; requires `SqlClient`. */
export const PendingMultiFactorStoreLayer: Layer.Layer<
  Auth.MultiFactor.PendingMultiFactorStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MultiFactor.PendingMultiFactorStore, makePendingMultiFactorStore);
/** Provides `Auth.IdentifierStore` from {@link makeIdentifierStore}; requires `SqlClient`. */
export const IdentifierStoreLayer: Layer.Layer<Auth.IdentifierStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.IdentifierStore, makeIdentifierStore);
/** Provides `Auth.Plugins.AccountLockoutStore` from {@link makeAccountLockoutStore}; requires `SqlClient`. */
export const AccountLockoutStoreLayer: Layer.Layer<
  Auth.Plugins.AccountLockoutStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.Plugins.AccountLockoutStore, makeAccountLockoutStore);
/** Provides `Auth.ApiKeyStore` from {@link makeApiKeyStore}; requires `SqlClient`. */
export const ApiKeyStoreLayer: Layer.Layer<Auth.ApiKeyStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.ApiKeyStore, makeApiKeyStore);
/** Provides `Auth.AdminUserStore` from {@link makeAdminUserStore}; requires `SqlClient`. */
export const AdminUserStoreLayer: Layer.Layer<Auth.AdminUserStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.AdminUserStore, makeAdminUserStore);

/**
 * A single layer that provides every SQL-backed effect-auth store on top of
 * the ambient `SqlClient`. Provide it once (together with any `SqlClient`
 * layer) and the core auth stack (SessionService, EmailPasswordService,
 * OAuth, WebAuthn, MagicLink, EmailOtp, MultiFactor, Admin, ApiKey, ...) has
 * persistence.
 *
 * Stores added to core after this package's restoration (OneTimeToken,
 * TrustedDevice, PhoneOtp, Organization, OIDC provider, SSO,
 * DeviceAuthorization, ...) are not yet covered here — use the
 * `KeyValueStore`-backed layers from core or bring your own until they land.
 *
 * Authorization is not bundled: wire {@link RbacEntityResolverLayer} and
 * {@link readRbacPolicies} into an `Authorizer` yourself, because
 * `EntityResolver` is one slot an application composes rather than a store.
 */
export const layer: Layer.Layer<
  | Auth.SessionStore
  | Auth.UserStore
  | Auth.UserServiceStore
  | Auth.Email.EmailPasswordStore
  | Auth.Password.PasswordResetUserStore
  | Auth.RateLimitStore
  | Auth.Email.EmailVerificationStore
  | Auth.MultiFactor.ChallengeStore
  | Auth.MultiFactor.CredentialStore
  | Auth.OAuth.OAuthStateStore
  | Auth.OAuth.OAuthAccountStore
  | Auth.OAuth.OAuthUserStore
  | Auth.Password.PasswordResetStore
  | Auth.MagicLinkStore
  | Auth.MagicLinkUserStore
  | Auth.Email.EmailOtpStore
  | Auth.Email.EmailOtpUserStore
  | Auth.MultiFactor.MultiFactorStore
  | Auth.MultiFactor.PendingMultiFactorStore
  | Auth.IdentifierStore
  | Auth.Plugins.AccountLockoutStore
  | Auth.ApiKeyStore
  | Auth.AdminUserStore,
  never,
  SqlClient.SqlClient
> = Layer.mergeAll(
  SessionStoreLayer,
  UserStoreLayer,
  UserServiceStoreLayer,
  EmailPasswordStoreLayer,
  PasswordResetUserStoreLayer,
  RateLimitStoreLayer,
  EmailVerificationStoreLayer,
  ChallengeStoreLayer,
  CredentialStoreLayer,
  OAuthStateStoreLayer,
  OAuthAccountStoreLayer,
  OAuthUserStoreLayer,
  PasswordResetStoreLayer,
  MagicLinkStoreLayer,
  MagicLinkUserStoreLayer,
  EmailOtpStoreLayer,
  EmailOtpUserStoreLayer,
  MultiFactorStoreLayer,
  PendingMultiFactorStoreLayer,
  IdentifierStoreLayer,
  AccountLockoutStoreLayer,
  ApiKeyStoreLayer,
  AdminUserStoreLayer,
);
