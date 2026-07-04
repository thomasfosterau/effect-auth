/**
 * Driver-agnostic SQL implementations of every effect-auth storage interface.
 *
 * Each `make*Store` is an Effect that reads the `SqlClient` service from
 * `effect/unstable/sql` out of the context and builds a plain store object,
 * and each `*StoreLayer` lifts it into an Effect `Layer` keyed by the
 * matching effect-auth `Context.Tag`. {@link layer} bundles all of them so a
 * single `Layer.provide` wires up the entire auth stack on top of any
 * `SqlClient` layer (pg, mysql, sqlite, D1, ...).
 *
 * Data codecs mirror `@effect-auth/alchemy`: dates as epoch milliseconds,
 * booleans as `0`/`1`, attribute bags and other structured values as JSON
 * `TEXT`, binary values (WebAuthn keys/challenges) as base64 `TEXT`.
 *
 * Multi-step upserts (challenge, oauthState, emailOtp) run inside
 * `sql.withTransaction` to prevent a partial DELETE+INSERT from being visible
 * to concurrent readers. The rate-limit increment and OTP attempt increment use
 * a single `ON CONFLICT … RETURNING` statement for true atomicity.
 *
 * ## Breaking change — token columns now store SHA-256 hashes (since bearer-token-hashing)
 *
 * The `token` column in `auth_magic_links`, `auth_email_verifications`,
 * `auth_password_resets`, and the `device_code` / `user_code` columns in
 * `auth_device_authorizations` previously stored plaintext values. They now
 * store SHA-256 hex digests computed by the service layer (via `hashToken`
 * from `effect-auth`).
 *
 * The `id` column in `auth_sessions` (the primary key) also now stores the
 * SHA-256 hash of the raw bearer token. The raw token is only ever held in
 * the session cookie; the database never sees it. This matches the
 * Copenhagen/Lucia split: cookie carries the raw token, store persists only
 * its hash.
 *
 * **Migration:** existing rows are stale after this upgrade — any outstanding
 * tokens (session cookies, magic links, password-reset links) issued before
 * the upgrade will not resolve to a matching row and will be rejected as
 * invalid. That is the safe behaviour: require users to re-login / re-request
 * links after deploying. No column rename or type change is required; the
 * column type (`TEXT`) is unchanged.
 */

import { Effect, Layer } from "effect";
import { SqlClient } from "effect/unstable/sql";
import { randomUUID } from "node:crypto";
import * as Auth from "effect-auth";

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const fromBase64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64"));

const encodeAttributes = (attributes: Record<string, unknown>): string =>
  JSON.stringify(attributes);

const decodeAttributes = (
  text: string | null,
  label: string,
): Effect.Effect<Record<string, unknown>, Auth.AuthError> =>
  Effect.try({
    try: () => (text == null ? {} : (JSON.parse(text) as Record<string, unknown>)),
    catch: (cause) =>
      new Auth.AuthError({ message: `${label}: attributes JSON parse failed`, cause }),
  });

const dateToMs = (date: Date): number => date.getTime();
const msToDate = (ms: number): Date => new Date(ms);

/**
 * Map a `SqlError` (or any defect from the driver) to the `AuthError` the
 * store interfaces expose, mirroring alchemy's `toAuthError`.
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
        Effect.mapError(
          (e): Auth.AuthError =>
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
  readonly email: string;
  readonly email_verified: number;
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
      email: row.email,
      emailVerified: row.email_verified !== 0,
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

  const getByEmail = (email: string, label: string) =>
    firstRow(label, sql<UserRow>`SELECT * FROM auth_users WHERE email = ${email}`).pipe(
      Effect.flatMap((row) => (row ? rowToUser(row, label) : Effect.succeed(null))),
    );

  const findById = (userId: string, label: string) =>
    getById(userId, label).pipe(
      Effect.flatMap((row) => (row ? rowToUser(row, label) : Effect.succeed(null))),
    );

  const requireById = (userId: string, label: string) =>
    getById(userId, label).pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? rowToUser(row, label)
          : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    );

  const insert = (user: Auth.User, label: string) =>
    asVoid(
      label,
      sql`INSERT INTO auth_users (id, email, email_verified, name, image, password_hash, attributes, created_at, updated_at)
          VALUES (${user.id}, ${user.email}, ${user.emailVerified ? 1 : 0}, ${user.name ?? null}, ${user.image ?? null}, ${null}, ${encodeAttributes(user.attributes)}, ${dateToMs(user.createdAt)}, ${dateToMs(user.updatedAt)})`,
    );

  const create = (
    input: {
      readonly email: string;
      readonly emailVerified?: boolean;
      readonly name?: string;
      readonly image?: string;
      readonly attributes?: Record<string, unknown>;
    },
    label: string,
  ): Effect.Effect<Auth.User, Auth.AuthError> =>
    Effect.gen(function* () {
      const now = new Date();
      const user: Auth.User = {
        id: randomUUID(),
        email: input.email,
        emailVerified: input.emailVerified ?? false,
        createdAt: now,
        updatedAt: now,
        attributes: input.attributes ?? {},
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.image !== undefined ? { image: input.image } : {}),
      };
      yield* insert(user, label);
      return user;
    });

  const setPasswordHash = (userId: string, hash: string, label: string) =>
    asVoid(label, sql`UPDATE auth_users SET password_hash = ${hash} WHERE id = ${userId}`);

  return { getById, getByEmail, findById, requireById, create, setPasswordHash };
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

export const makeSessionStore: Effect.Effect<Auth.SessionStoreShape, never, SqlClient.SqlClient> =
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
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
            Effect.all(rows.map((row) => rowToSession(row, "session.listByUserId"))),
          ),
        ),
    } satisfies Auth.SessionStoreShape;
  });

export const makeUserStore: Effect.Effect<Auth.UserStoreShape, never, SqlClient.SqlClient> =
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const users = userQueries(sql);
    return {
      get: (userId) => users.findById(userId, "user.get"),
      getCredentials: (userId) =>
        users
          .getById(userId, "user.getCredentials")
          .pipe(Effect.map((row) => row?.password_hash ?? null)),
    } satisfies Auth.UserStoreShape;
  });

// ---------------------------------------------------------------------------
// UserServiceStore
// ---------------------------------------------------------------------------

export const makeUserServiceStore: Effect.Effect<
  Auth.UserServiceStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    get: (userId) => users.findById(userId, "userService.get"),
    getByEmail: (email) => users.getByEmail(email, "userService.getByEmail"),
    update: (user) =>
      asVoid(
        "userService.update",
        sql`UPDATE auth_users SET email = ${user.email}, email_verified = ${user.emailVerified ? 1 : 0}, name = ${user.name ?? null}, image = ${user.image ?? null}, attributes = ${encodeAttributes(user.attributes)}, updated_at = ${dateToMs(user.updatedAt)} WHERE id = ${user.id}`,
      ).pipe(Effect.as(user)),
    delete: (userId) =>
      asVoid("userService.delete", sql`DELETE FROM auth_users WHERE id = ${userId}`),
  } satisfies Auth.UserServiceStoreShape;
});

// ---------------------------------------------------------------------------
// EmailPasswordStore + PasswordResetUserStore (auth_users)
// ---------------------------------------------------------------------------

export const makeEmailPasswordStore: Effect.Effect<
  Auth.EmailPasswordStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    getUserByEmail: (email) => users.getByEmail(email, "emailPassword.getUserByEmail"),
    createUser: (input) => users.create(input, "emailPassword.createUser"),
    getPasswordHash: (userId) =>
      users
        .getById(userId, "emailPassword.getPasswordHash")
        .pipe(Effect.map((row) => row?.password_hash ?? null)),
    setPasswordHash: (userId, hash) =>
      users.setPasswordHash(userId, hash, "emailPassword.setPasswordHash"),
  } satisfies Auth.EmailPasswordStoreShape;
});

export const makePasswordResetUserStore: Effect.Effect<
  Auth.PasswordResetUserStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    getUserByEmail: (email) => users.getByEmail(email, "passwordResetUser.getUserByEmail"),
    setPasswordHash: (userId, hash) =>
      users.setPasswordHash(userId, hash, "passwordResetUser.setPasswordHash"),
  } satisfies Auth.PasswordResetUserStoreShape;
});

// ---------------------------------------------------------------------------
// RoleStore (fails closed: storage errors become defects, never empty grants)
// ---------------------------------------------------------------------------

interface RoleRow {
  readonly role: string;
}

interface PermissionRow {
  readonly resource: string;
  readonly action: string;
}

export const makeRoleStore: Effect.Effect<Auth.RoleStoreShape, never, SqlClient.SqlClient> =
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    return {
      getUserRoles: (userId) =>
        sql<RoleRow>`SELECT role FROM auth_user_roles WHERE user_id = ${userId}`.pipe(
          Effect.map((rows) => rows.map((row) => row.role)),
          Effect.orDie,
        ),
      getRolePermissions: (role) =>
        sql<PermissionRow>`SELECT resource, action FROM auth_role_permissions WHERE role = ${role}`.pipe(
          Effect.map((rows) => rows.map((row) => ({ resource: row.resource, action: row.action }))),
          Effect.orDie,
        ),
    } satisfies Auth.RoleStoreShape;
  });

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

export const makeRateLimitStore: Effect.Effect<
  Auth.RateLimitStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const readEntry = (key: string, label: string) =>
    firstRow(label, sql<RateLimitRow>`SELECT * FROM auth_rate_limits WHERE key = ${key}`).pipe(
      Effect.map((row) => (row ? rowToRateLimit(row) : null)),
    );

  const upsert = (key: string, entry: Auth.RateLimitEntry, label: string) =>
    Effect.gen(function* () {
      const existing = yield* readEntry(key, label);
      if (existing == null) {
        yield* asVoid(
          label,
          sql`INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until)
                VALUES (${key}, ${entry.count}, ${entry.resetAt}, ${entry.blockedUntil ?? null})`,
        );
      } else {
        yield* asVoid(
          label,
          sql`UPDATE auth_rate_limits SET count = ${entry.count}, reset_at = ${entry.resetAt}, blocked_until = ${entry.blockedUntil ?? null} WHERE key = ${key}`,
        );
      }
    });

  return {
    get: (key) => readEntry(key, "rateLimit.get"),
    set: (key, entry, _ttl) => upsert(key, entry, "rateLimit.set"),
    increment: (key, ttlSeconds) =>
      Effect.gen(function* () {
        const now = Date.now();
        const resetAt = now + ttlSeconds * 1000;
        // Single atomic upsert+increment: if the row is new or the window has
        // expired, reset count to 1; otherwise increment by 1. RETURNING
        // avoids a separate SELECT and prevents TOCTOU undercounting.
        const rows = yield* allRows(
          "rateLimit.increment",
          sql<{ count: number }>`
            INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until)
              VALUES (${key}, 1, ${resetAt}, NULL)
              ON CONFLICT(key) DO UPDATE SET
                count = CASE WHEN ${now} >= reset_at THEN 1 ELSE count + 1 END,
                reset_at = CASE WHEN ${now} >= reset_at THEN ${resetAt} ELSE reset_at END,
                blocked_until = CASE WHEN ${now} >= reset_at THEN NULL ELSE blocked_until END
              RETURNING count`,
        );
        return rows[0]?.count ?? 1;
      }),
    delete: (key) =>
      asVoid("rateLimit.delete", sql`DELETE FROM auth_rate_limits WHERE key = ${key}`),
  } satisfies Auth.RateLimitStoreShape;
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

const rowToEmailVerification = (row: EmailVerificationRow): Auth.EmailVerification => ({
  token: row.token,
  userId: row.user_id,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

export const makeEmailVerificationStore: Effect.Effect<
  Auth.EmailVerificationStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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
  } satisfies Auth.EmailVerificationStoreShape;
});

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore + CredentialStore
// ---------------------------------------------------------------------------

interface ChallengeRow {
  readonly challenge: string;
  readonly expires_at: number;
  readonly user_id: string | null;
}

const rowToChallenge = (row: ChallengeRow): Auth.WebAuthnChallenge =>
  row.user_id == null
    ? { challenge: fromBase64(row.challenge), expiresAt: row.expires_at }
    : { challenge: fromBase64(row.challenge), expiresAt: row.expires_at, userId: row.user_id };

export const makeChallengeStore: Effect.Effect<
  Auth.ChallengeStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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
  } satisfies Auth.ChallengeStoreShape;
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
): Effect.Effect<Auth.WebAuthnCredential, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      id: row.id,
      userId: row.user_id,
      publicKey: fromBase64(row.public_key),
      algorithm: row.algorithm,
      counter: row.counter,
      createdAt: row.created_at,
      ...(row.name != null ? { name: row.name } : {}),
      ...(row.transports != null
        ? { transports: JSON.parse(row.transports) as readonly string[] }
        : {}),
    }),
    catch: (cause) => new Auth.AuthError({ message: "credential decode failed", cause }),
  });

export const makeCredentialStore: Effect.Effect<
  Auth.CredentialStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  return {
    create: (credential) =>
      asVoid(
        "credential.create",
        sql`INSERT INTO auth_webauthn_credentials (id, user_id, public_key, algorithm, counter, created_at, name, transports)
              VALUES (${credential.id}, ${credential.userId}, ${toBase64(credential.publicKey)}, ${credential.algorithm}, ${credential.counter}, ${credential.createdAt}, ${credential.name ?? null}, ${credential.transports ? JSON.stringify(credential.transports) : null})`,
      ).pipe(Effect.as(credential)),
    get: (credentialId) =>
      firstRow(
        "credential.get",
        sql<CredentialRow>`SELECT * FROM auth_webauthn_credentials WHERE id = ${credentialId}`,
      ).pipe(Effect.flatMap((row) => (row ? rowToCredential(row) : Effect.succeed(null)))),
    update: (credential) =>
      asVoid(
        "credential.update",
        sql`UPDATE auth_webauthn_credentials
              SET user_id = ${credential.userId}, public_key = ${toBase64(credential.publicKey)}, algorithm = ${credential.algorithm}, counter = ${credential.counter}, created_at = ${credential.createdAt}, name = ${credential.name ?? null}, transports = ${credential.transports ? JSON.stringify(credential.transports) : null}
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
      ).pipe(Effect.flatMap((rows) => Effect.all(rows.map((row) => rowToCredential(row))))),
  } satisfies Auth.CredentialStoreShape;
});

// ---------------------------------------------------------------------------
// OAuthStateStore + OAuthAccountStore + OAuthUserStore
// ---------------------------------------------------------------------------

interface OAuthStateRow {
  readonly state: string;
  readonly provider: string;
  readonly code_verifier: string | null;
  readonly return_to: string | null;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToOAuthState = (row: OAuthStateRow): Auth.OAuthState => ({
  state: row.state,
  provider: row.provider,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
  ...(row.code_verifier != null ? { codeVerifier: row.code_verifier } : {}),
  ...(row.return_to != null ? { returnTo: row.return_to } : {}),
});

export const makeOAuthStateStore: Effect.Effect<
  Auth.OAuthStateStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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
            sql`INSERT INTO auth_oauth_states (state, provider, code_verifier, return_to, created_at, expires_at)
                  VALUES (${state.state}, ${state.provider}, ${state.codeVerifier ?? null}, ${state.returnTo ?? null}, ${state.createdAt}, ${state.expiresAt})`,
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
  } satisfies Auth.OAuthStateStoreShape;
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

const rowToOAuthAccount = (row: OAuthAccountRow): Auth.OAuthAccount => ({
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

export const makeOAuthAccountStore: Effect.Effect<
  Auth.OAuthAccountStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const read = (provider: string, providerId: string, label: string) =>
    firstRow(
      label,
      sql<OAuthAccountRow>`SELECT * FROM auth_oauth_accounts WHERE provider = ${provider} AND provider_id = ${providerId}`,
    );

  /** Portable upsert keyed by (provider, provider_id). */
  const upsert = (account: Auth.OAuthAccount, label: string) =>
    Effect.gen(function* () {
      const existing = yield* read(account.provider, account.providerId, label);
      if (existing == null) {
        yield* asVoid(
          label,
          sql`INSERT INTO auth_oauth_accounts (id, user_id, provider, provider_id, email, name, picture, access_token, refresh_token, expires_at, created_at, updated_at)
              VALUES (${account.id}, ${account.userId}, ${account.provider}, ${account.providerId}, ${account.email ?? null}, ${account.name ?? null}, ${account.picture ?? null}, ${account.accessToken}, ${account.refreshToken ?? null}, ${account.expiresAt ?? null}, ${account.createdAt}, ${account.updatedAt})`,
        );
      } else {
        yield* asVoid(
          label,
          sql`UPDATE auth_oauth_accounts
              SET user_id = ${account.userId}, email = ${account.email ?? null}, name = ${account.name ?? null}, picture = ${account.picture ?? null}, access_token = ${account.accessToken}, refresh_token = ${account.refreshToken ?? null}, expires_at = ${account.expiresAt ?? null}, updated_at = ${account.updatedAt}
              WHERE provider = ${account.provider} AND provider_id = ${account.providerId}`,
        );
      }
    });

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
  } satisfies Auth.OAuthAccountStoreShape;
});

export const makeOAuthUserStore: Effect.Effect<
  Auth.OAuthUserStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    getUser: (userId) => users.requireById(userId, "oauthUser.getUser"),
    getUserByEmail: (email) => users.getByEmail(email, "oauthUser.getUserByEmail"),
    createUser: (input) => users.create(input, "oauthUser.createUser"),
  } satisfies Auth.OAuthUserStoreShape;
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

const rowToPasswordReset = (row: PasswordResetRow): Auth.PasswordResetToken => ({
  token: row.token,
  userId: row.user_id,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

export const makePasswordResetStore: Effect.Effect<
  Auth.PasswordResetStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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
  } satisfies Auth.PasswordResetStoreShape;
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

export const makeMagicLinkStore: Effect.Effect<
  Auth.MagicLinkStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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
    delete: (token) =>
      asVoid("magicLink.delete", sql`DELETE FROM auth_magic_links WHERE token = ${token}`),
    deleteByEmail: (email) =>
      asVoid("magicLink.deleteByEmail", sql`DELETE FROM auth_magic_links WHERE email = ${email}`),
  } satisfies Auth.MagicLinkStoreShape;
});

export const makeMagicLinkUserStore: Effect.Effect<
  Auth.MagicLinkUserStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    getUserByEmail: (email) => users.getByEmail(email, "magicLinkUser.getUserByEmail"),
    createUser: (input) => users.create(input, "magicLinkUser.createUser"),
  } satisfies Auth.MagicLinkUserStoreShape;
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

const rowToEmailOtp = (row: EmailOtpRow): Auth.EmailOtpRecord => ({
  email: row.email,
  purpose: row.purpose as Auth.EmailOtpPurpose,
  otpHash: row.otp_hash,
  attempts: row.attempts,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

export const makeEmailOtpStore: Effect.Effect<Auth.EmailOtpStoreShape, never, SqlClient.SqlClient> =
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const withTx = makeTx(sql);

    const read = (email: string, purpose: Auth.EmailOtpPurpose, label: string) =>
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
            return yield* Effect.fail(new Auth.AuthError({ message: "OTP record not found" }));
          }
          return attempts;
        }),
    } satisfies Auth.EmailOtpStoreShape;
  });

export const makeEmailOtpUserStore: Effect.Effect<
  Auth.EmailOtpUserStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const users = userQueries(sql);
  return {
    getUserByEmail: (email) => users.getByEmail(email, "emailOtpUser.getUserByEmail"),
    createUser: (input) => users.create(input, "emailOtpUser.createUser"),
  } satisfies Auth.EmailOtpUserStoreShape;
});

// ---------------------------------------------------------------------------
// TwoFactorStore + PendingTwoFactorStore
// ---------------------------------------------------------------------------

interface TwoFactorRow {
  readonly user_id: string;
  readonly secret: string;
  readonly backup_codes: string;
  readonly verified: number;
  readonly created_at: number;
}

const rowToTwoFactor = (row: TwoFactorRow): Effect.Effect<Auth.TwoFactorRecord, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      userId: row.user_id,
      secret: row.secret,
      backupCodes: JSON.parse(row.backup_codes) as readonly string[],
      verified: row.verified !== 0,
      createdAt: row.created_at,
    }),
    catch: (cause) => new Auth.AuthError({ message: "twoFactor decode failed", cause }),
  });

export const makeTwoFactorStore: Effect.Effect<
  Auth.TwoFactorStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  const read = (userId: string, label: string) =>
    firstRow(label, sql<TwoFactorRow>`SELECT * FROM auth_two_factor WHERE user_id = ${userId}`);

  return {
    get: (userId) =>
      read(userId, "twoFactor.get").pipe(
        Effect.flatMap((row) => (row ? rowToTwoFactor(row) : Effect.succeed(null))),
      ),
    upsert: (record) =>
      Effect.gen(function* () {
        const backupCodes = JSON.stringify(record.backupCodes);
        const verified = record.verified ? 1 : 0;
        const existing = yield* read(record.userId, "twoFactor.upsert");
        if (existing == null) {
          yield* asVoid(
            "twoFactor.upsert",
            sql`INSERT INTO auth_two_factor (user_id, secret, backup_codes, verified, created_at)
                  VALUES (${record.userId}, ${record.secret}, ${backupCodes}, ${verified}, ${record.createdAt})`,
          );
        } else {
          yield* asVoid(
            "twoFactor.upsert",
            sql`UPDATE auth_two_factor SET secret = ${record.secret}, backup_codes = ${backupCodes}, verified = ${verified}, created_at = ${record.createdAt} WHERE user_id = ${record.userId}`,
          );
        }
        return record;
      }),
    delete: (userId) =>
      asVoid("twoFactor.delete", sql`DELETE FROM auth_two_factor WHERE user_id = ${userId}`),
  } satisfies Auth.TwoFactorStoreShape;
});

interface PendingTwoFactorRow {
  readonly token: string;
  readonly user_id: string;
  readonly expires_at: number;
  readonly created_at: number;
}

const rowToPendingTwoFactor = (row: PendingTwoFactorRow): Auth.PendingTwoFactor => ({
  token: row.token,
  userId: row.user_id,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
});

export const makePendingTwoFactorStore: Effect.Effect<
  Auth.PendingTwoFactorStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  return {
    create: (pending) =>
      asVoid(
        "pendingTwoFactor.create",
        sql`INSERT INTO auth_pending_two_factor (token, user_id, expires_at, created_at)
            VALUES (${pending.token}, ${pending.userId}, ${pending.expiresAt}, ${pending.createdAt})`,
      ).pipe(Effect.as(pending)),
    get: (token) =>
      firstRow(
        "pendingTwoFactor.get",
        sql<PendingTwoFactorRow>`SELECT * FROM auth_pending_two_factor WHERE token = ${token}`,
      ).pipe(Effect.map((row) => (row ? rowToPendingTwoFactor(row) : null))),
    delete: (token) =>
      asVoid(
        "pendingTwoFactor.delete",
        sql`DELETE FROM auth_pending_two_factor WHERE token = ${token}`,
      ),
  } satisfies Auth.PendingTwoFactorStoreShape;
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
  type: row.type as Auth.IdentifierType,
  value: row.value,
  verified: row.verified !== 0,
  ...(row.verified_at != null ? { verifiedAt: msToDate(row.verified_at) } : {}),
  createdAt: msToDate(row.created_at),
});

export const makeIdentifierStore: Effect.Effect<
  Auth.IdentifierStoreShape,
  never,
  SqlClient.SqlClient
> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
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

    create: (identifier) =>
      asVoid(
        "identifier.create",
        sql`INSERT INTO auth_identifiers (id, user_id, type, value, verified, verified_at, created_at)
            VALUES (${identifier.id}, ${identifier.userId}, ${identifier.type}, ${identifier.value}, ${identifier.verified ? 1 : 0}, ${identifier.verifiedAt != null ? dateToMs(identifier.verifiedAt) : null}, ${dateToMs(identifier.createdAt)})`,
      ).pipe(Effect.as(identifier)),

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
  } satisfies Auth.IdentifierStoreShape;
});

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

export const SessionStoreLayer: Layer.Layer<Auth.SessionStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.SessionStore, makeSessionStore);
export const UserStoreLayer: Layer.Layer<Auth.UserStore, never, SqlClient.SqlClient> = Layer.effect(
  Auth.UserStore,
  makeUserStore,
);
export const UserServiceStoreLayer: Layer.Layer<Auth.UserServiceStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.UserServiceStore, makeUserServiceStore);
export const EmailPasswordStoreLayer: Layer.Layer<
  Auth.EmailPasswordStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.EmailPasswordStore, makeEmailPasswordStore);
export const PasswordResetUserStoreLayer: Layer.Layer<
  Auth.PasswordResetUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.PasswordResetUserStore, makePasswordResetUserStore);
export const RoleStoreLayer: Layer.Layer<Auth.RoleStore, never, SqlClient.SqlClient> = Layer.effect(
  Auth.RoleStore,
  makeRoleStore,
);
export const RateLimitStoreLayer: Layer.Layer<Auth.RateLimitStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.RateLimitStore, makeRateLimitStore);
export const EmailVerificationStoreLayer: Layer.Layer<
  Auth.EmailVerificationStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.EmailVerificationStore, makeEmailVerificationStore);
export const ChallengeStoreLayer: Layer.Layer<Auth.ChallengeStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.ChallengeStore, makeChallengeStore);
export const CredentialStoreLayer: Layer.Layer<Auth.CredentialStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.CredentialStore, makeCredentialStore);
export const OAuthStateStoreLayer: Layer.Layer<Auth.OAuthStateStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.OAuthStateStore, makeOAuthStateStore);
export const OAuthAccountStoreLayer: Layer.Layer<
  Auth.OAuthAccountStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.OAuthAccountStore, makeOAuthAccountStore);
export const OAuthUserStoreLayer: Layer.Layer<Auth.OAuthUserStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.OAuthUserStore, makeOAuthUserStore);
export const PasswordResetStoreLayer: Layer.Layer<
  Auth.PasswordResetStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.PasswordResetStore, makePasswordResetStore);
export const MagicLinkStoreLayer: Layer.Layer<Auth.MagicLinkStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.MagicLinkStore, makeMagicLinkStore);
export const MagicLinkUserStoreLayer: Layer.Layer<
  Auth.MagicLinkUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.MagicLinkUserStore, makeMagicLinkUserStore);
export const EmailOtpStoreLayer: Layer.Layer<Auth.EmailOtpStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.EmailOtpStore, makeEmailOtpStore);
export const EmailOtpUserStoreLayer: Layer.Layer<
  Auth.EmailOtpUserStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.EmailOtpUserStore, makeEmailOtpUserStore);
export const TwoFactorStoreLayer: Layer.Layer<Auth.TwoFactorStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.TwoFactorStore, makeTwoFactorStore);
export const PendingTwoFactorStoreLayer: Layer.Layer<
  Auth.PendingTwoFactorStore,
  never,
  SqlClient.SqlClient
> = Layer.effect(Auth.PendingTwoFactorStore, makePendingTwoFactorStore);
export const IdentifierStoreLayer: Layer.Layer<Auth.IdentifierStore, never, SqlClient.SqlClient> =
  Layer.effect(Auth.IdentifierStore, makeIdentifierStore);

/**
 * A single layer that provides every effect-auth store backed by the ambient
 * `SqlClient`. Provide it once (together with any `SqlClient` layer) and the
 * entire auth stack (SessionManager, EmailPasswordService, OAuth, WebAuthn,
 * MagicLink, EmailOtp, TwoFactor, etc.) has persistence.
 */
export const layer: Layer.Layer<
  | Auth.SessionStore
  | Auth.UserStore
  | Auth.UserServiceStore
  | Auth.EmailPasswordStore
  | Auth.PasswordResetUserStore
  | Auth.RoleStore
  | Auth.RateLimitStore
  | Auth.EmailVerificationStore
  | Auth.ChallengeStore
  | Auth.CredentialStore
  | Auth.OAuthStateStore
  | Auth.OAuthAccountStore
  | Auth.OAuthUserStore
  | Auth.PasswordResetStore
  | Auth.MagicLinkStore
  | Auth.MagicLinkUserStore
  | Auth.EmailOtpStore
  | Auth.EmailOtpUserStore
  | Auth.TwoFactorStore
  | Auth.PendingTwoFactorStore
  | Auth.IdentifierStore,
  never,
  SqlClient.SqlClient
> = Layer.mergeAll(
  SessionStoreLayer,
  UserStoreLayer,
  UserServiceStoreLayer,
  EmailPasswordStoreLayer,
  PasswordResetUserStoreLayer,
  RoleStoreLayer,
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
  TwoFactorStoreLayer,
  PendingTwoFactorStoreLayer,
  IdentifierStoreLayer,
);
