/**
 * `effect/sql` implementations of the store contracts, for SQLite (D1 included)
 * and PostgreSQL: a `make*Store` and `*StoreLayer` per store, and {@link layer}
 * for all of them over a `SqlClient`. MySQL is not supported; use
 * `@thomasfosterau/effect-auth-drizzle` there.
 */

import * as Clock from "effect/Clock";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { SqlClient, SqlError, Statement } from "effect/sql";
import * as Auth from "../index.ts";
import { decodeBigintColumns } from "./Int8.ts";
import { definedKeys } from "../DefinedKeys.ts";

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

const toBase64 = Schema.encodeSync(Schema.Uint8ArrayFromBase64);
/** Decodes a column this module wrote with {@link toBase64}; throws on a corrupt value. */
const fromBase64 = Schema.decodeSync(Schema.Uint8ArrayFromBase64);

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
const decodeMillis = Schema.decodeUnknownEffect(Schema.DateFromMillis);

/**
 * A stored epoch-millis column back to a `Date`, decoded with
 * `Schema.DateFromMillis`: a value outside the `Date` range fails as an
 * `AuthError` instead of becoming an Invalid Date.
 */
const msToDate = (ms: number, label: string): Effect.Effect<Date, Auth.AuthError> =>
  decodeMillis(ms).pipe(
    Effect.mapError(
      (cause) => new Auth.AuthError({ message: `${label}: stored instant did not decode`, cause }),
    ),
  );

/** A stored enumeration column back to its literal; anything else fails as an `AuthError`. */
const decodeColumn =
  <A>(schema: Schema.Decoder<A>) =>
  (value: string, label: string): Effect.Effect<A, Auth.AuthError> =>
    Schema.decodeEffect(schema)(value).pipe(
      Effect.mapError(
        (cause) => new Auth.AuthError({ message: `${label}: stored value did not decode`, cause }),
      ),
    );

const decodeIdentifierType = decodeColumn(Auth.Identifier.fields.type);
const decodeEmailOtpPurpose = decodeColumn<Auth.Email.EmailOtpPurpose>(
  Schema.Literals(["sign-in", "email-verification", "forget-password"]),
);

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

/**
 * Every row a store reads, with its `BIGINT` columns read as numbers whatever
 * the driver returns for an `int8` (a `bigint` from `@effect/sql-pg`, a string
 * from node-postgres). A value that is not a safe integer fails as an
 * `AuthError`.
 */
const allRows = <A extends object>(
  label: string,
  statement: Effect.Effect<ReadonlyArray<A>, SqlError.SqlError>,
): Effect.Effect<ReadonlyArray<A>, Auth.AuthError> =>
  statement.pipe(
    Effect.mapError(toAuthError(label)),
    Effect.flatMap((rows) =>
      Effect.forEach(rows, (row) => decodeBigintColumns(row, label), { concurrency: 1 }),
    ),
  );

const firstRow = <A extends object>(
  label: string,
  statement: Effect.Effect<ReadonlyArray<A>, SqlError.SqlError>,
) => allRows(label, statement).pipe(Effect.map(Arr.head));

/** Decode a row read with {@link firstRow}, keeping a miss a miss. */
const decodeRow =
  <A, B, E>(decode: (row: A) => Effect.Effect<B, E>) =>
  (row: Option.Option<A>): Effect.Effect<Option.Option<B>, E> =>
    Effect.transposeOption(Option.map(row, decode));

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

const rowToUser = (
  row: Omit<UserRow, "password_hash">,
  label: string,
): Effect.Effect<Auth.User, Auth.AuthError> =>
  Effect.all(
    {
      attributes: decodeAttributes(row.attributes, label),
      createdAt: msToDate(row.created_at, label),
      updatedAt: msToDate(row.updated_at, label),
    },
    { concurrency: 1 },
  ).pipe(
    Effect.map(({ attributes, createdAt, updatedAt }) => ({
      id: row.id,
      createdAt,
      updatedAt,
      attributes,
      ...definedKeys({ name: row.name ?? undefined, image: row.image ?? undefined }),
    })),
  );

/** User-facing helpers shared by every store that reads/creates users. */
const userQueries = (sql: SqlClient.SqlClient) => {
  const getById = (userId: string, label: string) =>
    firstRow(label, sql<UserRow>`SELECT * FROM auth_users WHERE id = ${userId}`);

  const findById = (userId: string, label: string) =>
    getById(userId, label).pipe(Effect.flatMap(decodeRow((r) => rowToUser(r, label))));

  const requireById = (userId: string, label: string) =>
    getById(userId, label).pipe(
      Effect.flatMap(
        Option.match({
          onNone: (): Effect.Effect<Auth.User, Auth.AuthError | Auth.UserNotFoundError> =>
            Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
          onSome: (row) => rowToUser(row, label),
        }),
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
        ...definedKeys({ name: input.name, image: input.image }),
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
    getById(userId, label).pipe(Effect.map(Option.exists((row) => row.password_hash != null)));

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
  Effect.all(
    {
      attributes: decodeAttributes(row.attributes, label),
      expiresAt: msToDate(row.expires_at, label),
      createdAt: msToDate(row.created_at, label),
      lastActivityAt: msToDate(row.last_activity_at, label),
    },
    { concurrency: 1 },
  ).pipe(
    Effect.map(({ attributes, expiresAt, createdAt, lastActivityAt }) => ({
      id: row.id,
      userId: row.user_id,
      expiresAt,
      createdAt,
      lastActivityAt,
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
      ).pipe(Effect.flatMap(decodeRow((r) => rowToSession(r, "session.get")))),
    update: (session) =>
      asVoid(
        "session.update",
        sql`UPDATE auth_sessions SET expires_at = ${dateToMs(session.expiresAt)}, last_activity_at = ${dateToMs(session.lastActivityAt)}, attributes = ${encodeAttributes(session.attributes)} WHERE id = ${session.id}`,
      ).pipe(Effect.as(session)),
    touch: (sessionId, touch) =>
      firstRow(
        "session.touch",
        sql<SessionRow>`UPDATE auth_sessions SET expires_at = ${dateToMs(touch.expiresAt)}, last_activity_at = ${dateToMs(touch.lastActivityAt)}
            WHERE id = ${sessionId} AND expires_at >= ${dateToMs(touch.lastActivityAt)}
            RETURNING *`,
      ).pipe(Effect.flatMap(decodeRow((r) => rowToSession(r, "session.touch")))),
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

/**
 * `Auth.UserServiceStore` over the `auth_users` table; requires `SqlClient`.
 * `delete` removes the user's `auth_user_roles` rows with the user row, in
 * one transaction: the roles are this subpath's own data about the user, and
 * no core store owns them.
 */
export const makeUserServiceStore: Effect.Effect<
  typeof Auth.UserServiceStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);
  const tx = makeTx(sql);
  return {
    get: (userId) => users.findById(userId, "userService.get"),
    update: (user) =>
      asVoid(
        "userService.update",
        sql`UPDATE auth_users SET name = ${user.name ?? null}, image = ${user.image ?? null}, attributes = ${encodeAttributes(user.attributes)}, updated_at = ${dateToMs(user.updatedAt)} WHERE id = ${user.id}`,
      ).pipe(Effect.as(user)),
    delete: (userId) =>
      tx(
        "userService.delete",
        Effect.andThen(
          asVoid("userService.delete", sql`DELETE FROM auth_user_roles WHERE user_id = ${userId}`),
          asVoid("userService.delete", sql`DELETE FROM auth_users WHERE id = ${userId}`),
        ),
      ),
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
        .pipe(Effect.map(Option.flatMap((row) => Option.fromNullishOr(row.password_hash)))),
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
      const rolePermissions = R.map(
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
      Effect.map(Option.map(rowToRateLimit)),
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
        // unqualified, PostgreSQL reports them as ambiguous.
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
      ).pipe(Effect.map(Option.map(rowToEmailVerification))),
    // One `DELETE ... RETURNING`: of concurrent consumers of one
    // token, only the one whose delete removed the row gets it back.
    consume: (token) =>
      firstRow(
        "emailVerification.consume",
        sql<EmailVerificationRow>`DELETE FROM auth_email_verifications WHERE token = ${token} RETURNING *`,
      ).pipe(Effect.map(Option.map(rowToEmailVerification))),
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
    getLatestByUserId: (userId) =>
      firstRow(
        "emailVerification.getLatestByUserId",
        sql<EmailVerificationRow>`SELECT * FROM auth_email_verifications WHERE user_id = ${userId}
            ORDER BY created_at DESC LIMIT 1`,
      ).pipe(Effect.map(Option.map(rowToEmailVerification))),
  } satisfies typeof Auth.Email.EmailVerificationStore.Service;
});

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore + CredentialStore
// ---------------------------------------------------------------------------

interface ChallengeRow {
  readonly challenge: string;
  readonly ceremony: string;
  readonly expires_at: number;
  readonly user_id: string | null;
}

/** A row whose ceremony is not one the core knows reads as missing. */
const rowToChallenge = (
  row: ChallengeRow,
): Effect.Effect<Option.Option<Auth.MultiFactor.WebAuthnChallenge>, Auth.AuthError> => {
  const { ceremony } = row;
  if (!Auth.MultiFactor.isWebAuthnCeremony(ceremony)) return Effect.succeedNone;
  return Effect.try({
    try: () => {
      const challenge = fromBase64(row.challenge);
      return Option.some(
        row.user_id == null
          ? { challenge, ceremony, expiresAt: row.expires_at }
          : { challenge, ceremony, expiresAt: row.expires_at, userId: row.user_id },
      );
    },
    catch: (cause) => new Auth.AuthError({ message: "challenge decode failed", cause }),
  });
};

/**
 * `Auth.MultiFactor.ChallengeStore` over `auth_webauthn_challenges` and the
 * ceremony each challenge was issued for, in
 * `auth_webauthn_challenge_ceremonies`; requires `SqlClient`. A
 * challenge with no ceremony row reads as missing.
 */
export const makeChallengeStore: Effect.Effect<
  typeof Auth.MultiFactor.ChallengeStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);
  // The ceremony row goes first: a delete interrupted between the statements
  // leaves a challenge row that no ceremony can redeem.
  const remove = (label: string, encoded: string) =>
    Effect.gen(function* () {
      yield* asVoid(
        label,
        sql`DELETE FROM auth_webauthn_challenge_ceremonies WHERE challenge = ${encoded}`,
      );
      yield* asVoid(label, sql`DELETE FROM auth_webauthn_challenges WHERE challenge = ${encoded}`);
    });
  return {
    create: (challenge) =>
      withTx(
        "challenge.create",
        Effect.gen(function* () {
          const encoded = toBase64(challenge.challenge);
          yield* remove("challenge.create", encoded);
          yield* asVoid(
            "challenge.create",
            sql`INSERT INTO auth_webauthn_challenges (challenge, expires_at, user_id)
                  VALUES (${encoded}, ${challenge.expiresAt}, ${challenge.userId ?? null})`,
          );
          yield* asVoid(
            "challenge.create",
            sql`INSERT INTO auth_webauthn_challenge_ceremonies (challenge, ceremony)
                  VALUES (${encoded}, ${challenge.ceremony})`,
          );
          return challenge;
        }),
      ),
    get: (challenge) =>
      firstRow(
        "challenge.get",
        sql<ChallengeRow>`SELECT c.challenge, k.ceremony, c.expires_at, c.user_id
          FROM auth_webauthn_challenges c
          JOIN auth_webauthn_challenge_ceremonies k ON k.challenge = c.challenge
          WHERE c.challenge = ${toBase64(challenge)}`,
      ).pipe(
        Effect.flatMap(Option.match({ onNone: () => Effect.succeedNone, onSome: rowToChallenge })),
      ),
    delete: (challenge) =>
      withTx("challenge.delete", remove("challenge.delete", toBase64(challenge))),
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
  readonly backup_eligible: number | null;
  readonly backup_state: number | null;
  readonly aaguid: string | null;
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
      ...definedKeys({
        name: row.name ?? undefined,
        transports: row.transports != null ? decodeStringList(row.transports) : undefined,
        backupEligible: row.backup_eligible != null ? row.backup_eligible !== 0 : undefined,
        backupState: row.backup_state != null ? row.backup_state !== 0 : undefined,
        aaguid: row.aaguid ?? undefined,
      }),
    }),
    catch: (cause) => new Auth.AuthError({ message: "credential decode failed", cause }),
  });

const optionalFlag = (flag: boolean | undefined): number | null =>
  flag === undefined ? null : flag ? 1 : 0;

/**
 * `Auth.MultiFactor.CredentialStore` over the `auth_webauthn_credentials`
 * table and each credential's backup flags and AAGUID, in
 * `auth_webauthn_credential_flags`; requires `SqlClient`.
 */
export const makeCredentialStore: Effect.Effect<
  typeof Auth.MultiFactor.CredentialStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const withTx = makeTx(sql);
  const getById = (credentialId: string, label: string) =>
    firstRow(
      label,
      sql<CredentialRow>`SELECT c.*, f.backup_eligible, f.backup_state, f.aaguid
        FROM auth_webauthn_credentials c
        LEFT JOIN auth_webauthn_credential_flags f ON f.credential_id = c.id
        WHERE c.id = ${credentialId}`,
    ).pipe(Effect.flatMap(decodeRow(rowToCredential)));
  // An upsert: a flags row left by a delete interrupted between its
  // statements is overwritten, never a conflict.
  const writeFlags = (label: string, credential: Auth.MultiFactor.WebAuthnCredential) =>
    asVoid(
      label,
      sql`INSERT INTO auth_webauthn_credential_flags (credential_id, backup_eligible, backup_state, aaguid)
            VALUES (${credential.id}, ${optionalFlag(credential.backupEligible)}, ${optionalFlag(credential.backupState)}, ${credential.aaguid ?? null})
            ON CONFLICT (credential_id) DO UPDATE SET
              backup_eligible = excluded.backup_eligible,
              backup_state = excluded.backup_state,
              aaguid = excluded.aaguid`,
    );

  return {
    // The credential row goes first: a create interrupted between the
    // statements leaves a credential with its flags absent, which its next
    // sign-in records.
    create: (credential) =>
      withTx(
        "credential.create",
        Effect.gen(function* () {
          yield* asVoid(
            "credential.create",
            sql`INSERT INTO auth_webauthn_credentials (id, user_id, public_key, algorithm, counter, created_at, name, transports)
                  VALUES (${credential.id}, ${credential.userId}, ${toBase64(credential.publicKey)}, ${credential.algorithm}, ${credential.counter}, ${credential.createdAt}, ${credential.name ?? null}, ${credential.transports ? encodeStringList(credential.transports) : null})`,
          );
          yield* writeFlags("credential.create", credential);
          return credential;
        }),
      ),
    get: (credentialId) => getById(credentialId, "credential.get"),
    // The credential `id` IS the base64url-encoded WebAuthn credential ID, so
    // the discoverable-login lookup is the same query.
    getByCredentialId: (credentialId) => getById(credentialId, "credential.getByCredentialId"),
    // The flags row is written only for a credential that exists, so an
    // update of a deleted credential recreates nothing.
    update: (credential) =>
      withTx(
        "credential.update",
        Effect.gen(function* () {
          const updated = yield* allRows(
            "credential.update",
            sql<{ readonly id: string }>`UPDATE auth_webauthn_credentials
                  SET user_id = ${credential.userId}, public_key = ${toBase64(credential.publicKey)}, algorithm = ${credential.algorithm}, counter = ${credential.counter}, created_at = ${credential.createdAt}, name = ${credential.name ?? null}, transports = ${credential.transports ? encodeStringList(credential.transports) : null}
                  WHERE id = ${credential.id}
                  RETURNING id`,
          );
          if (Arr.isReadonlyArrayNonEmpty(updated)) {
            yield* writeFlags("credential.update", credential);
          }
          return credential;
        }),
      ),
    // The credential row goes first: a delete interrupted between the
    // statements leaves only an orphaned flags row, which a later create of
    // the same id overwrites.
    delete: (credentialId) =>
      withTx(
        "credential.delete",
        Effect.gen(function* () {
          yield* asVoid(
            "credential.delete",
            sql`DELETE FROM auth_webauthn_credentials WHERE id = ${credentialId}`,
          );
          yield* asVoid(
            "credential.delete",
            sql`DELETE FROM auth_webauthn_credential_flags WHERE credential_id = ${credentialId}`,
          );
        }),
      ),
    listByUserId: (userId) =>
      allRows(
        "credential.listByUserId",
        sql<CredentialRow>`SELECT c.*, f.backup_eligible, f.backup_state, f.aaguid
          FROM auth_webauthn_credentials c
          LEFT JOIN auth_webauthn_credential_flags f ON f.credential_id = c.id
          WHERE c.user_id = ${userId}`,
      ).pipe(
        Effect.flatMap((rows) =>
          Effect.forEach(rows, (row) => rowToCredential(row), { concurrency: 1 }),
        ),
      ),
    // The flags rows go first here, since they are found through the
    // credential rows; an interrupted delete leaves credentials whose next
    // sign-in records their flags again.
    deleteByUserId: (userId) =>
      withTx(
        "credential.deleteByUserId",
        Effect.gen(function* () {
          yield* asVoid(
            "credential.deleteByUserId",
            sql`DELETE FROM auth_webauthn_credential_flags
                  WHERE credential_id IN (SELECT id FROM auth_webauthn_credentials WHERE user_id = ${userId})`,
          );
          yield* asVoid(
            "credential.deleteByUserId",
            sql`DELETE FROM auth_webauthn_credentials WHERE user_id = ${userId}`,
          );
        }),
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
  ...definedKeys({
    codeVerifier: row.code_verifier ?? undefined,
    nonce: row.nonce ?? undefined,
    returnTo: row.return_to ?? undefined,
  }),
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
    // One `DELETE ... RETURNING` statement: of two concurrent callers
    // passing the same state, only the one whose delete removed the row gets
    // it back, on SQLite, D1 and PostgreSQL alike.
    consume: (state) =>
      firstRow(
        "oauthState.consume",
        sql<OAuthStateRow>`DELETE FROM auth_oauth_states WHERE state = ${state} RETURNING *`,
      ).pipe(Effect.map(Option.map(rowToOAuthState))),
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
  ...definedKeys({
    email: row.email ?? undefined,
    name: row.name ?? undefined,
    picture: row.picture ?? undefined,
    refreshToken: row.refresh_token ?? undefined,
    expiresAt: row.expires_at ?? undefined,
  }),
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

  return {
    // A plain insert: the (provider, provider_id) unique index refuses a
    // second link, and the service reports it as a conflict.
    create: (account) =>
      asVoid(
        "oauthAccount.create",
        sql`INSERT INTO auth_oauth_accounts (id, user_id, provider, provider_id, email, name, picture, access_token, refresh_token, expires_at, created_at, updated_at)
            VALUES (${account.id}, ${account.userId}, ${account.provider}, ${account.providerId}, ${account.email ?? null}, ${account.name ?? null}, ${account.picture ?? null}, ${account.accessToken}, ${account.refreshToken ?? null}, ${account.expiresAt ?? null}, ${account.createdAt}, ${account.updatedAt})`,
      ).pipe(Effect.as(account)),
    get: (provider, providerId) =>
      read(provider, providerId, "oauthAccount.get").pipe(
        Effect.map(Option.map(rowToOAuthAccount)),
      ),
    getByUserId: (userId) =>
      allRows(
        "oauthAccount.getByUserId",
        sql<OAuthAccountRow>`SELECT * FROM auth_oauth_accounts WHERE user_id = ${userId}`,
      ).pipe(Effect.map((rows) => rows.map(rowToOAuthAccount))),
    update: (account) =>
      firstRow(
        "oauthAccount.update",
        sql<OAuthAccountRow>`UPDATE auth_oauth_accounts SET
            email = ${account.email ?? null},
            name = ${account.name ?? null},
            picture = ${account.picture ?? null},
            access_token = ${account.accessToken},
            refresh_token = ${account.refreshToken ?? null},
            expires_at = ${account.expiresAt ?? null},
            updated_at = ${account.updatedAt}
          WHERE id = ${account.id}
          RETURNING *`,
      ).pipe(Effect.map(Option.map(rowToOAuthAccount))),
    // Only an unlinked link (empty user_id) or one `userId` already holds
    // moves; a link another user holds is refused, never reassigned.
    linkToUser: (userId, account) =>
      firstRow(
        "oauthAccount.linkToUser",
        sql<{
          readonly id: string;
        }>`UPDATE auth_oauth_accounts SET user_id = ${userId}, updated_at = ${account.updatedAt}
            WHERE provider = ${account.provider} AND provider_id = ${account.providerId}
              AND (user_id = '' OR user_id = ${userId})
            RETURNING id`,
      ).pipe(
        Effect.flatMap((moved) =>
          Option.isSome(moved)
            ? Effect.void
            : read(account.provider, account.providerId, "oauthAccount.linkToUser").pipe(
                Effect.flatMap((held) =>
                  Option.isSome(held)
                    ? Effect.fail(
                        new Auth.AuthError({
                          message: "oauthAccount.linkToUser: the link belongs to another user",
                        }),
                      )
                    : Effect.void,
                ),
              ),
        ),
      ),
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
    deleteByUserId: (userId) =>
      asVoid(
        "oauthAccount.deleteByUserId",
        sql`DELETE FROM auth_oauth_accounts WHERE user_id = ${userId}`,
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
      ).pipe(Effect.map(Option.map(rowToPasswordReset))),
    // One `DELETE ... RETURNING`.
    consume: (token) =>
      firstRow(
        "passwordReset.consume",
        sql<PasswordResetRow>`DELETE FROM auth_password_resets WHERE token = ${token} RETURNING *`,
      ).pipe(Effect.map(Option.map(rowToPasswordReset))),
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
      ).pipe(Effect.map(Option.map(rowToMagicLink))),
    getByEmail: (email) =>
      firstRow(
        "magicLink.getByEmail",
        sql<MagicLinkRow>`SELECT * FROM auth_magic_links WHERE email = ${email}`,
      ).pipe(Effect.map(Option.map(rowToMagicLink))),
    // One `DELETE ... RETURNING`.
    consume: (token) =>
      firstRow(
        "magicLink.consume",
        sql<MagicLinkRow>`DELETE FROM auth_magic_links WHERE token = ${token} RETURNING *`,
      ).pipe(Effect.map(Option.map(rowToMagicLink))),
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

const rowToEmailOtp = (
  row: EmailOtpRow,
  label: string,
): Effect.Effect<Auth.Email.EmailOtpRecord, Auth.AuthError> =>
  Effect.map(decodeEmailOtpPurpose(row.purpose, label), (purpose) => ({
    email: row.email,
    purpose,
    otpHash: row.otp_hash,
    attempts: row.attempts,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  }));

interface EmailOtpFailuresRow {
  readonly failures: number;
  readonly last_failure_at: number;
}

const rowToOtpFailures = (row: EmailOtpFailuresRow): Auth.OtpFailures => ({
  count: row.failures,
  lastFailureAt: row.last_failure_at,
});

/**
 * `Auth.Email.EmailOtpStore` over the `auth_email_otps` table, with each
 * pair's failure budget in `auth_email_otp_failures`; requires
 * `SqlClient`.
 */
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
        Effect.flatMap((row) =>
          Option.match(row, {
            onNone: () => Effect.succeedNone,
            onSome: (found) => Effect.map(rowToEmailOtp(found, "emailOtp.get"), Option.some),
          }),
        ),
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
        // No row: another request consumed or exhausted the code.
        return Option.map(Arr.head(rows), (row) => row.attempts);
      }),
    getFailures: (email, purpose) =>
      firstRow(
        "emailOtp.getFailures",
        sql<EmailOtpFailuresRow>`SELECT failures, last_failure_at FROM auth_email_otp_failures
          WHERE email = ${email} AND purpose = ${purpose}`,
      ).pipe(Effect.map(Option.map(rowToOtpFailures))),
    recordFailure: (email, purpose, at) =>
      Effect.gen(function* () {
        // One upsert + RETURNING: concurrent wrong codes are all counted.
        const row = yield* firstRow(
          "emailOtp.recordFailure",
          sql<EmailOtpFailuresRow>`
            INSERT INTO auth_email_otp_failures (email, purpose, failures, last_failure_at)
              VALUES (${email}, ${purpose}, 1, ${at})
            ON CONFLICT (email, purpose) DO UPDATE
              SET failures = auth_email_otp_failures.failures + 1,
                  last_failure_at = excluded.last_failure_at
            RETURNING failures, last_failure_at`,
        );
        if (Option.isNone(row)) {
          return yield* new Auth.AuthError({ message: "OTP failure count not returned" });
        }
        return rowToOtpFailures(row.value);
      }),
    clearFailures: (email, purpose) =>
      asVoid(
        "emailOtp.clearFailures",
        sql`DELETE FROM auth_email_otp_failures WHERE email = ${email} AND purpose = ${purpose}`,
      ),
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
 * How many expired rows one {@link purgeExpired} run deleted, per table. The
 * companion tables (WebAuthn ceremonies, second-factor attempt counts,
 * lockout attempt times) lose their orphaned rows in the same run, uncounted.
 */
export interface PurgeExpiredResult {
  /** Rows deleted from `auth_sessions`: past their `expires_at`. */
  readonly sessions: number;
  /** Rows deleted from `auth_oauth_states`. */
  readonly oauthStates: number;
  /** Rows deleted from `auth_webauthn_challenges`. */
  readonly webauthnChallenges: number;
  /** Rows deleted from `auth_pending_multi_factor`. */
  readonly pendingMultiFactor: number;
  /** Rows deleted from `auth_email_verifications`. */
  readonly emailVerifications: number;
  /** Rows deleted from `auth_password_resets`. */
  readonly passwordResets: number;
  /** Rows deleted from `auth_magic_links`. */
  readonly magicLinks: number;
  /** Rows deleted from `auth_email_otps`. */
  readonly emailOtps: number;
  /** Rows deleted from `auth_email_otp_failures`: no wrong code for `otpFailureRetention`. */
  readonly emailOtpFailures: number;
  /** Rows deleted from `auth_rate_limits`: their window and block have both passed. */
  readonly rateLimits: number;
  /** Rows deleted from `auth_account_lockouts`: a lock that has ended, or an idle counter. */
  readonly accountLockouts: number;
}

/**
 * Delete every expired row from the `./sql` stores; requires `SqlClient`.
 *
 * No store deletes these rows on its own, and most are written for
 * unauthenticated requests: an OAuth state per authorize redirect, a WebAuthn
 * challenge per begin, a rate-limit row per key counted, a lockout row per
 * identifier tried, a code or link per send (the sends that hide whether an
 * account exists write one for any address). Schedule this from the host (a
 * cron trigger on Workers, a timer on a long-lived server) so the tables stay
 * bounded. Each table is one `DELETE`, run in turn, with expiry read from the
 * `Clock`.
 *
 * A purge changes no outcome; it only reclaims the space:
 *
 * - A session, OAuth state, WebAuthn challenge, pending second factor, email
 *   verification, password reset, magic link or email OTP goes once its
 *   `expires_at` is before now; the services already refuse it, and a row
 *   whose `expires_at` equals now is still accepted, so it stays. Expired
 *   sessions are purged too: `validateSession` refuses and deletes one anyway.
 * - A rate-limit row goes once its `reset_at` is not after now and its
 *   `blocked_until` is unset or not after now: the limiter then treats the key
 *   as one it has never seen.
 * - An account-lockout row goes once its lock has ended (the next attempt would
 *   start again from 1), or, never locked, once its key has had no attempt for
 *   `accountLockoutRetention`. A row from before attempt times were recorded
 *   gets one at its first purge and is judged from then.
 * - An email-OTP failure budget goes once its latest wrong code is
 *   `otpFailureRetention` old: past the backoff cap the delay has fully
 *   decayed, so a fresh start buys nothing a patient caller lacked.
 *
 * {@link purgeExpiredWith} is the same purge with a cap on the rows each table
 * loses per run, and the two retentions.
 */
export const purgeExpired: Effect.Effect<PurgeExpiredResult, Auth.AuthError, SqlClient.SqlClient> =
  Effect.suspend(() => purgeExpiredWith());

/** Options for {@link purgeExpiredWith}. */
export interface PurgeExpiredOptions {
  /**
   * The most rows the run deletes from each table. A positive integer;
   * omitted, every expired row goes, as {@link purgeExpired} does.
   */
  readonly limit?: number;
  /**
   * How long an email-OTP failure budget outlives its latest wrong code.
   * Default 25 hours: the default backoff cap (`backoff.maxDelay`, a day) and
   * an hour's margin. Keep it at least your `maxDelay`.
   */
  readonly otpFailureRetention?: Duration.Input;
  /**
   * How long an unlocked account-lockout counter outlives its key's latest
   * attempt. Default a day. Keep it at least the plugin's `lockoutDurationMs`.
   */
  readonly accountLockoutRetention?: Duration.Input;
}

/** {@link PurgeExpiredOptions.otpFailureRetention}'s default. */
export const DEFAULT_OTP_FAILURE_RETENTION: Duration.Duration = Duration.hours(25);
/** {@link PurgeExpiredOptions.accountLockoutRetention}'s default. */
export const DEFAULT_ACCOUNT_LOCKOUT_RETENTION: Duration.Duration = Duration.days(1);

const retentionMillis = (
  name: string,
  fallback: Duration.Duration,
  input?: Duration.Input,
): Effect.Effect<number, Auth.AuthError> => {
  const millis = Duration.toMillis(input ?? fallback);
  return Number.isFinite(millis) && millis >= 0
    ? Effect.succeed(millis)
    : Effect.fail(
        new Auth.AuthError({
          message: `purgeExpired ${name} must be a finite, non-negative duration`,
        }),
      );
};

/**
 * {@link purgeExpired} with options; requires `SqlClient`.
 *
 * With `limit`, each table's `DELETE` takes at most `limit` of its expired
 * rows (`DELETE … WHERE <expired> AND key IN (SELECT key … WHERE <expired> LIMIT n)`, which
 * SQLite, D1 and PostgreSQL all run), so one run's work is bounded: a Workers
 * cron tick with a CPU budget calls it once per tick, or loops until every
 * count in the result is `0`. Which expired rows a capped run takes is
 * unspecified. Omitting every option is {@link purgeExpired} exactly. A `limit`
 * that is not a positive integer, or a retention that is negative or
 * infinite, fails with `AuthError` before any statement runs.
 *
 * @example
 * ```ts
 * import * as Sql from "@thomasfosterau/effect-auth/sql"
 *
 * // One bounded tick: at most 500 rows from each table.
 * const tick = Sql.purgeExpiredWith({ limit: 500 })
 * ```
 */
export const purgeExpiredWith = (
  options?: PurgeExpiredOptions,
): Effect.Effect<PurgeExpiredResult, Auth.AuthError, SqlClient.SqlClient> => {
  const limit = options?.limit;
  if (limit !== undefined && !(Number.isSafeInteger(limit) && limit > 0)) {
    return Effect.fail(
      new Auth.AuthError({
        message: `purgeExpired limit must be a positive integer, got ${String(limit)}`,
      }),
    );
  }
  return Effect.gen(function* () {
    const otpFailureRetention = yield* retentionMillis(
      "otpFailureRetention",
      DEFAULT_OTP_FAILURE_RETENTION,
      options?.otpFailureRetention,
    );
    const accountLockoutRetention = yield* retentionMillis(
      "accountLockoutRetention",
      DEFAULT_ACCOUNT_LOCKOUT_RETENTION,
      options?.accountLockoutRetention,
    );
    const sql = yield* SqlClient.SqlClient;
    const now = yield* Clock.currentTimeMillis;
    return yield* purgeTables(sql, {
      now,
      limit: Option.fromUndefinedOr(limit),
      otpFailuresBefore: now - otpFailureRetention,
      lockoutAttemptsBefore: now - accountLockoutRetention,
    });
  });
};

/**
 * One table's purge: every row matching `expired`, or with `limit` at most
 * that many of them, chosen by `key` (a column list, so a composite key
 * compares as a row value). Returns how many rows went.
 *
 * The capped form repeats `expired` in the outer `WHERE`: under PostgreSQL's
 * READ COMMITTED a row the subquery picked can be refreshed concurrently (a
 * rate-limit window reopened, an OTP re-issued for the same address), and the
 * `DELETE` rechecks only its own `WHERE` after waiting on the row lock. Without
 * the predicate it would delete the fresh row. An `expired` that names the
 * table itself (a correlated `NOT EXISTS`) resolves to the nearest `FROM`, so
 * it reads right in both places.
 */
const purgeTable = (
  sql: SqlClient.SqlClient,
  options: {
    readonly label: string;
    readonly table: string;
    readonly key: string;
    readonly expired: Statement.Fragment;
    readonly limit: Option.Option<number>;
  },
): Effect.Effect<number, Auth.AuthError> => {
  const table = sql.literal(options.table);
  const key = sql.literal(options.key);
  const statement = Option.match(options.limit, {
    onNone: () => sql`DELETE FROM ${table} WHERE ${options.expired} RETURNING ${key}`,
    onSome: (limit) =>
      sql`DELETE FROM ${table} WHERE (${options.expired}) AND (${key}) IN (SELECT ${key} FROM ${table} WHERE ${options.expired} LIMIT ${limit}) RETURNING ${key}`,
  });
  return allRows(options.label, statement).pipe(Effect.map((rows) => rows.length));
};

/** A purge of the rows whose `expires_at` is before `now`. */
const purgeByExpiresAt = (
  sql: SqlClient.SqlClient,
  table: string,
  key: string,
  now: number,
  limit: Option.Option<number>,
) =>
  purgeTable(sql, {
    label: `purgeExpired.${table}`,
    table,
    key,
    expired: sql`expires_at < ${now}`,
    limit,
  });

/** A purge of a companion table's rows whose parent row is gone. */
const purgeOrphans = (
  sql: SqlClient.SqlClient,
  table: string,
  parent: string,
  key: string,
  limit: Option.Option<number>,
) =>
  purgeTable(sql, {
    label: `purgeExpired.${table}`,
    table,
    key,
    expired: sql`NOT EXISTS (SELECT 1 FROM ${sql.literal(parent)} p WHERE p.${sql.literal(key)} = ${sql.literal(table)}.${sql.literal(key)})`,
    limit,
  });

const purgeTables = (
  sql: SqlClient.SqlClient,
  options: {
    readonly now: number;
    readonly limit: Option.Option<number>;
    readonly otpFailuresBefore: number;
    readonly lockoutAttemptsBefore: number;
  },
): Effect.Effect<PurgeExpiredResult, Auth.AuthError> => {
  const { now, limit } = options;
  // A lockout row from before attempt times were recorded starts its idle
  // clock here, so it is judged like any other from the next purge on.
  const seedLockoutAttempts = asVoid(
    "purgeExpired.auth_account_lockout_attempts",
    sql`INSERT INTO auth_account_lockout_attempts (key, last_attempt_at)
          SELECT l.key, ${now} FROM auth_account_lockouts l
          WHERE NOT EXISTS (SELECT 1 FROM auth_account_lockout_attempts a WHERE a.key = l.key)
          ${Option.match(limit, { onNone: () => sql``, onSome: (n) => sql`LIMIT ${n}` })}
          ON CONFLICT(key) DO NOTHING`,
  );
  return Effect.gen(function* () {
    const sessions = yield* purgeByExpiresAt(sql, "auth_sessions", "id", now, limit);
    const oauthStates = yield* purgeByExpiresAt(sql, "auth_oauth_states", "state", now, limit);
    const webauthnChallenges = yield* purgeByExpiresAt(
      sql,
      "auth_webauthn_challenges",
      "challenge",
      now,
      limit,
    );
    yield* purgeOrphans(
      sql,
      "auth_webauthn_challenge_ceremonies",
      "auth_webauthn_challenges",
      "challenge",
      limit,
    );
    const pendingMultiFactor = yield* purgeByExpiresAt(
      sql,
      "auth_pending_multi_factor",
      "token",
      now,
      limit,
    );
    yield* purgeOrphans(
      sql,
      "auth_pending_multi_factor_attempts",
      "auth_pending_multi_factor",
      "token",
      limit,
    );
    const emailVerifications = yield* purgeByExpiresAt(
      sql,
      "auth_email_verifications",
      "token",
      now,
      limit,
    );
    const passwordResets = yield* purgeByExpiresAt(
      sql,
      "auth_password_resets",
      "token",
      now,
      limit,
    );
    const magicLinks = yield* purgeByExpiresAt(sql, "auth_magic_links", "token", now, limit);
    const emailOtps = yield* purgeByExpiresAt(sql, "auth_email_otps", "email, purpose", now, limit);
    const emailOtpFailures = yield* purgeTable(sql, {
      label: "purgeExpired.auth_email_otp_failures",
      table: "auth_email_otp_failures",
      key: "email, purpose",
      expired: sql`last_failure_at < ${options.otpFailuresBefore}`,
      limit,
    });
    const rateLimits = yield* purgeTable(sql, {
      label: "purgeExpired.auth_rate_limits",
      table: "auth_rate_limits",
      key: "key",
      expired: sql`reset_at <= ${now} AND (blocked_until IS NULL OR blocked_until <= ${now})`,
      limit,
    });
    yield* seedLockoutAttempts;
    const accountLockouts = yield* purgeTable(sql, {
      label: "purgeExpired.auth_account_lockouts",
      table: "auth_account_lockouts",
      key: "key",
      expired: sql`(locked_until IS NOT NULL AND locked_until <= ${now})
        OR (locked_until IS NULL AND EXISTS (SELECT 1 FROM auth_account_lockout_attempts a
          WHERE a.key = auth_account_lockouts.key AND a.last_attempt_at < ${options.lockoutAttemptsBefore}))`,
      limit,
    });
    yield* purgeOrphans(
      sql,
      "auth_account_lockout_attempts",
      "auth_account_lockouts",
      "key",
      limit,
    );
    return {
      sessions,
      oauthStates,
      webauthnChallenges,
      pendingMultiFactor,
      emailVerifications,
      passwordResets,
      magicLinks,
      emailOtps,
      emailOtpFailures,
      rateLimits,
      accountLockouts,
    } satisfies PurgeExpiredResult;
  });
};

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
      ...definedKeys({ lastUsedCounter: row.last_used_counter ?? undefined }),
    }),
    catch: (cause) => new Auth.AuthError({ message: "multiFactor decode failed", cause }),
  });

/** How many times `useBackupCode` re-reads after losing its compare-and-set to a concurrent change. */
const backupCodeRetries = 8;

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
      read(userId, "multiFactor.get").pipe(Effect.flatMap(decodeRow(rowToMultiFactor))),
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
    // One compare-and-set: the counter moves only forward, on a
    // verified record that still exists.
    useTotpCounter: (userId, counter) =>
      firstRow(
        "multiFactor.useTotpCounter",
        sql<{ user_id: string }>`UPDATE auth_multi_factor SET last_used_counter = ${counter}
            WHERE user_id = ${userId} AND verified = 1
              AND (last_used_counter IS NULL OR last_used_counter < ${counter})
            RETURNING user_id`,
      ).pipe(Effect.map(Option.isSome)),
    // A compare-and-set on the stored list: the write lands only if
    // the list is still the one read. A concurrent change (another code
    // spent) moves it, and the read is retried while the code is still there.
    useBackupCode: (userId, codeHash) => {
      const attempt = (left: number): Effect.Effect<boolean, Auth.AuthError> =>
        firstRow(
          "multiFactor.useBackupCode",
          sql<{ backup_codes: string }>`SELECT backup_codes FROM auth_multi_factor
              WHERE user_id = ${userId} AND verified = 1`,
        ).pipe(
          Effect.flatMap(
            decodeRow((row) =>
              Effect.try({
                try: () => ({
                  stored: row.backup_codes,
                  codes: decodeStringList(row.backup_codes),
                }),
                catch: (cause) =>
                  new Auth.AuthError({ message: "multiFactor decode failed", cause }),
              }),
            ),
          ),
          Effect.flatMap((current) => {
            if (Option.isNone(current) || !current.value.codes.includes(codeHash)) {
              return Effect.succeed(false);
            }
            const { stored, codes } = current.value;
            const next = encodeStringList(codes.filter((code) => code !== codeHash));
            return firstRow(
              "multiFactor.useBackupCode",
              sql<{ user_id: string }>`UPDATE auth_multi_factor SET backup_codes = ${next}
                  WHERE user_id = ${userId} AND verified = 1 AND backup_codes = ${stored}
                  RETURNING user_id`,
            ).pipe(
              Effect.flatMap((updated) =>
                Option.isSome(updated)
                  ? Effect.succeed(true)
                  : left > 0
                    ? attempt(left - 1)
                    : Effect.fail(
                        new Auth.AuthError({ message: "multiFactor.useBackupCode contended" }),
                      ),
              ),
            );
          }),
        );
      return attempt(backupCodeRetries);
    },
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
  const tx = makeTx(sql);
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
      ).pipe(Effect.map(Option.map(rowToPendingMultiFactor))),
    // One atomic statement: count the attempt only for a challenge that
    // exists, starting at 1 and incrementing in place after that.
    recordFailedAttempt: (token) =>
      firstRow(
        "pendingMultiFactor.recordFailedAttempt",
        sql<{ attempts: number }>`INSERT INTO auth_pending_multi_factor_attempts (token, attempts)
            SELECT token, 1 FROM auth_pending_multi_factor WHERE token = ${token}
            ON CONFLICT(token) DO UPDATE SET attempts = auth_pending_multi_factor_attempts.attempts + 1
            RETURNING attempts`,
      ).pipe(
        Effect.flatMap(
          Option.match({
            onNone: () =>
              Effect.fail(
                new Auth.AuthError({ message: "Pending multi-factor challenge not found" }),
              ),
            onSome: (row) => Effect.succeed(row.attempts),
          }),
        ),
      ),
    // The challenge goes in one `DELETE ... RETURNING`, so of
    // concurrent consumers only one gets it back; its count follows, as in
    // `delete`.
    consume: (token) =>
      tx(
        "pendingMultiFactor.consume",
        Effect.tap(
          firstRow(
            "pendingMultiFactor.consume",
            sql<PendingMultiFactorRow>`DELETE FROM auth_pending_multi_factor WHERE token = ${token} RETURNING *`,
          ).pipe(Effect.map(Option.map(rowToPendingMultiFactor))),
          () =>
            asVoid(
              "pendingMultiFactor.consume",
              sql`DELETE FROM auth_pending_multi_factor_attempts WHERE token = ${token}`,
            ),
        ),
      ),
    // The challenge goes first: interrupted in between (D1 has no
    // transactions), the leftover is an orphaned count, never a live
    // challenge whose count was reset.
    delete: (token) =>
      tx(
        "pendingMultiFactor.delete",
        Effect.andThen(
          asVoid(
            "pendingMultiFactor.delete",
            sql`DELETE FROM auth_pending_multi_factor WHERE token = ${token}`,
          ),
          asVoid(
            "pendingMultiFactor.delete",
            sql`DELETE FROM auth_pending_multi_factor_attempts WHERE token = ${token}`,
          ),
        ),
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

const rowToIdentifier = (
  row: IdentifierRow,
  label: string,
): Effect.Effect<Auth.Identifier, Auth.AuthError> =>
  Effect.all(
    {
      verifiedAt:
        row.verified_at != null
          ? Effect.asSome(msToDate(row.verified_at, label))
          : Effect.succeedNone,
      createdAt: msToDate(row.created_at, label),
      type: decodeIdentifierType(row.type, label),
    },
    { concurrency: 1 },
  ).pipe(
    Effect.map(({ verifiedAt, createdAt, type }) => ({
      id: row.id,
      userId: row.user_id,
      type,
      value: row.value,
      verified: row.verified !== 0,
      ...definedKeys({ verifiedAt: Option.isSome(verifiedAt) ? verifiedAt.value : undefined }),
      createdAt,
    })),
  );

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
      ).pipe(Effect.flatMap(decodeRow((row) => rowToIdentifier(row, "identifier.getByValue")))),

    listByUser: (userId) =>
      allRows(
        "identifier.listByUser",
        sql<IdentifierRow>`SELECT * FROM auth_identifiers WHERE user_id = ${userId} ORDER BY created_at ASC`,
      ).pipe(
        Effect.flatMap((rows) =>
          Effect.forEach(rows, (row) => rowToIdentifier(row, "identifier.listByUser"), {
            concurrency: 1,
          }),
        ),
      ),

    create: (identifier) => insert(identifier, "identifier.create"),

    // Claim, then release, in one transaction. A `to` another user holds fails
    // the INSERT on the `(type, value)` unique index and rolls back, so `from`
    // stays. The release is a compare-and-swap: the DELETE matches `from` by id,
    // user, type and value, so a `from` that is gone (another replace released
    // it first) deletes nothing, the claim is removed again and the call
    // resolves to `None`. On PostgreSQL a concurrent second DELETE waits for the
    // first to commit and then matches nothing (at PostgreSQL's default READ
    // COMMITTED isolation; stricter levels fail with a serialization error,
    // surfaced as `AuthError`), so of two replaces of one `from` one succeeds.
    // D1 has no transactions: the statements autocommit in the same order, so
    // a failure between them leaves both rows, never neither, and the removal
    // of a stale claim is a statement of its own.
    replace: (from, to) => {
      const invalid = Auth.replaceInputError(from, to);
      if (Option.isSome(invalid)) return Effect.fail(invalid.value);
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
          if (Arr.isReadonlyArrayNonEmpty(released)) return Option.some(to);
          // `from` was not held: take the claim back. A DELETE rather than a
          // ROLLBACK, so D1, where a ROLLBACK does nothing, ends unchanged too.
          yield* asVoid(
            "identifier.replace.undo",
            sql`DELETE FROM auth_identifiers WHERE id = ${to.id}`,
          );
          return Option.none();
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
        ).pipe(Effect.flatMap(decodeRow((row) => rowToIdentifier(row, "identifier.setVerified"))));
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
      ).pipe(Effect.map(Option.map(rowToLockout))),
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
        // Only `purgeExpired` reads this, to tell an idle counter from a live one.
        yield* asVoid(
          "accountLockout.registerAttempt",
          sql`INSERT INTO auth_account_lockout_attempts (key, last_attempt_at) VALUES (${key}, ${now})
                ON CONFLICT(key) DO UPDATE SET last_attempt_at = excluded.last_attempt_at`,
        );
        return rowToLockout(row);
      }),
    delete: (key) =>
      Effect.andThen(
        asVoid("accountLockout.delete", sql`DELETE FROM auth_account_lockouts WHERE key = ${key}`),
        asVoid(
          "accountLockout.delete",
          sql`DELETE FROM auth_account_lockout_attempts WHERE key = ${key}`,
        ),
      ),
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
      ...definedKeys({ name: row.name ?? undefined, prefix: row.prefix ?? undefined }),
      start: row.start,
      keyHash: row.key_hash,
      userId: row.user_id,
      enabled: row.enabled !== 0,
      ...definedKeys({
        expiresAt: row.expires_at ?? undefined,
        lastUsedAt: row.last_used_at ?? undefined,
        permissions: row.permissions != null ? decodePermissions(row.permissions) : undefined,
      }),
      metadata: row.metadata != null ? decodeAttributesJson(row.metadata) : {},
      ...definedKeys({
        remaining: row.remaining ?? undefined,
        refillAmount: row.refill_amount ?? undefined,
        refillInterval: row.refill_interval ?? undefined,
        refillMax: row.refill_max ?? undefined,
        lastRefillAt: row.last_refill_at ?? undefined,
      }),
      ...definedKeys({
        rateLimit:
          row.rate_limit_max_requests != null && row.rate_limit_window_ms != null
            ? { maxRequests: row.rate_limit_max_requests, windowMs: row.rate_limit_window_ms }
            : undefined,
      }),
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
      Effect.flatMap(decodeRow(rowToApiKey)),
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
      ).pipe(Effect.flatMap(decodeRow(rowToApiKey))),
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
    // One `UPDATE … RETURNING`: only the usage columns move, so a
    // concurrent owner edit survives, and the `WHERE` is the whole check, so
    // of concurrent uses of a key with one use left exactly one matches.
    recordUse: (id, use) => {
      const refill = use.refill;
      const topped =
        refill === undefined
          ? sql`remaining`
          : refill.max === undefined
            ? sql`remaining + ${refill.amount}`
            : sql`CASE WHEN remaining + ${refill.amount} > ${refill.max} THEN ${refill.max} ELSE remaining + ${refill.amount} END`;
      return firstRow(
        "apiKey.recordUse",
        sql<ApiKeyRow>`UPDATE auth_api_keys SET
              remaining = ${topped} - 1,
              ${refill === undefined ? sql`` : sql`last_refill_at = ${refill.to},`}
              last_used_at = ${use.usedAt},
              updated_at = ${use.usedAt}
            WHERE id = ${id}
              AND enabled = 1
              AND (expires_at IS NULL OR expires_at >= ${use.usedAt})
              AND (remaining IS NULL OR ${topped} > 0)
              ${refill === undefined ? sql`` : sql`AND last_refill_at = ${refill.from}`}
            RETURNING *`,
      ).pipe(Effect.flatMap(decodeRow(rowToApiKey)));
    },
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
    deleteByUserId: (userId) =>
      asVoid("apiKey.deleteByUserId", sql`DELETE FROM auth_api_keys WHERE user_id = ${userId}`),
  } satisfies typeof Auth.ApiKeyStore.Service;
});

// ---------------------------------------------------------------------------
// AdminUserStore (reuses auth_users + auth_identifiers — no dedicated table)
// ---------------------------------------------------------------------------

/** A user row without `password_hash`, which `listUsers` never selects, and its earliest email. */
interface ListedUserRow extends Omit<UserRow, "password_hash"> {
  readonly primary_email: string | null;
}

/** `value` as a `LIKE` pattern matching it as a literal substring (escape `\\`). */
const likeSubstring = (value: string): string => `%${value.replace(/[\\%_]/g, "\\$&")}%`;

/** `Auth.AdminUserStore` over the `auth_users` and `auth_identifiers` tables; requires `SqlClient`. */
export const makeAdminUserStore: Effect.Effect<
  typeof Auth.AdminUserStore.Service,
  never,
  SqlClient.SqlClient
> = SqlClient.SqlClient.useSync((sql) => {
  const users = userQueries(sql);

  // Each user with their earliest email identifier, the column `listUsers`
  // searches and orders by.
  const listed = sql`SELECT u.id, u.name, u.image, u.attributes, u.created_at, u.updated_at, (
      SELECT value FROM auth_identifiers ie
      WHERE ie.user_id = u.id AND ie.type = 'email'
      ORDER BY ie.created_at ASC LIMIT 1
    ) AS primary_email
    FROM auth_users u`;

  return {
    // Search, order and page in SQL: one page of rows is read, never the table.
    listUsers: (query) =>
      Effect.gen(function* () {
        const search = query.searchEmail?.toLowerCase();
        const where =
          search === undefined || search === ""
            ? sql``
            : sql`WHERE LOWER(COALESCE(l.primary_email, '')) LIKE ${likeSubstring(search)} ESCAPE '\\'`;
        const offset = Math.max(0, Math.trunc(query.offset ?? 0));
        // SQLite has no OFFSET without a LIMIT, so "no limit" is the largest one.
        const limit = Math.max(0, Math.trunc(query.limit ?? Number.MAX_SAFE_INTEGER));
        const counted = yield* firstRow(
          "adminUser.listUsers",
          sql<{
            readonly total: number;
          }>`SELECT CAST(COUNT(*) AS INTEGER) AS total FROM (${listed}) l ${where}`,
        );
        const rows = yield* allRows(
          "adminUser.listUsers",
          sql<ListedUserRow>`SELECT * FROM (${listed}) l ${where}
            ORDER BY COALESCE(l.primary_email, ''), l.id
            LIMIT ${limit} OFFSET ${offset}`,
        );
        return {
          users: yield* Effect.forEach(rows, (row) => rowToUser(row, "adminUser.listUsers"), {
            concurrency: 1,
          }),
          total: Option.match(counted, { onNone: () => 0, onSome: (row) => row.total }),
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
 * DeviceAuthorization, ...) are not yet covered here, and core's
 * `KeyValueStore`-backed layers do not cover them either: implement those
 * store interfaces yourself (over this `SqlClient` or any other backing)
 * until they land here.
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
