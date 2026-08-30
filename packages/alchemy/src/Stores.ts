/**
 * Cloudflare D1 implementations of every effect-auth storage interface.
 *
 * Each `make*Store` builds a plain store object backed by a D1 database, and
 * each `*StoreLayer` lifts it into an Effect `Layer` keyed by the matching
 * effect-auth `Context.Service` tag. {@link layer} bundles all of them so a
 * single `Layer.provide` wires up the entire auth stack.
 *
 * Concurrency: single-row upserts (`rateLimit.set`, `oauthAccount`,
 * `multiFactor`) and counters (`rateLimit.increment`,
 * `emailOtp.incrementAttempts`) use a single `ON CONFLICT … DO UPDATE` /
 * `UPDATE … RETURNING` statement for true atomicity — no read-modify-write
 * races. D1 is SQLite-based, so both constructs are supported.
 */

import { Effect, Layer } from "effect";
import { randomUUID } from "node:crypto";
import * as Auth from "@thomasfosterau/effect-auth";
import { d1All, d1First, d1Run, type D1Database } from "./D1.ts";

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

const toBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary);
};

const fromBase64 = (text: string): Uint8Array => {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

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

// ---------------------------------------------------------------------------
// Shared user row (auth_users backs UserStore, UserServiceStore,
// EmailPasswordStore and PasswordResetUserStore)
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

const insertUser = `INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)`;

const insertUserParams = (user: Auth.User): readonly unknown[] => [
  user.id,
  user.name ?? null,
  user.image ?? null,
  null,
  encodeAttributes(user.attributes),
  dateToMs(user.createdAt),
  dateToMs(user.updatedAt),
];

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

export const makeSessionStore = (db: D1Database): typeof Auth.SessionStore.Service => ({
  create: (session) =>
    d1Run(
      db,
      `INSERT INTO auth_sessions (id, user_id, expires_at, created_at, last_activity_at, attributes)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        session.id,
        session.userId,
        dateToMs(session.expiresAt),
        dateToMs(session.createdAt),
        dateToMs(session.lastActivityAt),
        encodeAttributes(session.attributes),
      ],
      "session.create",
    ).pipe(Effect.as(session)),
  get: (sessionId) =>
    d1First<SessionRow>(
      db,
      `SELECT * FROM auth_sessions WHERE id = ?`,
      [sessionId],
      "session.get",
    ).pipe(
      Effect.flatMap((row) => (row ? rowToSession(row, "session.get") : Effect.succeed(null))),
    ),
  update: (session) =>
    d1Run(
      db,
      `UPDATE auth_sessions SET expires_at = ?, last_activity_at = ?, attributes = ? WHERE id = ?`,
      [
        dateToMs(session.expiresAt),
        dateToMs(session.lastActivityAt),
        encodeAttributes(session.attributes),
        session.id,
      ],
      "session.update",
    ).pipe(Effect.as(session)),
  delete: (sessionId) =>
    d1Run(db, `DELETE FROM auth_sessions WHERE id = ?`, [sessionId], "session.delete").pipe(
      Effect.asVoid,
    ),
  deleteByUserId: (userId) =>
    d1Run(
      db,
      `DELETE FROM auth_sessions WHERE user_id = ?`,
      [userId],
      "session.deleteByUserId",
    ).pipe(Effect.asVoid),
  listByUserId: (userId) =>
    d1All<SessionRow>(
      db,
      `SELECT * FROM auth_sessions WHERE user_id = ?`,
      [userId],
      "session.listByUserId",
    ).pipe(
      Effect.flatMap((rows) =>
        Effect.all(rows.map((row) => rowToSession(row, "session.listByUserId"))),
      ),
    ),
});

export const makeUserStore = (db: D1Database): typeof Auth.UserStore.Service => ({
  get: (userId) =>
    d1First<UserRow>(db, `SELECT * FROM auth_users WHERE id = ?`, [userId], "user.get").pipe(
      Effect.flatMap((row) => (row ? rowToUser(row, "user.get") : Effect.succeed(null))),
    ),
  getCredentials: (userId) =>
    d1First<UserRow>(
      db,
      `SELECT password_hash FROM auth_users WHERE id = ?`,
      [userId],
      "user.getCredentials",
    ).pipe(Effect.map((row) => row?.password_hash ?? null)),
});

// ---------------------------------------------------------------------------
// UserServiceStore
// ---------------------------------------------------------------------------

export const makeUserServiceStore = (db: D1Database): typeof Auth.UserServiceStore.Service => ({
  get: (userId) =>
    d1First<UserRow>(db, `SELECT * FROM auth_users WHERE id = ?`, [userId], "userService.get").pipe(
      Effect.flatMap((row) => (row ? rowToUser(row, "userService.get") : Effect.succeed(null))),
    ),
  update: (user) =>
    d1Run(
      db,
      `UPDATE auth_users SET name = ?, image = ?, attributes = ?, updated_at = ? WHERE id = ?`,
      [
        user.name ?? null,
        user.image ?? null,
        encodeAttributes(user.attributes),
        dateToMs(user.updatedAt),
        user.id,
      ],
      "userService.update",
    ).pipe(Effect.as(user)),
  delete: (userId) =>
    d1Run(db, `DELETE FROM auth_users WHERE id = ?`, [userId], "userService.delete").pipe(
      Effect.asVoid,
    ),
});

// ---------------------------------------------------------------------------
// EmailPasswordStore + PasswordResetUserStore (auth_users)
// ---------------------------------------------------------------------------

export const makeEmailPasswordStore = (
  db: D1Database,
): typeof Auth.Email.EmailPasswordStore.Service => ({
  createUser: (input) =>
    Effect.gen(function* () {
      const now = new Date();
      const user: Auth.User = {
        id: randomUUID(),
        createdAt: now,
        updatedAt: now,
        attributes: input.attributes ?? {},
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.image !== undefined ? { image: input.image } : {}),
      };
      yield* d1Run(db, insertUser, insertUserParams(user), "emailPassword.createUser");
      return user;
    }),
  getPasswordHash: (userId) =>
    d1First<UserRow>(
      db,
      `SELECT password_hash FROM auth_users WHERE id = ?`,
      [userId],
      "emailPassword.getPasswordHash",
    ).pipe(Effect.map((row) => row?.password_hash ?? null)),
  setPasswordHash: (userId, hash) =>
    d1Run(
      db,
      `UPDATE auth_users SET password_hash = ? WHERE id = ?`,
      [hash, userId],
      "emailPassword.setPasswordHash",
    ).pipe(Effect.asVoid),
});

export const makePasswordResetUserStore = (
  db: D1Database,
): typeof Auth.Password.PasswordResetUserStore.Service => ({
  setPasswordHash: (userId, hash) =>
    d1Run(
      db,
      `UPDATE auth_users SET password_hash = ? WHERE id = ?`,
      [hash, userId],
      "passwordResetUser.setPasswordHash",
    ).pipe(Effect.asVoid),
});

// ---------------------------------------------------------------------------
// RoleStore
// ---------------------------------------------------------------------------

interface RoleRow {
  readonly role: string;
}

interface PermissionRow {
  readonly resource: string;
  readonly action: string;
}

export const makeRoleStore = (db: D1Database): typeof Auth.RoleStore.Service => ({
  getUserRoles: (userId) =>
    d1All<RoleRow>(
      db,
      `SELECT role FROM auth_user_roles WHERE user_id = ?`,
      [userId],
      "role.getUserRoles",
    ).pipe(
      Effect.map((rows) => rows.map((row) => row.role)),
      Effect.orDie,
    ),
  getRolePermissions: (role) =>
    d1All<PermissionRow>(
      db,
      `SELECT resource, action FROM auth_role_permissions WHERE role = ?`,
      [role],
      "role.getRolePermissions",
    ).pipe(
      Effect.map((rows) => rows.map((row) => ({ resource: row.resource, action: row.action }))),
      Effect.orDie,
    ),
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

const upsertRateLimit = `INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until) VALUES (?, ?, ?, ?)
  ON CONFLICT(key) DO UPDATE SET count = excluded.count, reset_at = excluded.reset_at, blocked_until = excluded.blocked_until`;

export const makeRateLimitStore = (db: D1Database): typeof Auth.RateLimitStore.Service => {
  const readEntry = (key: string) =>
    d1First<RateLimitRow>(
      db,
      `SELECT * FROM auth_rate_limits WHERE key = ?`,
      [key],
      "rateLimit.get",
    ).pipe(Effect.map((row) => (row ? rowToRateLimit(row) : null)));

  return {
    get: (key) => readEntry(key),
    // Atomic single-statement upsert: no read-modify-write race.
    set: (key, entry, _ttl) =>
      d1Run(
        db,
        upsertRateLimit,
        [key, entry.count, entry.resetAt, entry.blockedUntil ?? null],
        "rateLimit.set",
      ).pipe(Effect.asVoid),
    increment: (key, ttlSeconds) =>
      Effect.gen(function* () {
        const now = Date.now();
        const resetAt = now + ttlSeconds * 1000;
        // Single atomic upsert+increment: if the row is new or the window has
        // expired, reset count to 1; otherwise increment by 1. RETURNING
        // avoids a separate SELECT and prevents TOCTOU undercounting.
        const row = yield* d1First<{ count: number }>(
          db,
          `INSERT INTO auth_rate_limits (key, count, reset_at, blocked_until)
             VALUES (?, 1, ?, NULL)
             ON CONFLICT(key) DO UPDATE SET
               count = CASE WHEN ? >= reset_at THEN 1 ELSE count + 1 END,
               reset_at = CASE WHEN ? >= reset_at THEN ? ELSE reset_at END,
               blocked_until = CASE WHEN ? >= reset_at THEN NULL ELSE blocked_until END
             RETURNING count`,
          [key, resetAt, now, now, resetAt, now],
          "rateLimit.increment",
        );
        return row?.count ?? 1;
      }),
    delete: (key) =>
      d1Run(db, `DELETE FROM auth_rate_limits WHERE key = ?`, [key], "rateLimit.delete").pipe(
        Effect.asVoid,
      ),
  };
};

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

export const makeEmailVerificationStore = (
  db: D1Database,
): typeof Auth.Email.EmailVerificationStore.Service => ({
  create: (verification) =>
    d1Run(
      db,
      `INSERT INTO auth_email_verifications (token, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
      [
        verification.token,
        verification.userId,
        verification.email,
        verification.createdAt,
        verification.expiresAt,
      ],
      "emailVerification.create",
    ).pipe(Effect.as(verification)),
  get: (token) =>
    d1First<EmailVerificationRow>(
      db,
      `SELECT * FROM auth_email_verifications WHERE token = ?`,
      [token],
      "emailVerification.get",
    ).pipe(Effect.map((row) => (row ? rowToEmailVerification(row) : null))),
  delete: (token) =>
    d1Run(
      db,
      `DELETE FROM auth_email_verifications WHERE token = ?`,
      [token],
      "emailVerification.delete",
    ).pipe(Effect.asVoid),
  deleteByUserId: (userId) =>
    d1Run(
      db,
      `DELETE FROM auth_email_verifications WHERE user_id = ?`,
      [userId],
      "emailVerification.deleteByUserId",
    ).pipe(Effect.asVoid),
});

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore + CredentialStore
// ---------------------------------------------------------------------------

interface ChallengeRow {
  readonly challenge: string;
  readonly expires_at: number;
  readonly user_id: string | null;
}

const rowToChallenge = (row: ChallengeRow): Auth.SecondFactor.WebAuthnChallenge =>
  row.user_id == null
    ? { challenge: fromBase64(row.challenge), expiresAt: row.expires_at }
    : { challenge: fromBase64(row.challenge), expiresAt: row.expires_at, userId: row.user_id };

export const makeChallengeStore = (
  db: D1Database,
): typeof Auth.SecondFactor.ChallengeStore.Service => ({
  create: (challenge) =>
    d1Run(
      db,
      `INSERT OR REPLACE INTO auth_webauthn_challenges (challenge, expires_at, user_id) VALUES (?, ?, ?)`,
      [toBase64(challenge.challenge), challenge.expiresAt, challenge.userId ?? null],
      "challenge.create",
    ).pipe(Effect.as(challenge)),
  get: (challenge) =>
    d1First<ChallengeRow>(
      db,
      `SELECT * FROM auth_webauthn_challenges WHERE challenge = ?`,
      [toBase64(challenge)],
      "challenge.get",
    ).pipe(Effect.map((row) => (row ? rowToChallenge(row) : null))),
  delete: (challenge) =>
    d1Run(
      db,
      `DELETE FROM auth_webauthn_challenges WHERE challenge = ?`,
      [toBase64(challenge)],
      "challenge.delete",
    ).pipe(Effect.asVoid),
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
): Effect.Effect<Auth.SecondFactor.WebAuthnCredential, Auth.AuthError> =>
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

const credentialParams = (credential: Auth.SecondFactor.WebAuthnCredential): readonly unknown[] => [
  credential.id,
  credential.userId,
  toBase64(credential.publicKey),
  credential.algorithm,
  credential.counter,
  credential.createdAt,
  credential.name ?? null,
  credential.transports ? JSON.stringify(credential.transports) : null,
];

export const makeCredentialStore = (
  db: D1Database,
): typeof Auth.SecondFactor.CredentialStore.Service => {
  const getById = (credentialId: string, label: string) =>
    d1First<CredentialRow>(
      db,
      `SELECT * FROM auth_webauthn_credentials WHERE id = ?`,
      [credentialId],
      label,
    ).pipe(Effect.flatMap((row) => (row ? rowToCredential(row) : Effect.succeed(null))));

  return {
    create: (credential) =>
      d1Run(
        db,
        `INSERT INTO auth_webauthn_credentials (id, user_id, public_key, algorithm, counter, created_at, name, transports)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        credentialParams(credential),
        "credential.create",
      ).pipe(Effect.as(credential)),
    get: (credentialId) => getById(credentialId, "credential.get"),
    // The credential `id` IS the base64url-encoded WebAuthn credential ID, so
    // the discoverable-login lookup is the same query.
    getByCredentialId: (credentialId) => getById(credentialId, "credential.getByCredentialId"),
    update: (credential) =>
      d1Run(
        db,
        `UPDATE auth_webauthn_credentials
         SET user_id = ?, public_key = ?, algorithm = ?, counter = ?, created_at = ?, name = ?, transports = ?
         WHERE id = ?`,
        [
          credential.userId,
          toBase64(credential.publicKey),
          credential.algorithm,
          credential.counter,
          credential.createdAt,
          credential.name ?? null,
          credential.transports ? JSON.stringify(credential.transports) : null,
          credential.id,
        ],
        "credential.update",
      ).pipe(Effect.as(credential)),
    delete: (credentialId) =>
      d1Run(
        db,
        `DELETE FROM auth_webauthn_credentials WHERE id = ?`,
        [credentialId],
        "credential.delete",
      ).pipe(Effect.asVoid),
    listByUserId: (userId) =>
      d1All<CredentialRow>(
        db,
        `SELECT * FROM auth_webauthn_credentials WHERE user_id = ?`,
        [userId],
        "credential.listByUserId",
      ).pipe(Effect.flatMap((rows) => Effect.all(rows.map(rowToCredential)))),
  };
};

// ---------------------------------------------------------------------------
// OAuthStateStore + OAuthAccountStore
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

export const makeOAuthStateStore = (db: D1Database): typeof Auth.OAuth.OAuthStateStore.Service => ({
  create: (state) =>
    d1Run(
      db,
      `INSERT OR REPLACE INTO auth_oauth_states (state, provider, code_verifier, nonce, return_to, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        state.state,
        state.provider,
        state.codeVerifier ?? null,
        state.nonce ?? null,
        state.returnTo ?? null,
        state.createdAt,
        state.expiresAt,
      ],
      "oauthState.create",
    ).pipe(Effect.as(state)),
  get: (state) =>
    d1First<OAuthStateRow>(
      db,
      `SELECT * FROM auth_oauth_states WHERE state = ?`,
      [state],
      "oauthState.get",
    ).pipe(Effect.map((row) => (row ? rowToOAuthState(row) : null))),
  delete: (state) =>
    d1Run(db, `DELETE FROM auth_oauth_states WHERE state = ?`, [state], "oauthState.delete").pipe(
      Effect.asVoid,
    ),
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

const oauthAccountParams = (account: Auth.OAuth.OAuthAccount): readonly unknown[] => [
  account.id,
  account.userId,
  account.provider,
  account.providerId,
  account.email ?? null,
  account.name ?? null,
  account.picture ?? null,
  account.accessToken,
  account.refreshToken ?? null,
  account.expiresAt ?? null,
  account.createdAt,
  account.updatedAt,
];

/**
 * Atomic upsert keyed by the (provider, provider_id) unique index — a single
 * statement, so concurrent upserts can't lose each other's writes.
 */
const upsertOAuthAccount = `INSERT INTO auth_oauth_accounts
  (id, user_id, provider, provider_id, email, name, picture, access_token, refresh_token, expires_at, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(provider, provider_id) DO UPDATE SET
    user_id = excluded.user_id,
    email = excluded.email,
    name = excluded.name,
    picture = excluded.picture,
    access_token = excluded.access_token,
    refresh_token = excluded.refresh_token,
    expires_at = excluded.expires_at,
    updated_at = excluded.updated_at`;

export const makeOAuthAccountStore = (
  db: D1Database,
): typeof Auth.OAuth.OAuthAccountStore.Service => ({
  create: (account) =>
    d1Run(db, upsertOAuthAccount, oauthAccountParams(account), "oauthAccount.create").pipe(
      Effect.as(account),
    ),
  get: (provider, providerId) =>
    d1First<OAuthAccountRow>(
      db,
      `SELECT * FROM auth_oauth_accounts WHERE provider = ? AND provider_id = ?`,
      [provider, providerId],
      "oauthAccount.get",
    ).pipe(Effect.map((row) => (row ? rowToOAuthAccount(row) : null))),
  getByUserId: (userId) =>
    d1All<OAuthAccountRow>(
      db,
      `SELECT * FROM auth_oauth_accounts WHERE user_id = ?`,
      [userId],
      "oauthAccount.getByUserId",
    ).pipe(Effect.map((rows) => rows.map(rowToOAuthAccount))),
  update: (account) =>
    d1Run(db, upsertOAuthAccount, oauthAccountParams(account), "oauthAccount.update").pipe(
      Effect.as(account),
    ),
  linkToUser: (userId, account) =>
    d1Run(
      db,
      upsertOAuthAccount,
      oauthAccountParams({ ...account, userId }),
      "oauthAccount.linkToUser",
    ).pipe(Effect.asVoid),
  unlinkFromUser: (userId, provider) =>
    d1Run(
      db,
      `DELETE FROM auth_oauth_accounts WHERE user_id = ? AND provider = ?`,
      [userId, provider],
      "oauthAccount.unlinkFromUser",
    ).pipe(Effect.asVoid),
  delete: (provider, providerId) =>
    d1Run(
      db,
      `DELETE FROM auth_oauth_accounts WHERE provider = ? AND provider_id = ?`,
      [provider, providerId],
      "oauthAccount.delete",
    ).pipe(Effect.asVoid),
  // Backed by auth_users.password_hash — enables the last-credential
  // unlinking guard without a separate store.
  hasPassword: (userId) =>
    d1First<UserRow>(
      db,
      `SELECT password_hash FROM auth_users WHERE id = ?`,
      [userId],
      "oauthAccount.hasPassword",
    ).pipe(Effect.map((row) => row?.password_hash != null)),
});

// ---------------------------------------------------------------------------
// OAuthUserStore (auth_users)
// ---------------------------------------------------------------------------

export const makeOAuthUserStore = (db: D1Database): typeof Auth.OAuth.OAuthUserStore.Service => {
  const requireById = (
    userId: string,
    label: string,
  ): Effect.Effect<Auth.User, Auth.AuthError | Auth.UserNotFoundError> =>
    d1First<UserRow>(db, `SELECT * FROM auth_users WHERE id = ?`, [userId], label).pipe(
      Effect.flatMap(
        (row): Effect.Effect<Auth.User, Auth.AuthError | Auth.UserNotFoundError> =>
          row
            ? rowToUser(row, label)
            : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    );

  return {
    getUser: (userId) => requireById(userId, "oauthUser.getUser"),
    createUser: (input) =>
      Effect.gen(function* () {
        const now = new Date();
        const user: Auth.User = {
          id: randomUUID(),
          createdAt: now,
          updatedAt: now,
          attributes: {},
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.image !== undefined ? { image: input.image } : {}),
        };
        yield* d1Run(db, insertUser, insertUserParams(user), "oauthUser.createUser");
        return user;
      }),
    // Supports `updateUserInfoOnLink`: refresh profile fields from the provider.
    updateUser: (userId, update) =>
      Effect.gen(function* () {
        yield* d1Run(
          db,
          `UPDATE auth_users SET name = COALESCE(?, name), image = COALESCE(?, image), updated_at = ? WHERE id = ?`,
          [update.name ?? null, update.image ?? null, Date.now(), userId],
          "oauthUser.updateUser",
        );
        return yield* requireById(userId, "oauthUser.updateUser").pipe(
          Effect.catchTag("UserNotFoundError", (e) =>
            Effect.fail(new Auth.AuthError({ message: "User not found after update", cause: e })),
          ),
        );
      }),
  };
};

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

export const makePasswordResetStore = (
  db: D1Database,
): typeof Auth.Password.PasswordResetStore.Service => ({
  create: (reset) =>
    d1Run(
      db,
      `INSERT INTO auth_password_resets (token, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
      [reset.token, reset.userId, reset.email, reset.createdAt, reset.expiresAt],
      "passwordReset.create",
    ).pipe(Effect.as(reset)),
  get: (token) =>
    d1First<PasswordResetRow>(
      db,
      `SELECT * FROM auth_password_resets WHERE token = ?`,
      [token],
      "passwordReset.get",
    ).pipe(Effect.map((row) => (row ? rowToPasswordReset(row) : null))),
  delete: (token) =>
    d1Run(
      db,
      `DELETE FROM auth_password_resets WHERE token = ?`,
      [token],
      "passwordReset.delete",
    ).pipe(Effect.asVoid),
  deleteByUserId: (userId) =>
    d1Run(
      db,
      `DELETE FROM auth_password_resets WHERE user_id = ?`,
      [userId],
      "passwordReset.deleteByUserId",
    ).pipe(Effect.asVoid),
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

export const makeMagicLinkStore = (db: D1Database): typeof Auth.MagicLinkStore.Service => ({
  create: (token) =>
    d1Run(
      db,
      `INSERT INTO auth_magic_links (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
      [token.token, token.email, token.createdAt, token.expiresAt],
      "magicLink.create",
    ).pipe(Effect.as(token)),
  get: (token) =>
    d1First<MagicLinkRow>(
      db,
      `SELECT * FROM auth_magic_links WHERE token = ?`,
      [token],
      "magicLink.get",
    ).pipe(Effect.map((row) => (row ? rowToMagicLink(row) : null))),
  getByEmail: (email) =>
    d1First<MagicLinkRow>(
      db,
      `SELECT * FROM auth_magic_links WHERE email = ?`,
      [email],
      "magicLink.getByEmail",
    ).pipe(Effect.map((row) => (row ? rowToMagicLink(row) : null))),
  delete: (token) =>
    d1Run(db, `DELETE FROM auth_magic_links WHERE token = ?`, [token], "magicLink.delete").pipe(
      Effect.asVoid,
    ),
  deleteByEmail: (email) =>
    d1Run(
      db,
      `DELETE FROM auth_magic_links WHERE email = ?`,
      [email],
      "magicLink.deleteByEmail",
    ).pipe(Effect.asVoid),
});

/**
 * `MagicLinkUserStore` and `EmailOTPUserStore` are structurally identical
 * (createUser over auth_users), so both stores share this implementation.
 */
const makeEmailSignInUserStore = (
  db: D1Database,
  label: string,
): typeof Auth.MagicLinkUserStore.Service & typeof Auth.Email.EmailOTPUserStore.Service => ({
  createUser: (input) =>
    Effect.gen(function* () {
      const now = new Date();
      const user: Auth.User = {
        id: randomUUID(),
        createdAt: now,
        updatedAt: now,
        attributes: {},
        ...(input.name !== undefined ? { name: input.name } : {}),
      };
      yield* d1Run(db, insertUser, insertUserParams(user), `${label}.createUser`);
      return user;
    }),
});

export const makeMagicLinkUserStore = (db: D1Database): typeof Auth.MagicLinkUserStore.Service =>
  makeEmailSignInUserStore(db, "magicLinkUser");

// ---------------------------------------------------------------------------
// EmailOTPStore + EmailOTPUserStore
// ---------------------------------------------------------------------------

interface EmailOTPRow {
  readonly email: string;
  readonly purpose: string;
  readonly otp_hash: string;
  readonly attempts: number;
  readonly created_at: number;
  readonly expires_at: number;
}

const rowToEmailOTP = (row: EmailOTPRow): Auth.Email.EmailOTPRecord => ({
  email: row.email,
  purpose: row.purpose as Auth.Email.EmailOTPPurpose,
  otpHash: row.otp_hash,
  attempts: row.attempts,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

const upsertEmailOTP = `INSERT INTO auth_email_otps (email, purpose, otp_hash, attempts, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(email, purpose) DO UPDATE SET
    otp_hash = excluded.otp_hash,
    attempts = excluded.attempts,
    created_at = excluded.created_at,
    expires_at = excluded.expires_at`;

export const makeEmailOTPStore = (db: D1Database): typeof Auth.Email.EmailOTPStore.Service => {
  const read = (email: string, purpose: Auth.Email.EmailOTPPurpose, label: string) =>
    d1First<EmailOTPRow>(
      db,
      `SELECT * FROM auth_email_otps WHERE email = ? AND purpose = ?`,
      [email, purpose],
      label,
    );

  return {
    upsert: (record) =>
      d1Run(
        db,
        upsertEmailOTP,
        [
          record.email,
          record.purpose,
          record.otpHash,
          record.attempts,
          record.createdAt,
          record.expiresAt,
        ],
        "emailOtp.upsert",
      ).pipe(Effect.as(record)),
    get: (email, purpose) =>
      read(email, purpose, "emailOtp.get").pipe(
        Effect.map((row) => (row ? rowToEmailOTP(row) : null)),
      ),
    delete: (email, purpose) =>
      d1Run(
        db,
        `DELETE FROM auth_email_otps WHERE email = ? AND purpose = ?`,
        [email, purpose],
        "emailOtp.delete",
      ).pipe(Effect.asVoid),
    incrementAttempts: (email, purpose) =>
      Effect.gen(function* () {
        // Single atomic UPDATE + RETURNING avoids a read-modify-write race.
        const row = yield* d1First<{ attempts: number }>(
          db,
          `UPDATE auth_email_otps SET attempts = attempts + 1 WHERE email = ? AND purpose = ? RETURNING attempts`,
          [email, purpose],
          "emailOtp.incrementAttempts",
        );
        if (row == null) {
          return yield* new Auth.AuthError({ message: "OTP record not found" });
        }
        return row.attempts;
      }),
  };
};

export const makeEmailOTPUserStore = (
  db: D1Database,
): typeof Auth.Email.EmailOTPUserStore.Service => makeEmailSignInUserStore(db, "emailOtpUser");

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
): Effect.Effect<Auth.SecondFactor.MultiFactorRecord, Auth.AuthError> =>
  Effect.try({
    try: () => ({
      userId: row.user_id,
      secret: row.secret,
      backupCodes: JSON.parse(row.backup_codes) as readonly string[],
      verified: row.verified !== 0,
      createdAt: row.created_at,
      ...(row.last_used_counter != null ? { lastUsedCounter: row.last_used_counter } : {}),
    }),
    catch: (cause) => new Auth.AuthError({ message: "multiFactor decode failed", cause }),
  });

// Atomic single-statement upsert keyed by the user_id primary key.
const upsertMultiFactor = `INSERT INTO auth_multi_factor (user_id, secret, backup_codes, verified, created_at, last_used_counter)
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(user_id) DO UPDATE SET
    secret = excluded.secret,
    backup_codes = excluded.backup_codes,
    verified = excluded.verified,
    created_at = excluded.created_at,
    last_used_counter = excluded.last_used_counter`;

export const makeMultiFactorStore = (
  db: D1Database,
): typeof Auth.SecondFactor.MultiFactorStore.Service => ({
  get: (userId) =>
    d1First<MultiFactorRow>(
      db,
      `SELECT * FROM auth_multi_factor WHERE user_id = ?`,
      [userId],
      "multiFactor.get",
    ).pipe(Effect.flatMap((row) => (row ? rowToMultiFactor(row) : Effect.succeed(null)))),
  upsert: (record) =>
    d1Run(
      db,
      upsertMultiFactor,
      [
        record.userId,
        record.secret,
        JSON.stringify(record.backupCodes),
        record.verified ? 1 : 0,
        record.createdAt,
        record.lastUsedCounter ?? null,
      ],
      "multiFactor.upsert",
    ).pipe(Effect.as(record)),
  delete: (userId) =>
    d1Run(
      db,
      `DELETE FROM auth_multi_factor WHERE user_id = ?`,
      [userId],
      "multiFactor.delete",
    ).pipe(Effect.asVoid),
});

interface PendingMultiFactorRow {
  readonly token: string;
  readonly user_id: string;
  readonly expires_at: number;
  readonly created_at: number;
}

const rowToPendingMultiFactor = (
  row: PendingMultiFactorRow,
): Auth.SecondFactor.PendingMultiFactor => ({
  token: row.token,
  userId: row.user_id,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
});

export const makePendingMultiFactorStore = (
  db: D1Database,
): typeof Auth.SecondFactor.PendingMultiFactorStore.Service => ({
  create: (pending) =>
    d1Run(
      db,
      `INSERT INTO auth_pending_multi_factor (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
      [pending.token, pending.userId, pending.expiresAt, pending.createdAt],
      "pendingMultiFactor.create",
    ).pipe(Effect.as(pending)),
  get: (token) =>
    d1First<PendingMultiFactorRow>(
      db,
      `SELECT * FROM auth_pending_multi_factor WHERE token = ?`,
      [token],
      "pendingMultiFactor.get",
    ).pipe(Effect.map((row) => (row ? rowToPendingMultiFactor(row) : null))),
  delete: (token) =>
    d1Run(
      db,
      `DELETE FROM auth_pending_multi_factor WHERE token = ?`,
      [token],
      "pendingMultiFactor.delete",
    ).pipe(Effect.asVoid),
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

export const makeIdentifierStore = (db: D1Database): typeof Auth.IdentifierStore.Service => ({
  getByValue: (type, value) =>
    d1First<IdentifierRow>(
      db,
      `SELECT * FROM auth_identifiers WHERE type = ? AND value = ?`,
      [type, value],
      "identifier.getByValue",
    ).pipe(Effect.map((row) => (row ? rowToIdentifier(row) : null))),
  listByUser: (userId) =>
    d1All<IdentifierRow>(
      db,
      `SELECT * FROM auth_identifiers WHERE user_id = ? ORDER BY created_at ASC`,
      [userId],
      "identifier.listByUser",
    ).pipe(Effect.map((rows) => rows.map(rowToIdentifier))),
  create: (identifier) =>
    d1Run(
      db,
      `INSERT INTO auth_identifiers (id, user_id, type, value, verified, verified_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        identifier.id,
        identifier.userId,
        identifier.type,
        identifier.value,
        identifier.verified ? 1 : 0,
        identifier.verifiedAt != null ? dateToMs(identifier.verifiedAt) : null,
        dateToMs(identifier.createdAt),
      ],
      "identifier.create",
    ).pipe(Effect.as(identifier)),
  setVerified: (id, verifiedAt) =>
    Effect.gen(function* () {
      yield* d1Run(
        db,
        `UPDATE auth_identifiers SET verified = 1, verified_at = ? WHERE id = ?`,
        [dateToMs(verifiedAt), id],
        "identifier.setVerified",
      );
      const row = yield* d1First<IdentifierRow>(
        db,
        `SELECT * FROM auth_identifiers WHERE id = ?`,
        [id],
        "identifier.setVerified",
      );
      return row ? rowToIdentifier(row) : null;
    }),
  delete: (id) =>
    d1Run(db, `DELETE FROM auth_identifiers WHERE id = ?`, [id], "identifier.delete").pipe(
      Effect.asVoid,
    ),
  deleteByUser: (userId) =>
    d1Run(
      db,
      `DELETE FROM auth_identifiers WHERE user_id = ?`,
      [userId],
      "identifier.deleteByUser",
    ).pipe(Effect.asVoid),
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

export const makeAccountLockoutStore = (
  db: D1Database,
): typeof Auth.Plugins.AccountLockoutStore.Service => ({
  get: (key) =>
    d1First<AccountLockoutRow>(
      db,
      `SELECT * FROM auth_account_lockouts WHERE key = ?`,
      [key],
      "accountLockout.get",
    ).pipe(Effect.map((row) => (row ? rowToLockout(row) : null))),
  // The whole transition is one statement, so concurrent attempts can't lose
  // increments: an active lock is returned unchanged; an expired lock (or
  // missing row) resets to 1; otherwise increment; crossing the threshold
  // sets locked_until.
  registerAttempt: (key, { maxAttempts, lockoutDurationMs, now }) =>
    Effect.gen(function* () {
      const lockedUntil = now + lockoutDurationMs;
      const row = yield* d1First<AccountLockoutRow>(
        db,
        `INSERT INTO auth_account_lockouts (key, failures, locked_until)
           VALUES (?, 1, ?)
           ON CONFLICT(key) DO UPDATE SET
             failures = CASE
               WHEN locked_until IS NOT NULL AND locked_until > ? THEN failures
               WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
               ELSE failures + 1 END,
             locked_until = CASE
               WHEN locked_until IS NOT NULL AND locked_until > ? THEN locked_until
               WHEN (CASE
                 WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
                 ELSE failures + 1 END) >= ? THEN ?
               ELSE NULL END
           RETURNING key, failures, locked_until`,
        [key, 1 >= maxAttempts ? lockedUntil : null, now, now, now, now, maxAttempts, lockedUntil],
        "accountLockout.registerAttempt",
      );
      if (row == null) {
        return yield* Effect.fail(
          new Auth.AuthError({ message: "accountLockout.registerAttempt returned no row" }),
        );
      }
      return rowToLockout(row);
    }),
  delete: (key) =>
    d1Run(
      db,
      `DELETE FROM auth_account_lockouts WHERE key = ?`,
      [key],
      "accountLockout.delete",
    ).pipe(Effect.asVoid),
});

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

export const SessionStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SessionStore, makeSessionStore(db));
export const UserStoreLayer = (db: D1Database) => Layer.succeed(Auth.UserStore, makeUserStore(db));
export const UserServiceStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.UserServiceStore, makeUserServiceStore(db));
export const EmailPasswordStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Email.EmailPasswordStore, makeEmailPasswordStore(db));
export const PasswordResetUserStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Password.PasswordResetUserStore, makePasswordResetUserStore(db));
export const RoleStoreLayer = (db: D1Database) => Layer.succeed(Auth.RoleStore, makeRoleStore(db));
export const RateLimitStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.RateLimitStore, makeRateLimitStore(db));
export const EmailVerificationStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Email.EmailVerificationStore, makeEmailVerificationStore(db));
export const ChallengeStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SecondFactor.ChallengeStore, makeChallengeStore(db));
export const CredentialStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SecondFactor.CredentialStore, makeCredentialStore(db));
export const OAuthStateStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.OAuth.OAuthStateStore, makeOAuthStateStore(db));
export const OAuthAccountStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.OAuth.OAuthAccountStore, makeOAuthAccountStore(db));
export const OAuthUserStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.OAuth.OAuthUserStore, makeOAuthUserStore(db));
export const PasswordResetStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Password.PasswordResetStore, makePasswordResetStore(db));
export const MagicLinkStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.MagicLinkStore, makeMagicLinkStore(db));
export const MagicLinkUserStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.MagicLinkUserStore, makeMagicLinkUserStore(db));
export const EmailOTPStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Email.EmailOTPStore, makeEmailOTPStore(db));
export const EmailOTPUserStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Email.EmailOTPUserStore, makeEmailOTPUserStore(db));
export const MultiFactorStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SecondFactor.MultiFactorStore, makeMultiFactorStore(db));
export const PendingMultiFactorStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SecondFactor.PendingMultiFactorStore, makePendingMultiFactorStore(db));
export const IdentifierStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.IdentifierStore, makeIdentifierStore(db));
export const AccountLockoutStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.Plugins.AccountLockoutStore, makeAccountLockoutStore(db));

/**
 * A single layer that provides every effect-auth store backed by the given D1
 * database. Provide it once and the core auth stack (SessionService,
 * EmailPasswordService, OAuth, WebAuthn, MagicLink, EmailOTP, MultiFactor,
 * etc.) has persistence.
 */
export const layer = (db: D1Database) =>
  Layer.mergeAll(
    SessionStoreLayer(db),
    UserStoreLayer(db),
    UserServiceStoreLayer(db),
    EmailPasswordStoreLayer(db),
    PasswordResetUserStoreLayer(db),
    RoleStoreLayer(db),
    RateLimitStoreLayer(db),
    EmailVerificationStoreLayer(db),
    ChallengeStoreLayer(db),
    CredentialStoreLayer(db),
    OAuthStateStoreLayer(db),
    OAuthAccountStoreLayer(db),
    OAuthUserStoreLayer(db),
    PasswordResetStoreLayer(db),
    MagicLinkStoreLayer(db),
    MagicLinkUserStoreLayer(db),
    EmailOTPStoreLayer(db),
    EmailOTPUserStoreLayer(db),
    MultiFactorStoreLayer(db),
    PendingMultiFactorStoreLayer(db),
    IdentifierStoreLayer(db),
    AccountLockoutStoreLayer(db),
  );
