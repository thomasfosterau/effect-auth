/**
 * Cloudflare D1 implementations of every effect-auth storage interface.
 *
 * Each `make*Store` builds a plain store object backed by a D1 database, and
 * each `*StoreLayer` lifts it into an Effect `Layer` keyed by the matching
 * effect-auth `Context.Tag`. {@link layer} bundles all of them so a single
 * `Layer.provide` wires up the entire auth stack.
 */

import { Effect, Layer } from "effect";
import { randomUUID } from "node:crypto";
import * as Auth from "effect-auth";
import { d1All, d1First, d1Run, type D1Database } from "./D1.js";

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

const decodeAttributes = (text: string | null): Record<string, unknown> =>
  text == null ? {} : (JSON.parse(text) as Record<string, unknown>);

const dateToMs = (date: Date): number => date.getTime();
const msToDate = (ms: number): Date => new Date(ms);

// ---------------------------------------------------------------------------
// Shared user row (auth_users backs UserStore, UserServiceStore,
// EmailPasswordStore and PasswordResetUserStore)
// ---------------------------------------------------------------------------

interface UserRow {
  readonly id: string;
  readonly email: string | null;
  readonly password_hash: string | null;
  readonly attributes: string | null;
  readonly created_at: number;
}

const rowToUser = (row: UserRow): Auth.User => ({
  id: row.id,
  attributes: decodeAttributes(row.attributes),
});

const emailFromAttributes = (attributes: Record<string, unknown>): string | null => {
  const email = attributes["email"];
  return typeof email === "string" ? email : null;
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

const rowToSession = (row: SessionRow): Auth.Session => ({
  id: row.id,
  userId: row.user_id,
  expiresAt: msToDate(row.expires_at),
  createdAt: msToDate(row.created_at),
  lastActivityAt: msToDate(row.last_activity_at),
  attributes: decodeAttributes(row.attributes),
});

export const makeSessionStore = (db: D1Database): Auth.SessionStore => ({
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
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToSession(row))
          : Effect.fail(new Auth.SessionNotFoundError({ message: "Session not found", sessionId })),
      ),
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
});

export const makeUserStore = (db: D1Database): Auth.UserStore => ({
  get: (userId) =>
    d1First<UserRow>(db, `SELECT * FROM auth_users WHERE id = ?`, [userId], "user.get").pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToUser(row))
          : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    ),
  getCredentials: (userId) =>
    d1First<UserRow>(
      db,
      `SELECT password_hash FROM auth_users WHERE id = ?`,
      [userId],
      "user.getCredentials",
    ).pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(row.password_hash ?? "")
          : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    ),
});

// ---------------------------------------------------------------------------
// UserServiceStore
// ---------------------------------------------------------------------------

export const makeUserServiceStore = (db: D1Database): Auth.UserServiceStore => ({
  get: (userId) =>
    d1First<UserRow>(db, `SELECT * FROM auth_users WHERE id = ?`, [userId], "userService.get").pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToUser(row))
          : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId })),
      ),
    ),
  getByEmail: (email) =>
    d1First<UserRow>(
      db,
      `SELECT * FROM auth_users WHERE email = ?`,
      [email],
      "userService.getByEmail",
    ).pipe(Effect.map((row) => (row ? rowToUser(row) : null))),
  update: (user) =>
    d1Run(
      db,
      `UPDATE auth_users SET attributes = ?, email = ? WHERE id = ?`,
      [encodeAttributes(user.attributes), emailFromAttributes(user.attributes), user.id],
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

export const makeEmailPasswordStore = (db: D1Database): Auth.EmailPasswordStore => ({
  getUserByEmail: (email) =>
    d1First<UserRow>(
      db,
      `SELECT * FROM auth_users WHERE email = ?`,
      [email],
      "emailPassword.getUserByEmail",
    ).pipe(Effect.map((row) => (row ? rowToUser(row) : null))),
  createUser: (input) =>
    Effect.gen(function* () {
      const id = randomUUID();
      const attributes: Record<string, unknown> = {
        ...input.attributes,
        email: input.email,
      };
      if (input.name !== undefined) {
        attributes["name"] = input.name;
      }
      yield* d1Run(
        db,
        `INSERT INTO auth_users (id, email, password_hash, attributes, created_at) VALUES (?, ?, ?, ?, ?)`,
        [id, input.email, null, encodeAttributes(attributes), Date.now()],
        "emailPassword.createUser",
      );
      return { id, attributes };
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

export const makePasswordResetUserStore = (db: D1Database): Auth.PasswordResetUserStore => ({
  getUserByEmail: (email) =>
    d1First<UserRow>(
      db,
      `SELECT * FROM auth_users WHERE email = ?`,
      [email],
      "passwordResetUser.getUserByEmail",
    ).pipe(Effect.map((row) => (row ? rowToUser(row) : null))),
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

export const makeRoleStore = (db: D1Database): Auth.RoleStore => ({
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

export const makeRateLimitStore = (db: D1Database): Auth.RateLimitStore => {
  const readEntry = (key: string) =>
    d1First<RateLimitRow>(
      db,
      `SELECT * FROM auth_rate_limits WHERE key = ?`,
      [key],
      "rateLimit.get",
    ).pipe(Effect.map((row) => (row ? rowToRateLimit(row) : null)));

  return {
    get: (key) => readEntry(key).pipe(Effect.orDie),
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
        const existing = yield* readEntry(key);
        if (existing == null || now >= existing.resetAt) {
          yield* d1Run(
            db,
            upsertRateLimit,
            [key, 1, now + ttlSeconds * 1000, null],
            "rateLimit.increment",
          );
          return 1;
        }
        const count = existing.count + 1;
        yield* d1Run(
          db,
          `UPDATE auth_rate_limits SET count = ? WHERE key = ?`,
          [count, key],
          "rateLimit.increment",
        );
        return count;
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

const rowToEmailVerification = (row: EmailVerificationRow): Auth.EmailVerification => ({
  token: row.token,
  userId: row.user_id,
  email: row.email,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
});

export const makeEmailVerificationStore = (db: D1Database): Auth.EmailVerificationStore => ({
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

const rowToChallenge = (row: ChallengeRow): Auth.WebAuthnChallenge =>
  row.user_id == null
    ? { challenge: fromBase64(row.challenge), expiresAt: row.expires_at }
    : { challenge: fromBase64(row.challenge), expiresAt: row.expires_at, userId: row.user_id };

export const makeChallengeStore = (db: D1Database): Auth.ChallengeStore => ({
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
    ).pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToChallenge(row))
          : Effect.fail(new Auth.ChallengeNotFoundError({ message: "Challenge not found" })),
      ),
    ),
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

const rowToCredential = (row: CredentialRow): Auth.WebAuthnCredential => ({
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
});

const credentialParams = (credential: Auth.WebAuthnCredential): readonly unknown[] => [
  credential.id,
  credential.userId,
  toBase64(credential.publicKey),
  credential.algorithm,
  credential.counter,
  credential.createdAt,
  credential.name ?? null,
  credential.transports ? JSON.stringify(credential.transports) : null,
];

export const makeCredentialStore = (db: D1Database): Auth.CredentialStore => ({
  create: (credential) =>
    d1Run(
      db,
      `INSERT INTO auth_webauthn_credentials (id, user_id, public_key, algorithm, counter, created_at, name, transports)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      credentialParams(credential),
      "credential.create",
    ).pipe(Effect.as(credential)),
  get: (credentialId) =>
    d1First<CredentialRow>(
      db,
      `SELECT * FROM auth_webauthn_credentials WHERE id = ?`,
      [credentialId],
      "credential.get",
    ).pipe(
      Effect.orDie,
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToCredential(row))
          : Effect.fail(
              new Auth.CredentialNotFoundError({ message: "Credential not found", credentialId }),
            ),
      ),
    ),
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
  getByUserId: (userId) =>
    d1All<CredentialRow>(
      db,
      `SELECT * FROM auth_webauthn_credentials WHERE user_id = ?`,
      [userId],
      "credential.getByUserId",
    ).pipe(Effect.map((rows) => rows.map(rowToCredential))),
});

// ---------------------------------------------------------------------------
// OAuthStateStore + OAuthAccountStore
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

export const makeOAuthStateStore = (db: D1Database): Auth.OAuthStateStore => ({
  create: (state) =>
    d1Run(
      db,
      `INSERT OR REPLACE INTO auth_oauth_states (state, provider, code_verifier, return_to, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        state.state,
        state.provider,
        state.codeVerifier ?? null,
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
    ).pipe(
      Effect.flatMap((row) =>
        row
          ? Effect.succeed(rowToOAuthState(row))
          : Effect.fail(new Auth.AuthError({ message: `OAuth state not found: ${state}` })),
      ),
    ),
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

const oauthAccountParams = (account: Auth.OAuthAccount): readonly unknown[] => [
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

export const makeOAuthAccountStore = (db: D1Database): Auth.OAuthAccountStore => ({
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

export const makePasswordResetStore = (db: D1Database): Auth.PasswordResetStore => ({
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
// Layers
// ---------------------------------------------------------------------------

export const SessionStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.SessionStore, makeSessionStore(db));
export const UserStoreLayer = (db: D1Database) => Layer.succeed(Auth.UserStore, makeUserStore(db));
export const UserServiceStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.UserServiceStore, makeUserServiceStore(db));
export const EmailPasswordStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.EmailPasswordStore, makeEmailPasswordStore(db));
export const PasswordResetUserStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.PasswordResetUserStore, makePasswordResetUserStore(db));
export const RoleStoreLayer = (db: D1Database) => Layer.succeed(Auth.RoleStore, makeRoleStore(db));
export const RateLimitStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.RateLimitStore, makeRateLimitStore(db));
export const EmailVerificationStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.EmailVerificationStore, makeEmailVerificationStore(db));
export const ChallengeStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.ChallengeStore, makeChallengeStore(db));
export const CredentialStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.CredentialStore, makeCredentialStore(db));
export const OAuthStateStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.OAuthStateStore, makeOAuthStateStore(db));
export const OAuthAccountStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.OAuthAccountStore, makeOAuthAccountStore(db));
export const PasswordResetStoreLayer = (db: D1Database) =>
  Layer.succeed(Auth.PasswordResetStore, makePasswordResetStore(db));

/**
 * A single layer that provides every effect-auth store backed by the given D1
 * database. Provide it once and the entire auth stack (SessionManager,
 * EmailPasswordService, OAuth, WebAuthn, etc.) has persistence.
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
    PasswordResetStoreLayer(db),
  );
