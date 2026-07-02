/**
 * SQL schema for the effect-auth `SqlClient` stores.
 *
 * Tables are namespaced with an `auth_` prefix so they can live alongside an
 * application's own tables in the same database. All statements are
 * idempotent (`CREATE TABLE IF NOT EXISTS`) so {@link migrate} is safe to run
 * on every deploy.
 *
 * Column types are intentionally limited to `TEXT`/`INTEGER` so the DDL is
 * portable across dialects (SQLite/D1, Postgres, MySQL). Data codecs mirror
 * `@effect-auth/alchemy`: dates as epoch milliseconds (`INTEGER`), booleans
 * as `0`/`1` (`INTEGER`), attribute bags and other structured values as JSON
 * `TEXT`.
 */

import { Effect } from "effect";
import { SqlClient } from "effect/unstable/sql";
import * as Auth from "effect-auth";

/**
 * The ordered list of DDL statements that create the auth schema. Each entry
 * is a single statement so it can be executed through a prepared statement.
 */
export const schemaStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    image TEXT,
    password_hash TEXT,
    attributes TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_users_email_idx ON auth_users (email)`,
  `CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity_at INTEGER NOT NULL,
    attributes TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_user_roles (
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
  )`,
  `CREATE TABLE IF NOT EXISTS auth_role_permissions (
    role TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    PRIMARY KEY (role, resource, action)
  )`,
  `CREATE TABLE IF NOT EXISTS auth_rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL,
    blocked_until INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS auth_email_verifications (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_email_verifications_user_idx ON auth_email_verifications (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_webauthn_challenges (
    challenge TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    user_id TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS auth_webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm INTEGER NOT NULL,
    counter INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    name TEXT,
    transports TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS auth_webauthn_credentials_user_idx ON auth_webauthn_credentials (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_oauth_states (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    code_verifier TEXT,
    return_to TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS auth_oauth_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    picture TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_oauth_accounts_provider_idx ON auth_oauth_accounts (provider, provider_id)`,
  `CREATE INDEX IF NOT EXISTS auth_oauth_accounts_user_idx ON auth_oauth_accounts (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_password_resets (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_password_resets_user_idx ON auth_password_resets (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_magic_links (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_magic_links_email_idx ON auth_magic_links (email)`,
  `CREATE TABLE IF NOT EXISTS auth_email_otps (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (email, purpose)
  )`,
  `CREATE TABLE IF NOT EXISTS auth_two_factor (
    user_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL,
    verified INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS auth_pending_two_factor (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`,
];

/**
 * Create every auth table and index through the ambient `SqlClient`.
 *
 * Run this once during provisioning, or on each cold start — every statement
 * uses `IF NOT EXISTS`, so repeated runs are no-ops.
 */
export const migrate: Effect.Effect<void, Auth.AuthError, SqlClient.SqlClient> = Effect.gen(
  function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* Effect.forEach(
      schemaStatements,
      (statement) =>
        sql
          .unsafe(statement)
          .pipe(Effect.mapError(() => new Auth.AuthError({ message: "sql migrate failed" }))),
      { discard: true },
    );
  },
);
