/**
 * SQL schema for the effect-auth `SqlClient` stores.
 *
 * Tables are namespaced with an `auth_` prefix so they can live alongside an
 * application's own tables in the same database. All statements are
 * idempotent (`CREATE TABLE IF NOT EXISTS`) so {@link migrate} is safe to run
 * on every deploy.
 *
 * Column types use `TEXT`, `INTEGER`, and `BIGINT`:
 * - Epoch-millisecond timestamps are `BIGINT` — epoch-ms values (~1.75e12)
 *   overflow Postgres `INTEGER` (int4) and MySQL signed `INT`. `BIGINT` is
 *   safe on SQLite (D1 included), which treats it identically to `INTEGER`
 *   (64-bit affinity), and on Postgres.
 * - Booleans and small counters remain `INTEGER`.
 * - Attribute bags and other structured values are JSON `TEXT`.
 *
 * Token columns (`auth_sessions.id`, `auth_magic_links.token`,
 * `auth_email_verifications.token`, `auth_password_resets.token`,
 * `auth_api_keys.key_hash`) store the SHA-256 hash computed by the service
 * layer — the database never sees a raw bearer token.
 */

import { Effect } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * The ordered list of DDL statements that create the auth schema. Each entry
 * is a single statement so it can be executed through a prepared statement.
 */
export const schemaStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    name TEXT,
    image TEXT,
    password_hash TEXT,
    attributes TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    last_activity_at BIGINT NOT NULL,
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
    reset_at BIGINT NOT NULL,
    blocked_until BIGINT
  )`,
  `CREATE TABLE IF NOT EXISTS auth_email_verifications (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_email_verifications_user_idx ON auth_email_verifications (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_webauthn_challenges (
    challenge TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    user_id TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS auth_webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm INTEGER NOT NULL,
    counter INTEGER NOT NULL,
    created_at BIGINT NOT NULL,
    name TEXT,
    transports TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS auth_webauthn_credentials_user_idx ON auth_webauthn_credentials (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_oauth_states (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    code_verifier TEXT,
    nonce TEXT,
    return_to TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
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
    expires_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_oauth_accounts_provider_idx ON auth_oauth_accounts (provider, provider_id)`,
  `CREATE INDEX IF NOT EXISTS auth_oauth_accounts_user_idx ON auth_oauth_accounts (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_password_resets (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_password_resets_user_idx ON auth_password_resets (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_magic_links (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_magic_links_email_idx ON auth_magic_links (email)`,
  `CREATE TABLE IF NOT EXISTS auth_email_otps (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (email, purpose)
  )`,
  `CREATE TABLE IF NOT EXISTS auth_multi_factor (
    user_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL,
    verified INTEGER NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_counter INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS auth_pending_multi_factor (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS auth_identifiers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    verified_at BIGINT,
    created_at BIGINT NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_identifiers_type_value_idx ON auth_identifiers (type, value)`,
  `CREATE INDEX IF NOT EXISTS auth_identifiers_user_idx ON auth_identifiers (user_id)`,
  `CREATE TABLE IF NOT EXISTS auth_account_lockouts (
    key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL,
    locked_until BIGINT
  )`,
  `CREATE TABLE IF NOT EXISTS auth_api_keys (
    id TEXT PRIMARY KEY,
    name TEXT,
    prefix TEXT,
    start TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    user_id TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    expires_at BIGINT,
    last_used_at BIGINT,
    permissions TEXT,
    metadata TEXT,
    remaining INTEGER,
    refill_amount INTEGER,
    refill_interval BIGINT,
    refill_max INTEGER,
    last_refill_at BIGINT,
    rate_limit_max_requests INTEGER,
    rate_limit_window_ms BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_api_keys_hash_idx ON auth_api_keys (key_hash)`,
  `CREATE INDEX IF NOT EXISTS auth_api_keys_user_idx ON auth_api_keys (user_id)`,
  // `purgeExpired` deletes by expiry (#420).
  `CREATE INDEX IF NOT EXISTS auth_magic_links_expires_idx ON auth_magic_links (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_email_otps_expires_idx ON auth_email_otps (expires_at)`,
];

/**
 * Create every auth table and index through the ambient `SqlClient`.
 *
 * Run this once during provisioning, or on each cold start — every statement
 * uses `IF NOT EXISTS`, so repeated runs are no-ops.
 */
export const migrate: Effect.Effect<void, Auth.AuthError, SqlClient.SqlClient> =
  SqlClient.SqlClient.use((sql) =>
    Effect.forEach(
      schemaStatements,
      (statement) =>
        sql
          .unsafe(statement)
          .pipe(
            Effect.mapError(
              (cause) => new Auth.AuthError({ message: "sql migrate failed", cause }),
            ),
          ),
      { concurrency: 1, discard: true },
    ),
  );
