/**
 * The `auth_`-prefixed tables of the `SqlClient` stores, as idempotent DDL
 * ({@link schemaStatements}), so {@link migrate} is safe on every deploy.
 * Instants are epoch-millisecond `BIGINT`s, booleans and counters `INTEGER`,
 * structured values JSON `TEXT`, and token columns hold the service's SHA-256
 * digests.
 */

import { Effect } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "../index.ts";

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
  // `purgeExpired` deletes by expiry.
  `CREATE INDEX IF NOT EXISTS auth_magic_links_expires_idx ON auth_magic_links (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_email_otps_expires_idx ON auth_email_otps (expires_at)`,
  // Wrong second-factor codes per pending challenge. A table of its
  // own rather than a column on `auth_pending_multi_factor`: SQLite has no
  // `ADD COLUMN IF NOT EXISTS`, and every statement here must be idempotent.
  `CREATE TABLE IF NOT EXISTS auth_pending_multi_factor_attempts (
    token TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL
  )`,
  // Wrong email-OTP codes per (email, purpose), kept across resends.
  // A table of its own so `emailOtp.upsert`'s DELETE + INSERT leave it; a
  // successful verification deletes the row, and `purgeExpired` deletes one
  // whose backoff has long decayed.
  `CREATE TABLE IF NOT EXISTS auth_email_otp_failures (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    failures INTEGER NOT NULL,
    last_failure_at BIGINT NOT NULL,
    PRIMARY KEY (email, purpose)
  )`,
  // The ceremony each WebAuthn challenge was issued for, a table of
  // its own for the same reason. A challenge with no row here reads as
  // missing, so one written before the table existed is redeemable by neither
  // ceremony.
  `CREATE TABLE IF NOT EXISTS auth_webauthn_challenge_ceremonies (
    challenge TEXT PRIMARY KEY,
    ceremony TEXT NOT NULL
  )`,
  // Each passkey's backup flags and AAGUID, a table of its own because the
  // DDL is append-only. A credential with no row here (one stored before the
  // table existed) reads with the three absent, and its next sign-in records
  // the flags.
  `CREATE TABLE IF NOT EXISTS auth_webauthn_credential_flags (
    credential_id TEXT PRIMARY KEY,
    backup_eligible INTEGER,
    backup_state INTEGER,
    aaguid TEXT
  )`,
  // The latest attempt per lockout key, so `purgeExpired` can drop a failure
  // counter nobody has touched for a while; a table of its own because the DDL
  // is append-only.
  `CREATE TABLE IF NOT EXISTS auth_account_lockout_attempts (
    key TEXT PRIMARY KEY,
    last_attempt_at BIGINT NOT NULL
  )`,
  // `purgeExpired` deletes by expiry from these too.
  `CREATE INDEX IF NOT EXISTS auth_sessions_expires_idx ON auth_sessions (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_oauth_states_expires_idx ON auth_oauth_states (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_webauthn_challenges_expires_idx ON auth_webauthn_challenges (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_pending_multi_factor_expires_idx ON auth_pending_multi_factor (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_email_verifications_expires_idx ON auth_email_verifications (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_password_resets_expires_idx ON auth_password_resets (expires_at)`,
  `CREATE INDEX IF NOT EXISTS auth_rate_limits_reset_idx ON auth_rate_limits (reset_at)`,
  `CREATE INDEX IF NOT EXISTS auth_account_lockouts_locked_idx ON auth_account_lockouts (locked_until)`,
  `CREATE INDEX IF NOT EXISTS auth_account_lockout_attempts_last_idx ON auth_account_lockout_attempts (last_attempt_at)`,
  `CREATE INDEX IF NOT EXISTS auth_email_otp_failures_last_idx ON auth_email_otp_failures (last_failure_at)`,
];

const CREATE_TABLE = /create\s+table\s+if\s+not\s+exists\s+(\w+)/i;

/**
 * Every table the auth schema creates, parsed from {@link schemaStatements} so
 * it cannot drift from the DDL that is actually applied. A tool that owns the
 * schema's lifecycle (the Alchemy `AuthSchema` resources) reads it to list or
 * drop the tables.
 */
export const authTableNames: readonly string[] = schemaStatements.flatMap((statement) => {
  const name = CREATE_TABLE.exec(statement)?.[1];
  return name === undefined ? [] : [name];
});

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
