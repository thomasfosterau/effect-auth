/**
 * SQL schema for the effect-auth `SqlClient` stores.
 *
 * Tables are namespaced with an `auth_` prefix so they can live alongside an
 * application's own tables in the same database. All statements are
 * idempotent (`CREATE TABLE IF NOT EXISTS`) so {@link migrate} is safe to run
 * on every deploy.
 *
 * Column types use `TEXT`, `INTEGER`, and `BIGINT`:
 * - Epoch-millisecond timestamps are `BIGINT` — epoch-ms values (~1.75e12) overflow
 *   Postgres `INTEGER` (int4, max 2,147,483,647) and MySQL signed `INT`.
 *   `BIGINT` is safe on all three drivers; SQLite treats it identically to
 *   `INTEGER` (64-bit affinity) so there is no regression there.
 * - Booleans and small counters remain `INTEGER`.
 * - Attribute bags and other structured values are JSON `TEXT`.
 *
 * **Migration note for Postgres / MySQL early adopters:**
 * If you ran `migrate` against a Postgres or MySQL database before this
 * change, you must alter the affected columns manually before upgrading:
 * ```sql
 * -- Postgres
 * ALTER TABLE auth_users ALTER COLUMN created_at TYPE BIGINT,
 *                        ALTER COLUMN updated_at TYPE BIGINT;
 * ALTER TABLE auth_sessions ALTER COLUMN expires_at TYPE BIGINT,
 *                           ALTER COLUMN created_at TYPE BIGINT,
 *                           ALTER COLUMN last_activity_at TYPE BIGINT;
 * ALTER TABLE auth_rate_limits ALTER COLUMN reset_at TYPE BIGINT,
 *                              ALTER COLUMN blocked_until TYPE BIGINT;
 * ALTER TABLE auth_email_verifications ALTER COLUMN created_at TYPE BIGINT,
 *                                      ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_webauthn_challenges ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_webauthn_credentials ALTER COLUMN created_at TYPE BIGINT;
 * ALTER TABLE auth_oauth_states ALTER COLUMN created_at TYPE BIGINT,
 *                               ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_oauth_accounts ALTER COLUMN expires_at TYPE BIGINT,
 *                                 ALTER COLUMN created_at TYPE BIGINT,
 *                                 ALTER COLUMN updated_at TYPE BIGINT;
 * ALTER TABLE auth_password_resets ALTER COLUMN created_at TYPE BIGINT,
 *                                  ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_magic_links ALTER COLUMN created_at TYPE BIGINT,
 *                              ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_email_otps ALTER COLUMN created_at TYPE BIGINT,
 *                             ALTER COLUMN expires_at TYPE BIGINT;
 * ALTER TABLE auth_two_factor ALTER COLUMN created_at TYPE BIGINT;
 * ALTER TABLE auth_pending_two_factor ALTER COLUMN expires_at TYPE BIGINT,
 *                                     ALTER COLUMN created_at TYPE BIGINT;
 *
 * -- MySQL (adjust table by table as needed)
 * ALTER TABLE auth_users MODIFY created_at BIGINT NOT NULL,
 *                        MODIFY updated_at BIGINT NOT NULL;
 * -- … repeat for all timestamp columns listed above.
 * ```
 * SQLite and D1 (`@effect-auth/alchemy`) need no migration — their `INTEGER`
 * affinity already stores 64-bit values.
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
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS auth_users_email_idx ON auth_users (email)`,
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
  `CREATE TABLE IF NOT EXISTS auth_two_factor (
    user_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL,
    verified INTEGER NOT NULL,
    created_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS auth_pending_two_factor (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
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
