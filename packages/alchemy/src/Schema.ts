/**
 * SQL schema for the effect-auth Cloudflare D1 stores.
 *
 * Tables are namespaced with an `auth_` prefix so they can live alongside an
 * application's own tables in the same D1 database. All statements are
 * idempotent (`IF NOT EXISTS`) so {@link migrate} is safe to run on every
 * deploy.
 */

import { Effect } from "effect";
import type * as Auth from "effect-auth";
import { d1Run, type D1Database } from "./D1.js";

/**
 * The ordered list of DDL statements that create the auth schema. Each entry
 * is a single statement so it can be executed through a prepared statement.
 */
export const schemaStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    attributes TEXT,
    created_at INTEGER NOT NULL
  )`,
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
];

/**
 * Create every auth table and index in the given D1 database.
 *
 * Run this once during provisioning, or on each cold start — every statement
 * uses `IF NOT EXISTS`, so repeated runs are no-ops.
 */
export const migrate = (db: D1Database): Effect.Effect<void, Auth.AuthError> =>
  Effect.forEach(schemaStatements, (sql) => d1Run(db, sql, [], "migrate"), {
    discard: true,
  });
