/**
 * Table names, the dialect-independent {@link Tables} set and the row types the
 * stores read. Each dialect (`Pg`, `Sqlite`, `MySql`) defines the tables with
 * the same column names, and every column reads back as the same `string`,
 * `Date`, `JsonObject` or `boolean`. Login handles live only in the identifiers
 * table.
 */

import type * as MySql from "./MySqlSchema.ts";
import type * as Pg from "./PgSchema.ts";
import type * as Sqlite from "./SqliteSchema.ts";

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------

/** The physical table name for each of the auth tables. */
export interface TableNames {
  readonly sessions: string;
  readonly users: string;
  readonly identifiers: string;
  /** `ApiKeyStore`'s keys, by SHA-256 digest. */
  readonly apiKeys: string;
  /** `RateLimitStore`'s fixed-window counters. */
  readonly rateLimits: string;
  /** `EmailVerificationStore`'s and `PasswordResetStore`'s pending tokens, by digest. */
  readonly tokens: string;
}

/** The default `effect_auth_*` table names, shared by every dialect. */
export const defaultTableNames: TableNames = {
  sessions: "effect_auth_sessions",
  users: "effect_auth_users",
  identifiers: "effect_auth_identifiers",
  apiKeys: "effect_auth_api_keys",
  rateLimits: "effect_auth_rate_limits",
  tokens: "effect_auth_tokens",
};

/** What `ApiKey.permissions` holds: resource to allowed actions. */
export type ApiKeyPermissions = Record<string, ReadonlyArray<string>>;

/**
 * Which flow a row of the tokens table belongs to. One table holds both kinds;
 * every read and delete is scoped to its purpose, so a password-reset request
 * never clears a pending email verification.
 */
export type TokenPurpose = "email-verification" | "password-reset";

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * The set of tables a store factory reads and writes: one dialect's six
 * tables, never a mixture.
 *
 * The union is what makes the stores dialect-generic without giving up type
 * safety — `Pg.defineTables()`, `Sqlite.defineTables()` and
 * `MySql.defineTables()` each produce one member, and every member yields the
 * same row and insert shapes, so the store code is written once.
 */
export type Tables = Pg.Tables | Sqlite.Tables | MySql.Tables;

/** Row shapes selected from each table, whichever dialect produced them. */
export type SessionRow = Tables["sessions"]["$inferSelect"];
/** The row `select()` returns from any dialect's users table. */
export type UserRow = Tables["users"]["$inferSelect"];
/** The row `select()` returns from any dialect's identifiers table. */
export type IdentifierRow = Tables["identifiers"]["$inferSelect"];
/** The row `select()` returns from any dialect's API keys table. */
export type ApiKeyRow = Tables["apiKeys"]["$inferSelect"];
/** The row `select()` returns from any dialect's rate limits table. */
export type RateLimitRow = Tables["rateLimits"]["$inferSelect"];
/** The row `select()` returns from any dialect's tokens table. */
export type TokenRow = Tables["tokens"]["$inferSelect"];
