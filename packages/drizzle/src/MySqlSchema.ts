/**
 * Drizzle `mysql-core` table definitions backing the effect-auth stores.
 *
 * The same tables as `Pg`, under the same names, with the same column
 * names. MySQL's differences from PostgreSQL are all physical:
 *
 * - Text keys are `varchar(255)` rather than `text`: InnoDB cannot index a
 *   `TEXT` column without a prefix length, and `(type, value)` *must* be
 *   indexable — that unique index is the claim mechanism behind
 *   `Auth.claimIdentifier`.
 * - Timestamps are `datetime({ mode: "date", fsp: 3 })`: millisecond precision
 *   (matching `Date`), and unlike `TIMESTAMP` not capped at 2038. MySQL stores
 *   no zone; a `Date` is an instant, and the store never reads a wall-clock
 *   field.
 * - Attribute bags are `json().$type<Auth.JsonObject>()`, `NOT NULL`
 *   and — unlike the other two dialects — *without* a default, because MySQL
 *   does not accept a literal `DEFAULT` on a `JSON` column. Every insert this
 *   package performs writes the bag explicitly, so nothing depends on it.
 * - Booleans are `boolean()`, i.e. `tinyint` `0`/`1`.
 * - Identifier values compare byte for byte: `identifiers.value` is
 *   `varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin` ({@link binaryVarchar}),
 *   because MySQL's default collation (`utf8mb4_0900_ai_ci` on MySQL 8) is
 *   case- and accent-insensitive: under it a lookup of `bob@exämple.com` finds
 *   `bob@example.com`'s row, so a reset or sign-in for one address resolves the
 *   other's account (#602). PostgreSQL and SQLite compare bytes already. An
 *   application's own column that holds identifier values (the single-table
 *   store's `users.email`, or a table mapped through `defineSchema`) needs the
 *   same collation.
 *
 * ### Support status
 *
 * MySQL is supported at the type level and by the shared store implementation,
 * but is **not** covered by an integration suite: the test environment has no
 * MySQL server. `MySql.test.ts` pins the table definitions, the emitted DDL and
 * the fact that a `MySqlDatabase` handle satisfies `databaseLayer`; the query
 * behaviour itself is covered by the PostgreSQL (PGlite) and SQLite
 * (better-sqlite3) suites, which exercise the very same store code through the
 * very same seam.
 */

import {
  bigint,
  boolean,
  customType,
  datetime,
  index,
  int,
  json,
  mysqlTable,
  uniqueIndex,
  varchar,
} from "drizzle-orm/mysql-core";
import type * as Auth from "@thomasfosterau/effect-auth";
import { type DdlDialect, renderDdl, renderScript } from "./Ddl.ts";
import { resolveTableNames } from "./internal.ts";
import type { ApiKeyPermissions, TableNames, TokenPurpose } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/** Long enough for a SHA-256 hex digest, a UUID, an email or a URL-ish handle. */
const KEY_LENGTH = 255;

/**
 * The collation identifier values are stored and compared under: binary, so
 * two values are equal only when their bytes are (#602). `utf8mb4_bin` rather
 * than MySQL 8's `utf8mb4_0900_bin` because MariaDB and MySQL 5.7 have it too.
 * It is a `PAD SPACE` collation, so trailing spaces still compare equal; core
 * trims the emails and usernames it stores and treats a returned identifier
 * whose value differs from the one it asked for as a miss, so that never
 * resolves another account.
 */
export const identifierCollation = "utf8mb4_bin";

/**
 * A `varchar` column under {@link identifierCollation}, for a column that holds
 * identifier values: `identifiers.value` here, and an application's own column
 * the stores look identifiers up in (the single-table store's `users.email`, or
 * the value column of a table mapped through `defineSchema`). drizzle-kit
 * emits its SQL type as written:
 * `varchar(<length>) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`.
 *
 * A custom type because drizzle-orm 0.4x's `varchar` has no `collate`; on
 * drizzle-orm 1.0, `varchar(name, { length }).collate("utf8mb4_bin")` declares
 * the same column.
 *
 * @example
 * ```ts
 * const users = mysqlTable("users", {
 *   id: varchar("id", { length: 255 }).primaryKey(),
 *   email: MySql.binaryVarchar("email", { length: 255 }).unique(),
 *   emailVerified: boolean("email_verified").notNull().default(false),
 * });
 * ```
 */
export const binaryVarchar = customType<{
  data: string;
  driverData: string;
  config: { readonly length: number };
  configRequired: true;
}>({
  dataType: (config) =>
    `varchar(${config.length}) CHARACTER SET utf8mb4 COLLATE ${identifierCollation}`,
});

const sessionColumns = () => ({
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  userId: varchar("user_id", { length: KEY_LENGTH }).notNull(),
  expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
  lastActivityAt: datetime("last_activity_at", { mode: "date", fsp: 3 }).notNull(),
  attributes: json("attributes").$type<Auth.JsonObject>().notNull(),
});

const userColumns = () => ({
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  name: varchar("name", { length: KEY_LENGTH }),
  image: varchar("image", { length: 2048 }),
  passwordHash: varchar("password_hash", { length: 512 }),
  attributes: json("attributes").$type<Auth.JsonObject>().notNull(),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
  updatedAt: datetime("updated_at", { mode: "date", fsp: 3 }).notNull(),
});

const identifierColumns = () => ({
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  userId: varchar("user_id", { length: KEY_LENGTH }).notNull(),
  type: varchar("type", { length: 32 }).$type<Auth.IdentifierType>().notNull(),
  value: binaryVarchar("value", { length: KEY_LENGTH }).notNull(),
  verified: boolean("verified").notNull().default(false),
  verifiedAt: datetime("verified_at", { mode: "date", fsp: 3 }),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
});

/** A `datetime(3)` read back as a `Date`. */
const instant = (name: string) => datetime(name, { mode: "date", fsp: 3 });

/** A key column: long enough for a SHA-256 hex digest, a UUID or an email. */
const key = (name: string) => varchar(name, { length: KEY_LENGTH });

const apiKeyColumns = () => ({
  id: key("id").primaryKey(),
  userId: key("user_id").notNull(),
  name: key("name"),
  prefix: varchar("prefix", { length: 64 }),
  start: varchar("start", { length: 64 }).notNull(),
  /** SHA-256 hex digest of the full key — never the key itself. */
  keyHash: key("key_hash").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  expiresAt: instant("expires_at"),
  lastUsedAt: instant("last_used_at"),
  permissions: json("permissions").$type<ApiKeyPermissions>(),
  metadata: json("metadata").$type<Auth.JsonObject>().notNull(),
  remaining: int("remaining"),
  refillAmount: int("refill_amount"),
  refillInterval: bigint("refill_interval", { mode: "number" }),
  refillMax: int("refill_max"),
  lastRefillAt: instant("last_refill_at"),
  rateLimitMaxRequests: int("rate_limit_max_requests"),
  rateLimitWindowMs: bigint("rate_limit_window_ms", { mode: "number" }),
  createdAt: instant("created_at").notNull(),
  updatedAt: instant("updated_at").notNull(),
});

const rateLimitColumns = () => ({
  key: key("key").primaryKey(),
  count: int("count").notNull(),
  resetAt: instant("reset_at").notNull(),
  blockedUntil: instant("blocked_until"),
});

const tokenColumns = () => ({
  /** SHA-256 hex digest of the token — never the token itself. */
  token: key("token").primaryKey(),
  purpose: varchar("purpose", { length: 32 }).$type<TokenPurpose>().notNull(),
  userId: key("user_id").notNull(),
  email: key("email").notNull(),
  createdAt: instant("created_at").notNull(),
  expiresAt: instant("expires_at").notNull(),
});

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Build the MySQL auth tables under the given names. Omitted names fall
 * back to `defaultTableNames`.
 *
 * @example
 * ```ts
 * const tables = MySql.defineTables({ sessions: "app_sessions" });
 * const stores = layer(tables);
 * ```
 */
export const defineTables = (names?: Partial<TableNames>) => {
  const resolved = resolveTableNames(names);
  return {
    sessions: mysqlTable(resolved.sessions, sessionColumns(), (table) => [
      index(`${resolved.sessions}_user_id_idx`).on(table.userId),
    ]),
    users: mysqlTable(resolved.users, userColumns()),
    identifiers: mysqlTable(resolved.identifiers, identifierColumns(), (table) => [
      uniqueIndex(`${resolved.identifiers}_type_value_key`).on(table.type, table.value),
      index(`${resolved.identifiers}_user_id_idx`).on(table.userId),
    ]),
    apiKeys: mysqlTable(resolved.apiKeys, apiKeyColumns(), (table) => [
      uniqueIndex(`${resolved.apiKeys}_key_hash_key`).on(table.keyHash),
      index(`${resolved.apiKeys}_user_id_idx`).on(table.userId),
    ]),
    rateLimits: mysqlTable(resolved.rateLimits, rateLimitColumns()),
    tokens: mysqlTable(resolved.tokens, tokenColumns(), (table) => [
      index(`${resolved.tokens}_purpose_user_id_idx`).on(table.purpose, table.userId),
    ]),
  };
};

/** The MySQL member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The MySQL tables under their default `effect_auth_*` names. */
export const tables: Tables = defineTables();

/** `effect_auth_sessions` — session records keyed by token hash. */
export const sessionsTable = tables.sessions;
/** `effect_auth_users` — user records; login handles live in identifiers. */
export const usersTable = tables.users;
/** `effect_auth_identifiers` — email/username/phone claims, unique per `(type, value)`. */
export const identifiersTable = tables.identifiers;
/** `effect_auth_api_keys` — API keys by SHA-256 digest, unique per digest. */
export const apiKeysTable = tables.apiKeys;
/** `effect_auth_rate_limits` — one fixed-window counter per rate-limit key. */
export const rateLimitsTable = tables.rateLimits;
/** `effect_auth_tokens` — pending email-verification and password-reset tokens, by digest. */
export const tokensTable = tables.tokens;

/** Row shapes selected from each MySQL table. */
export type SessionRow = Tables["sessions"]["$inferSelect"];
/** The row `select()` returns from this dialect's users table. */
export type UserRow = Tables["users"]["$inferSelect"];
/** The row `select()` returns from this dialect's identifiers table. */
export type IdentifierRow = Tables["identifiers"]["$inferSelect"];

// ---------------------------------------------------------------------------
// SQL migration
// ---------------------------------------------------------------------------

/** How this dialect spells the shared DDL spec (`Ddl.ts`). */
const dialect: DdlDialect = {
  types: {
    key: "VARCHAR(255)",
    image: "VARCHAR(2048)",
    password: "VARCHAR(512)",
    tag: "VARCHAR(32)",
    short: "VARCHAR(64)",
    identifierValue: `VARCHAR(255) CHARACTER SET utf8mb4 COLLATE ${identifierCollation}`,
    instant: "DATETIME(3)",
    json: "JSON",
    boolean: "TINYINT",
    integer: "INT",
    bigint: "BIGINT",
  },
  primaryKey: " NOT NULL PRIMARY KEY",
  // MySQL takes no literal DEFAULT on a JSON column; every insert writes the bag.
  defaults: { emptyObject: undefined, true: "1", false: "0" },
  // `key` is reserved.
  quote: (name) => (name === "key" ? `\`${name}\`` : name),
  inlineIndexes: true,
};

/**
 * The DDL equivalent of {@link defineTables}, one statement per entry, in
 * dependency order.
 *
 * One statement per table, where the other dialects add one per index: MySQL has no
 * `CREATE INDEX IF NOT EXISTS`, so the indexes are declared inside their
 * `CREATE TABLE IF NOT EXISTS`, which keeps the whole script replayable on
 * every deploy.
 *
 * `identifiers.value` is declared under {@link identifierCollation}.
 */
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> =>
  renderDdl(dialect, names);

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  renderScript(migrationStatements(names));
