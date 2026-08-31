/**
 * Drizzle `mysql-core` table definitions backing the effect-auth stores.
 *
 * The same three tables as `Pg`, under the same names, with the same column
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
 * - Attribute bags are `json().$type<Record<string, unknown>>()`, `NOT NULL`
 *   and — unlike the other two dialects — *without* a default, because MySQL
 *   does not accept a literal `DEFAULT` on a `JSON` column. Every insert this
 *   package performs writes the bag explicitly, so nothing depends on it.
 * - Booleans are `boolean()`, i.e. `tinyint` `0`/`1`.
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
  boolean,
  datetime,
  index,
  json,
  mysqlTable,
  uniqueIndex,
  varchar,
} from "drizzle-orm/mysql-core";
import type * as Auth from "@thomasfosterau/effect-auth";
import { resolveTableNames } from "./internal.ts";
import type { TableNames } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/** Long enough for a SHA-256 hex digest, a UUID, an email or a URL-ish handle. */
const KEY_LENGTH = 255;

const sessionColumns = () => ({
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  userId: varchar("user_id", { length: KEY_LENGTH }).notNull(),
  expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
  lastActivityAt: datetime("last_activity_at", { mode: "date", fsp: 3 }).notNull(),
  attributes: json("attributes").$type<Record<string, unknown>>().notNull(),
});

const userColumns = () => ({
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  name: varchar("name", { length: KEY_LENGTH }),
  image: varchar("image", { length: 2048 }),
  passwordHash: varchar("password_hash", { length: 512 }),
  attributes: json("attributes").$type<Record<string, unknown>>().notNull(),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
  updatedAt: datetime("updated_at", { mode: "date", fsp: 3 }).notNull(),
});

const identifierColumns = () => ({
  id: varchar("id", { length: KEY_LENGTH }).primaryKey(),
  userId: varchar("user_id", { length: KEY_LENGTH }).notNull(),
  type: varchar("type", { length: 32 }).$type<Auth.IdentifierType>().notNull(),
  value: varchar("value", { length: KEY_LENGTH }).notNull(),
  verified: boolean("verified").notNull().default(false),
  verifiedAt: datetime("verified_at", { mode: "date", fsp: 3 }),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
});

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Build the three MySQL auth tables under the given names. Omitted names fall
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
  };
};

/** The MySQL member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The three MySQL tables under their default `effect_auth_*` names. */
export const tables: Tables = defineTables();

/** `effect_auth_sessions` — session records keyed by token hash. */
export const sessionsTable = tables.sessions;
/** `effect_auth_users` — user records; login handles live in identifiers. */
export const usersTable = tables.users;
/** `effect_auth_identifiers` — email/username/phone claims, unique per `(type, value)`. */
export const identifiersTable = tables.identifiers;

/** Row shapes selected from each MySQL table. */
export type SessionRow = Tables["sessions"]["$inferSelect"];
export type UserRow = Tables["users"]["$inferSelect"];
export type IdentifierRow = Tables["identifiers"]["$inferSelect"];

// ---------------------------------------------------------------------------
// SQL migration
// ---------------------------------------------------------------------------

/**
 * The DDL equivalent of {@link defineTables}, one statement per entry, in
 * dependency order.
 *
 * Three statements rather than the six the other dialects emit: MySQL has no
 * `CREATE INDEX IF NOT EXISTS`, so the indexes are declared inside their
 * `CREATE TABLE IF NOT EXISTS`, which keeps the whole script replayable on
 * every deploy.
 */
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> => {
  const t = resolveTableNames(names);
  return [
    `CREATE TABLE IF NOT EXISTS ${t.users} (
  id VARCHAR(255) NOT NULL PRIMARY KEY,
  name VARCHAR(255),
  image VARCHAR(2048),
  password_hash VARCHAR(512),
  attributes JSON NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL
)`,
    `CREATE TABLE IF NOT EXISTS ${t.sessions} (
  id VARCHAR(255) NOT NULL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  last_activity_at DATETIME(3) NOT NULL,
  attributes JSON NOT NULL,
  KEY ${t.sessions}_user_id_idx (user_id)
)`,
    `CREATE TABLE IF NOT EXISTS ${t.identifiers} (
  id VARCHAR(255) NOT NULL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL,
  value VARCHAR(255) NOT NULL,
  verified TINYINT NOT NULL DEFAULT 0,
  verified_at DATETIME(3),
  created_at DATETIME(3) NOT NULL,
  UNIQUE KEY ${t.identifiers}_type_value_key (type, value),
  KEY ${t.identifiers}_user_id_idx (user_id)
)`,
  ];
};

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  `${migrationStatements(names).join(";\n\n")};\n`;
