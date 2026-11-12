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
  boolean,
  customType,
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
/** The row `select()` returns from this dialect's users table. */
export type UserRow = Tables["users"]["$inferSelect"];
/** The row `select()` returns from this dialect's identifiers table. */
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
 *
 * `identifiers.value` is declared under {@link identifierCollation}. Being
 * `IF NOT EXISTS`, the script never changes a table that already exists: an
 * identifiers table created before #602 keeps the server's default collation
 * until {@link collationMigrationStatements} has run once.
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
  value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  verified TINYINT NOT NULL DEFAULT 0,
  verified_at DATETIME(3),
  created_at DATETIME(3) NOT NULL,
  UNIQUE KEY ${t.identifiers}_type_value_key (type, value),
  KEY ${t.identifiers}_user_id_idx (user_id)
)`,
  ];
};

/**
 * The one-off migration for an identifiers table created before #602, whose
 * `value` column has the server's default collation: it converts the column to
 * {@link identifierCollation}. Running it again changes nothing, but each run
 * rebuilds the table, so it is not part of {@link migrationStatements}.
 *
 * The old case- and accent-insensitive unique key refused any two values that
 * compared equal under it, so no two existing rows collide under the binary
 * collation and the conversion cannot fail on them.
 *
 * @example
 * ```ts
 * for (const statement of MySql.collationMigrationStatements()) {
 *   await db.execute(sql.raw(statement));
 * }
 * ```
 */
export const collationMigrationStatements = (
  names?: Partial<TableNames>,
): ReadonlyArray<string> => {
  const t = resolveTableNames(names);
  return [
    `ALTER TABLE ${t.identifiers} MODIFY value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL`,
  ];
};

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  `${migrationStatements(names).join(";\n\n")};\n`;
