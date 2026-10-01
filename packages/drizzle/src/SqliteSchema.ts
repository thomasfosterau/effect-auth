/**
 * Drizzle `sqlite-core` table definitions backing the effect-auth stores.
 *
 * The same three tables as `Pg`, under the same names, with the same column
 * names — only the physical types change, because SQLite has neither a date
 * type, a boolean type, nor a JSON type.
 *
 * ### Column conventions
 *
 * - Timestamps are `integer({ mode: "timestamp_ms" })`: epoch milliseconds on
 *   disk, real `Date` values in the domain, so no precision is lost relative to
 *   PostgreSQL's `timestamptz`. (Time zone is not stored — a `Date` is an
 *   instant, and the store never reads a wall-clock field.)
 * - Attribute bags are `text({ mode: "json" }).$type<Record<string, unknown>>()`,
 *   `NOT NULL` with a `'{}'` default: drizzle serializes on write and parses on
 *   read, so the store layer still sees plain objects.
 * - Booleans are `integer({ mode: "boolean" })` — `0`/`1` on disk, `boolean` in
 *   the domain.
 * - Identifiers are unique on `(type, value)`; that index is the real claim
 *   mechanism behind `Auth.claimIdentifier`.
 *
 * Works with every drizzle SQLite driver — `better-sqlite3`, `libsql`,
 * `bun:sqlite`, D1, Expo, op-sqlite — synchronous or asynchronous.
 */

import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import type * as Auth from "@thomasfosterau/effect-auth";
import { resolveTableNames } from "./internal.ts";
import type { TableNames } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

const sessionColumns = () => ({
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  lastActivityAt: integer("last_activity_at", { mode: "timestamp_ms" }).notNull(),
  attributes: text("attributes", { mode: "json" })
    .$type<Record<string, unknown>>()
    .notNull()
    .default({}),
});

const userColumns = () => ({
  id: text("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  passwordHash: text("password_hash"),
  attributes: text("attributes", { mode: "json" })
    .$type<Record<string, unknown>>()
    .notNull()
    .default({}),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

const identifierColumns = () => ({
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  type: text("type").$type<Auth.IdentifierType>().notNull(),
  value: text("value").notNull(),
  verified: integer("verified", { mode: "boolean" }).notNull().default(false),
  verifiedAt: integer("verified_at", { mode: "timestamp_ms" }),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Build the three SQLite auth tables under the given names. Omitted names fall
 * back to `defaultTableNames`.
 *
 * @example
 * ```ts
 * const tables = Sqlite.defineTables({ sessions: "app_sessions" });
 * const stores = layer(tables);
 * ```
 */
export const defineTables = (names?: Partial<TableNames>) => {
  const resolved = resolveTableNames(names);
  return {
    sessions: sqliteTable(resolved.sessions, sessionColumns(), (table) => [
      index(`${resolved.sessions}_user_id_idx`).on(table.userId),
    ]),
    users: sqliteTable(resolved.users, userColumns()),
    identifiers: sqliteTable(resolved.identifiers, identifierColumns(), (table) => [
      uniqueIndex(`${resolved.identifiers}_type_value_key`).on(table.type, table.value),
      index(`${resolved.identifiers}_user_id_idx`).on(table.userId),
    ]),
  };
};

/** The SQLite member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The three SQLite tables under their default `effect_auth_*` names. */
export const tables: Tables = defineTables();

/** `effect_auth_sessions` — session records keyed by token hash. */
export const sessionsTable = tables.sessions;
/** `effect_auth_users` — user records; login handles live in identifiers. */
export const usersTable = tables.users;
/** `effect_auth_identifiers` — email/username/phone claims, unique per `(type, value)`. */
export const identifiersTable = tables.identifiers;

/** Row shapes selected from each SQLite table. */
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
 * dependency order. Every statement is idempotent (`IF NOT EXISTS`), so it is
 * safe to replay on each deploy.
 */
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> => {
  const t = resolveTableNames(names);
  return [
    `CREATE TABLE IF NOT EXISTS ${t.users} (
  id TEXT PRIMARY KEY,
  name TEXT,
  image TEXT,
  password_hash TEXT,
  attributes TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
)`,
    `CREATE TABLE IF NOT EXISTS ${t.sessions} (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  attributes TEXT NOT NULL DEFAULT '{}'
)`,
    `CREATE INDEX IF NOT EXISTS ${t.sessions}_user_id_idx ON ${t.sessions} (user_id)`,
    `CREATE TABLE IF NOT EXISTS ${t.identifiers} (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verified_at INTEGER,
  created_at INTEGER NOT NULL
)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${t.identifiers}_type_value_key ON ${t.identifiers} (type, value)`,
    `CREATE INDEX IF NOT EXISTS ${t.identifiers}_user_id_idx ON ${t.identifiers} (user_id)`,
  ];
};

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  `${migrationStatements(names).join(";\n\n")};\n`;
