/**
 * Drizzle `pg-core` table definitions backing the effect-auth stores.
 *
 * Three tables cover the surface this package implements — sessions, users and
 * identifiers — namespaced with an `effect_auth_` prefix so they can live beside
 * an application's own tables. The exported table objects are ordinary drizzle
 * schema objects: feed them to `drizzle-kit` (or any migration tool) exactly as
 * you would your own.
 *
 * ### Column conventions
 *
 * - Timestamps are `timestamp({ mode: "date", withTimezone: true })`, so the
 *   domain sees real `Date` values and PostgreSQL stores `timestamptz`.
 * - Attribute bags are `jsonb().$type<Record<string, unknown>>()`, `NOT NULL`
 *   with a `'{}'` default — the driver round-trips them as plain objects, no
 *   `JSON.parse` in the store layer.
 * - Identifiers are unique on `(type, value)`; that index is the real claim
 *   mechanism behind `Auth.claimIdentifier`.
 *
 * ### Custom table names
 *
 * {@link defineTables} builds the same three tables under names you choose;
 * pass the result to any store factory. {@link migrationStatements} emits DDL
 * for whichever names you used.
 */

import { boolean, index, jsonb, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import type * as Auth from "@thomasfosterau/effect-auth";
import { resolveTableNames } from "./internal.ts";
import type { TableNames } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Columns
//
// Each column set is built by a function rather than shared as a value:
// drizzle column builders are consumed (and named) by `pgTable`, so a fresh
// set per table keeps `defineTables` re-entrant.
// ---------------------------------------------------------------------------

const sessionColumns = () => ({
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  lastActivityAt: timestamp("last_activity_at", { mode: "date", withTimezone: true }).notNull(),
  attributes: jsonb("attributes").$type<Record<string, unknown>>().notNull().default({}),
});

const userColumns = () => ({
  id: text("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  passwordHash: text("password_hash"),
  attributes: jsonb("attributes").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

const identifierColumns = () => ({
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  type: text("type").$type<Auth.IdentifierType>().notNull(),
  value: text("value").notNull(),
  verified: boolean("verified").notNull().default(false),
  verifiedAt: timestamp("verified_at", { mode: "date", withTimezone: true }),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Build the three PostgreSQL auth tables under the given names. Omitted names
 * fall back to `defaultTableNames`.
 *
 * @example
 * ```ts
 * const tables = Pg.defineTables({ sessions: "app_sessions" });
 * const stores = layer(tables);
 * ```
 */
export const defineTables = (names?: Partial<TableNames>) => {
  const resolved = resolveTableNames(names);
  return {
    sessions: pgTable(resolved.sessions, sessionColumns(), (table) => [
      index(`${resolved.sessions}_user_id_idx`).on(table.userId),
    ]),
    users: pgTable(resolved.users, userColumns()),
    identifiers: pgTable(resolved.identifiers, identifierColumns(), (table) => [
      uniqueIndex(`${resolved.identifiers}_type_value_key`).on(table.type, table.value),
      index(`${resolved.identifiers}_user_id_idx`).on(table.userId),
    ]),
  };
};

/** The PostgreSQL member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The three PostgreSQL tables under their default `effect_auth_*` names. */
export const tables: Tables = defineTables();

/** `effect_auth_sessions` — session records keyed by token hash. */
export const sessionsTable = tables.sessions;
/** `effect_auth_users` — user records; login handles live in identifiers. */
export const usersTable = tables.users;
/** `effect_auth_identifiers` — email/username/phone claims, unique per `(type, value)`. */
export const identifiersTable = tables.identifiers;

/** Row shapes selected from each PostgreSQL table. */
export type SessionRow = Tables["sessions"]["$inferSelect"];
export type UserRow = Tables["users"]["$inferSelect"];
export type IdentifierRow = Tables["identifiers"]["$inferSelect"];

// ---------------------------------------------------------------------------
// SQL migration
// ---------------------------------------------------------------------------

/**
 * The DDL equivalent of {@link defineTables}, one statement per entry, in
 * dependency order. Every statement is idempotent (`IF NOT EXISTS`) so it is
 * safe to replay on each deploy.
 *
 * Use this when you do not run `drizzle-kit` — hand the statements to your own
 * migration runner, or paste {@link migrationSql} into a `.sql` file.
 */
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> => {
  const t = resolveTableNames(names);
  return [
    `CREATE TABLE IF NOT EXISTS ${t.users} (
  id TEXT PRIMARY KEY,
  name TEXT,
  image TEXT,
  password_hash TEXT,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
)`,
    `CREATE TABLE IF NOT EXISTS ${t.sessions} (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb
)`,
    `CREATE INDEX IF NOT EXISTS ${t.sessions}_user_id_idx ON ${t.sessions} (user_id)`,
    `CREATE TABLE IF NOT EXISTS ${t.identifiers} (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${t.identifiers}_type_value_key ON ${t.identifiers} (type, value)`,
    `CREATE INDEX IF NOT EXISTS ${t.identifiers}_user_id_idx ON ${t.identifiers} (user_id)`,
  ];
};

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  `${migrationStatements(names).join(";\n\n")};\n`;
