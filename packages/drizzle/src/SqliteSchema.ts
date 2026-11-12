/**
 * Drizzle `sqlite-core` table definitions backing the effect-auth stores.
 *
 * The same tables as `Pg`, under the same names, with the same column
 * names — only the physical types change, because SQLite has neither a date
 * type, a boolean type, nor a JSON type.
 *
 * ### Column conventions
 *
 * - Timestamps are `integer({ mode: "timestamp_ms" })`: epoch milliseconds on
 *   disk, real `Date` values in the domain, so no precision is lost relative to
 *   PostgreSQL's `timestamptz`. (Time zone is not stored — a `Date` is an
 *   instant, and the store never reads a wall-clock field.)
 * - Attribute bags are `text({ mode: "json" }).$type<Auth.JsonObject>()`,
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
import { sqliteDialect, renderDdl, renderScript } from "./Ddl.ts";
import { resolveTableNames } from "./internal.ts";
import type { ApiKeyPermissions, TableNames, TokenPurpose } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/** The JSON attribute bag, `{}` when unset. */
const attributesColumn = () =>
  text("attributes", { mode: "json" }).$type<Auth.JsonObject>().notNull().default({});

const sessionColumns = () => ({
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  lastActivityAt: integer("last_activity_at", { mode: "timestamp_ms" }).notNull(),
  attributes: attributesColumn(),
});

const userColumns = () => ({
  id: text("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  passwordHash: text("password_hash"),
  attributes: attributesColumn(),
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

/** An epoch-milliseconds `integer` read back as a `Date`. */
const instant = (name: string) => integer(name, { mode: "timestamp_ms" });

const apiKeyColumns = () => ({
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  name: text("name"),
  prefix: text("prefix"),
  start: text("start").notNull(),
  /** SHA-256 hex digest of the full key — never the key itself. */
  keyHash: text("key_hash").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  expiresAt: instant("expires_at"),
  lastUsedAt: instant("last_used_at"),
  permissions: text("permissions", { mode: "json" }).$type<ApiKeyPermissions>(),
  metadata: text("metadata", { mode: "json" }).$type<Auth.JsonObject>().notNull().default({}),
  remaining: integer("remaining"),
  refillAmount: integer("refill_amount"),
  refillInterval: integer("refill_interval"),
  refillMax: integer("refill_max"),
  lastRefillAt: instant("last_refill_at"),
  rateLimitMaxRequests: integer("rate_limit_max_requests"),
  rateLimitWindowMs: integer("rate_limit_window_ms"),
  createdAt: instant("created_at").notNull(),
  updatedAt: instant("updated_at").notNull(),
});

const rateLimitColumns = () => ({
  key: text("key").primaryKey(),
  count: integer("count").notNull(),
  resetAt: instant("reset_at").notNull(),
  blockedUntil: instant("blocked_until"),
});

const tokenColumns = () => ({
  /** SHA-256 hex digest of the token — never the token itself. */
  token: text("token").primaryKey(),
  purpose: text("purpose").$type<TokenPurpose>().notNull(),
  userId: text("user_id").notNull(),
  email: text("email").notNull(),
  createdAt: instant("created_at").notNull(),
  expiresAt: instant("expires_at").notNull(),
});

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Build the SQLite auth tables under the given names. Omitted names fall
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
    apiKeys: sqliteTable(resolved.apiKeys, apiKeyColumns(), (table) => [
      uniqueIndex(`${resolved.apiKeys}_key_hash_key`).on(table.keyHash),
      index(`${resolved.apiKeys}_user_id_idx`).on(table.userId),
    ]),
    rateLimits: sqliteTable(resolved.rateLimits, rateLimitColumns()),
    tokens: sqliteTable(resolved.tokens, tokenColumns(), (table) => [
      index(`${resolved.tokens}_purpose_user_id_idx`).on(table.purpose, table.userId),
    ]),
  };
};

/** The SQLite member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The SQLite tables under their default `effect_auth_*` names. */
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
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> =>
  renderDdl(sqliteDialect, names);

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  renderScript(migrationStatements(names));
