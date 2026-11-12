/**
 * Drizzle `pg-core` table definitions backing the effect-auth stores.
 *
 * Six tables cover the surface this package implements — sessions, users,
 * identifiers, API keys, rate limits and one-time tokens — namespaced with an `effect_auth_` prefix so they can live beside
 * an application's own tables. The exported table objects are ordinary drizzle
 * schema objects: feed them to `drizzle-kit` (or any migration tool) exactly as
 * you would your own.
 *
 * ### Column conventions
 *
 * - Timestamps are `timestamp({ mode: "date", withTimezone: true })`, so the
 *   domain sees real `Date` values and PostgreSQL stores `timestamptz`.
 * - Attribute bags are `jsonb().$type<Auth.JsonObject>()`, `NOT NULL`
 *   with a `'{}'` default — the driver round-trips them as plain objects, no
 *   `JSON.parse` in the store layer.
 * - Identifiers are unique on `(type, value)`; that index is the real claim
 *   mechanism behind `Auth.claimIdentifier`.
 *
 * ### Custom table names
 *
 * {@link defineTables} builds the same tables under names you choose;
 * pass the result to any store factory. {@link migrationStatements} emits DDL
 * for whichever names you used.
 */

import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import type * as Auth from "@thomasfosterau/effect-auth";
import { pgDialect, renderDdl, renderScript } from "./Ddl.ts";
import { resolveTableNames } from "./internal.ts";
import type { ApiKeyPermissions, TableNames, TokenPurpose } from "./Schema.ts";

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
  attributes: jsonb("attributes").$type<Auth.JsonObject>().notNull().default({}),
});

const userColumns = () => ({
  id: text("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  passwordHash: text("password_hash"),
  attributes: jsonb("attributes").$type<Auth.JsonObject>().notNull().default({}),
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

/** A `timestamptz` read back as a `Date`. */
const instant = (name: string) => timestamp(name, { mode: "date", withTimezone: true });

const apiKeyColumns = () => ({
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  name: text("name"),
  prefix: text("prefix"),
  start: text("start").notNull(),
  /** SHA-256 hex digest of the full key — never the key itself. */
  keyHash: text("key_hash").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  expiresAt: instant("expires_at"),
  lastUsedAt: instant("last_used_at"),
  permissions: jsonb("permissions").$type<ApiKeyPermissions>(),
  metadata: jsonb("metadata").$type<Auth.JsonObject>().notNull().default({}),
  remaining: integer("remaining"),
  refillAmount: integer("refill_amount"),
  refillInterval: bigint("refill_interval", { mode: "number" }),
  refillMax: integer("refill_max"),
  lastRefillAt: instant("last_refill_at"),
  rateLimitMaxRequests: integer("rate_limit_max_requests"),
  rateLimitWindowMs: bigint("rate_limit_window_ms", { mode: "number" }),
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
 * Build the PostgreSQL auth tables under the given names. Omitted names
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
    apiKeys: pgTable(resolved.apiKeys, apiKeyColumns(), (table) => [
      uniqueIndex(`${resolved.apiKeys}_key_hash_key`).on(table.keyHash),
      index(`${resolved.apiKeys}_user_id_idx`).on(table.userId),
    ]),
    rateLimits: pgTable(resolved.rateLimits, rateLimitColumns()),
    tokens: pgTable(resolved.tokens, tokenColumns(), (table) => [
      index(`${resolved.tokens}_purpose_user_id_idx`).on(table.purpose, table.userId),
    ]),
  };
};

/** The PostgreSQL member of the shared `Tables` union. */
export type Tables = ReturnType<typeof defineTables>;

/** The PostgreSQL tables under their default `effect_auth_*` names. */
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

/** Row shapes selected from each PostgreSQL table. */
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
 * dependency order. Every statement is idempotent (`IF NOT EXISTS`) so it is
 * safe to replay on each deploy.
 *
 * Use this when you do not run `drizzle-kit` — hand the statements to your own
 * migration runner, or paste {@link migrationSql} into a `.sql` file.
 */
export const migrationStatements = (names?: Partial<TableNames>): ReadonlyArray<string> =>
  renderDdl(pgDialect, names);

/** {@link migrationStatements} joined into a single runnable SQL script. */
export const migrationSql = (names?: Partial<TableNames>): string =>
  renderScript(migrationStatements(names));
