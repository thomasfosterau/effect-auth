/**
 * `@thomasfosterau/effect-auth-drizzle` — Drizzle ORM storage layers for
 * effect-auth, on PostgreSQL, SQLite or MySQL.
 *
 * Implements `SessionStore`, `UserStore` and `IdentifierStore` — the three
 * stores every sign-in flow touches — against drizzle table objects you can
 * hand straight to `drizzle-kit`. One module per store, plus a batched
 * `Request`/`RequestResolver` read interface for application code.
 *
 * ### The export map
 *
 * Each store is a namespace with the same two entry points, `make` and `layer`:
 *
 * - `SessionStore` / `UserStore` / `IdentifierStore` — the store modules.
 * - `SingleTableIdentifierStore` — the opt-in `IdentifierStore` whose email
 *   identifier is the application's own `users` row (one per user).
 * - `Requests` — the batched read interface (`Requests.layer`, `Requests.getUser`, ...).
 * - `Pg` / `Sqlite` / `MySql` — one dialect's tables and DDL each
 *   (`defineTables`, `tables`, `sessionsTable`, `migrationStatements`, ...).
 * - `layer` — the aggregate of all three stores.
 * - `DrizzleDatabase` / `databaseLayer` / `effectDatabaseLayer` / `AuthDatabase`
 *   — the database seam.
 * - `TableNames` / `defaultTableNames` / `Tables` and the row types — what the
 *   three dialects agree on.
 * - `defineSchema` / `fromTables` / `AuthSchema` and the `*ColumnNames` types —
 *   how to point the stores at tables this package did not define.
 * - `ladderCheck` — a role column's `CHECK`, derived from the app's `Ladder`.
 * - `ownedListFilter` / `isFollowerLayer` — `Auth.OwnedAccess`'s read scope
 *   rendered as a `WHERE`, and its follower seam over an application's own
 *   follow table.
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect";
 * import { drizzle } from "drizzle-orm/node-postgres";
 * import { Pool } from "pg";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const db = drizzle(new Pool({ connectionString: process.env["DATABASE_URL"] }));
 *
 * // All three stores on top of the drizzle handle.
 * const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
 *
 * // Custom table names use the same schema shape.
 * const custom = Drizzle.Pg.defineTables({ sessions: "app_sessions" });
 * const customStores = Drizzle.layer(custom).pipe(Layer.provide(Drizzle.databaseLayer(db)));
 *
 * // Another dialect: the same stores, that dialect's tables.
 * const sqliteStores = Drizzle.layer(Drizzle.Sqlite.tables).pipe(
 *   Layer.provide(Drizzle.databaseLayer(sqliteDb)),
 * );
 *
 * // Batched reads for application code (one query per batch of lookups).
 * const requests = Drizzle.Requests.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
 * const users = Effect.forEach(ids, Drizzle.Requests.getUser, { concurrency: "unbounded" });
 *
 * // A drizzle Effect driver: the stores run its queries directly, no Promise
 * // boundary anywhere between `Auth.SessionStore` and the database.
 * import * as PgDrizzle from "drizzle-orm/effect-postgres";
 * const effectStores = Drizzle.layer().pipe(
 *   Layer.provide(Drizzle.effectDatabaseLayer(PgDrizzle.makeWithDefaults())),
 * );
 *
 * // A handle the application owns the lifetime of: passing an `Effect` instead
 * // of a handle resolves it per query, in the calling request's scope.
 * const perRequest = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(RequestDatabase)));
 *
 * // An application's own tables, under its own column names and key types: the
 * // mapping says where each field the stores need actually lives.
 * const adopted = Drizzle.layer(
 *   Drizzle.defineSchema({
 *     sessions: { table: appSessions, columns: { id: "digest", userId: "account", ... } },
 *     users: { table: appUsers, columns: { id: "key", name: "displayName", ... } },
 *     identifiers: { table: appHandles, columns: { id: "key", type: "kind", ... } },
 *   }),
 * ).pipe(Layer.provide(Drizzle.databaseLayer(db)));
 * ```
 */

export {
  type AuthSchema,
  type AuthSchemaSpec,
  type ColumnKey,
  defineSchema,
  fromTables,
  type IdentifierColumnNames,
  type IdentifierColumns,
  type IdentifierSchema,
  type SchemaInput,
  type SessionColumnNames,
  type SessionColumns,
  type SessionSchema,
  type TableSchema,
  type TableSpec,
  type UserColumnNames,
  type UserColumns,
  type UserSchema,
} from "./Columns.ts";
export * from "./Database.ts";
export * from "./Schema.ts";
export { layer } from "./Layers.ts";
export { ladderCheck } from "./LadderCheck.ts";
export { isFollowerLayer, ownedListFilter, type OwnedColumns } from "./OwnedListFilter.ts";

export * as IdentifierStore from "./IdentifierStore.ts";
export * as MySql from "./MySqlSchema.ts";
export * as Pg from "./PgSchema.ts";
export * as Requests from "./Requests.ts";
export * as SessionStore from "./SessionStore.ts";
export * as SingleTableIdentifierStore from "./SingleTableIdentifierStore.ts";
export * as Sqlite from "./SqliteSchema.ts";
export * as UserStore from "./UserStore.ts";
