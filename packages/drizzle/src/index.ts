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
 * - `Requests` — the batched read interface (`Requests.layer`, `Requests.getUser`, ...).
 * - `Pg` / `Sqlite` / `MySql` — one dialect's tables and DDL each
 *   (`defineTables`, `tables`, `sessionsTable`, `migrationStatements`, ...).
 * - `layer` — the aggregate of all three stores.
 * - `DrizzleDatabase` / `databaseLayer` / `AuthDatabase` — the database seam.
 * - `TableNames` / `defaultTableNames` / `Tables` and the row types — what the
 *   three dialects agree on.
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
 * ```
 */

export * from "./Database.ts";
export * from "./Schema.ts";
export { layer } from "./Layers.ts";

export * as IdentifierStore from "./IdentifierStore.ts";
export * as MySql from "./MySqlSchema.ts";
export * as Pg from "./PgSchema.ts";
export * as Requests from "./Requests.ts";
export * as SessionStore from "./SessionStore.ts";
export * as Sqlite from "./SqliteSchema.ts";
export * as UserStore from "./UserStore.ts";
