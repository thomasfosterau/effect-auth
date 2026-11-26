/**
 * Drizzle ORM stores for effect-auth on PostgreSQL, SQLite or MySQL, one
 * namespace per module. Each store is a namespace with `make` and `layer`, and
 * `Layers.layer` provides them together; `Pg`, `Sqlite` and `MySql` hold each
 * dialect's tables and DDL; `Columns.defineSchema` maps the stores onto an
 * application's tables; `Requests`, `LadderCheck` and `OwnedListFilter`
 * complete it.
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect";
 * import { drizzle } from "drizzle-orm/node-postgres";
 * import { Pool } from "pg";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const db = drizzle({ client: new Pool({ connectionString: process.env["DATABASE_URL"] }) });
 *
 * // All three stores on top of the drizzle handle.
 * const stores = Drizzle.Layers.layer().pipe(Layer.provide(Drizzle.Database.databaseLayer(db)));
 *
 * // Custom table names use the same schema shape.
 * const custom = Drizzle.Pg.defineTables({ sessions: "app_sessions" });
 * const customStores = Drizzle.Layers.layer(custom).pipe(Layer.provide(Drizzle.Database.databaseLayer(db)));
 *
 * // Another dialect: the same stores, that dialect's tables.
 * const sqliteStores = Drizzle.Layers.layer(Drizzle.Sqlite.tables).pipe(
 *   Layer.provide(Drizzle.Database.databaseLayer(sqliteDb)),
 * );
 *
 * // Batched reads for application code (one query per batch of lookups).
 * const requests = Drizzle.Requests.layer().pipe(Layer.provide(Drizzle.Database.databaseLayer(db)));
 * const users = Effect.forEach(ids, Drizzle.Requests.getUser, { concurrency: "unbounded" });
 *
 * // A drizzle Effect driver: the stores run its queries directly, no Promise
 * // boundary anywhere between `Auth.SessionStore` and the database.
 * import * as PgDrizzle from "drizzle-orm/effect-postgres";
 * const effectStores = Drizzle.Layers.layer().pipe(
 *   Layer.provide(Drizzle.Database.effectDatabaseLayer(PgDrizzle.makeWithDefaults())),
 * );
 *
 * // A handle the application owns the lifetime of: passing an `Effect` instead
 * // of a handle resolves it per query, in the calling request's scope.
 * const perRequest = Drizzle.Layers.layer().pipe(Layer.provide(Drizzle.Database.databaseLayer(RequestDatabase)));
 *
 * // An application's own tables, under its own column names and key types: the
 * // mapping says where each field the stores need actually lives.
 * const adopted = Drizzle.Layers.layer(
 *   Drizzle.Columns.defineSchema({
 *     sessions: { table: appSessions, columns: { id: "digest", userId: "account", ... } },
 *     users: { table: appUsers, columns: { id: "key", name: "displayName", ... } },
 *     identifiers: { table: appHandles, columns: { id: "key", type: "kind", ... } },
 *   }),
 * ).pipe(Layer.provide(Drizzle.Database.databaseLayer(db)));
 * ```
 */

export * as ApiKeyStore from "./ApiKeyStore.ts";
export * as Columns from "./Columns.ts";
export * as Database from "./Database.ts";
export * as EmailPasswordStore from "./EmailPasswordStore.ts";
export * as IdentifierStore from "./IdentifierStore.ts";
export * as LadderCheck from "./LadderCheck.ts";
export * as Layers from "./Layers.ts";
export * as MySql from "./MySqlSchema.ts";
export * as OwnedListFilter from "./OwnedListFilter.ts";
export * as Pg from "./PgSchema.ts";
export * as RateLimitStore from "./RateLimitStore.ts";
export * as Requests from "./Requests.ts";
export * as Schema from "./Schema.ts";
export * as SessionStore from "./SessionStore.ts";
export * as SingleTableIdentifierStore from "./SingleTableIdentifierStore.ts";
export * as Sqlite from "./SqliteSchema.ts";
export * as TokenStore from "./TokenStore.ts";
export * as UserServiceStore from "./UserServiceStore.ts";
export * as UserStore from "./UserStore.ts";
