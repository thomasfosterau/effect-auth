/**
 * `@thomasfosterau/effect-auth-drizzle` — PostgreSQL storage layers for
 * effect-auth, built on Drizzle ORM's `drizzle-orm/pg-core`.
 *
 * Implements `SessionStore`, `UserStore` and `IdentifierStore` — the three
 * stores every sign-in flow touches — against drizzle table objects you can
 * hand straight to `drizzle-kit`.
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
 * const custom = Drizzle.defineTables({ sessions: "app_sessions" });
 * const customStores = Drizzle.layer(custom).pipe(Layer.provide(Drizzle.databaseLayer(db)));
 * ```
 */

export * from "./Database.ts";
export * from "./Schema.ts";
export * from "./Stores.ts";
