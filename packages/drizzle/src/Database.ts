/**
 * The service seam between effect-auth's stores and a Drizzle PostgreSQL
 * database handle.
 *
 * This package never opens a connection of its own: the application builds a
 * drizzle handle with whichever PostgreSQL driver it already uses
 * (`node-postgres`, `postgres.js`, Neon, PGlite, ...) and hands it over as the
 * {@link DrizzleDatabase} service.
 *
 * @example
 * ```ts
 * import { Layer } from "effect";
 * import { drizzle } from "drizzle-orm/node-postgres";
 * import { Pool } from "pg";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * const db = drizzle(new Pool({ connectionString: process.env["DATABASE_URL"] }));
 * const stores = Drizzle.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
 * ```
 */

import { Context, Layer } from "effect";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";

/**
 * Any drizzle PostgreSQL database handle, regardless of driver or relational
 * schema. Every `drizzle(...)` handle from a `drizzle-orm` PostgreSQL driver
 * (`node-postgres`, `postgres-js`, `neon-http`, `pglite`, ...) is assignable
 * to this type, as is a transaction handle passed to `db.transaction(...)`.
 */
// The two schema type parameters are deliberately unconstrained: the stores
// address tables directly and never use drizzle's relational query API, so a
// caller's schema shape is irrelevant here (and pinning it would reject every
// concrete driver handle).
export type DrizzlePgDatabase = PgDatabase<PgQueryResultHKT, any, any>;

/**
 * Tag for the drizzle database handle the stores read out of context.
 *
 * Provide it with {@link databaseLayer}, or directly with
 * `Layer.succeed(DrizzleDatabase, drizzle(pool))`.
 */
export class DrizzleDatabase extends Context.Service<DrizzleDatabase, DrizzlePgDatabase>()(
  "@effect-auth/DrizzleDatabase",
) {}

/** Provide an already-constructed drizzle handle as {@link DrizzleDatabase}. */
export const databaseLayer = (db: DrizzlePgDatabase): Layer.Layer<DrizzleDatabase> =>
  Layer.succeed(DrizzleDatabase, db);
