/**
 * `@thomasfosterau/effect-auth-sql` — driver-agnostic SQL storage layers for
 * effect-auth.
 *
 * Built on `effect/sql`'s `SqlClient`, so it works with any
 * `SqlClient` layer (pg, mysql, sqlite, Cloudflare D1, ...).
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect";
 * import * as Sql from "@thomasfosterau/effect-auth-sql";
 *
 * // SqlClientLayer: any Layer providing SqlClient.SqlClient
 * const stores = Sql.layer.pipe(Layer.provide(SqlClientLayer));
 * const setup = Sql.migrate.pipe(Effect.provide(SqlClientLayer));
 * ```
 */

export * from "./Schema.ts";
export * from "./Stores.ts";
