/**
 * `@thomasfosterau/effect-auth-sql` — driver-agnostic SQL storage layers for
 * effect-auth.
 *
 * Built on `effect/sql`'s `SqlClient`, so it works with any `SqlClient`
 * layer for a supported dialect: SQLite, Cloudflare D1 and PostgreSQL. MySQL
 * is not supported (#260); the package README lists the dialects and the
 * drizzle alternative for MySQL.
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
export * from "./ReadScope.ts";
