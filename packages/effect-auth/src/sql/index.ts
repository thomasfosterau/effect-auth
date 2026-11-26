/**
 * `@thomasfosterau/effect-auth/sql`: storage layers over `effect/sql`'s
 * `SqlClient` for SQLite, D1 and PostgreSQL, adding no dependency. MySQL is not
 * supported. The root barrel does not re-export it.
 *
 * @example
 * ```ts skip-type-checking
 * import { Effect, Layer } from "effect";
 * import * as Sql from "@thomasfosterau/effect-auth/sql";
 *
 * // SqlClientLayer: any Layer providing SqlClient.SqlClient
 * const stores = Sql.layer.pipe(Layer.provide(SqlClientLayer));
 * const setup = Sql.migrate.pipe(Effect.provide(SqlClientLayer));
 * ```
 */

export * from "./Schema.ts";
export * from "./Stores.ts";
export * from "./ReadScope.ts";
