/**
 * `@thomasfosterau/effect-auth/sql` — driver-agnostic SQL storage layers for
 * effect-auth.
 *
 * Built on `effect/sql`'s `SqlClient`, which ships in `effect` itself, so the
 * subpath adds no dependency: it works with any `SqlClient` layer for a
 * supported dialect (SQLite, Cloudflare D1 and PostgreSQL). MySQL is not
 * supported (#260); the package README lists the dialects and the drizzle
 * alternative for MySQL. The root barrel does not re-export it.
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
