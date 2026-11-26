/**
 * Postgres for effect-auth on Alchemy: a `SqlClient` over a Hyperdrive binding
 * or any Postgres URL, the `@thomasfosterau/effect-auth/sql` stores over it
 * ({@link layer}), and the {@link database} target `AuthSchemaProvider`
 * reconciles on deploy. On Workers, `@effect/sql-pg` needs `nodejs_compat`.
 *
 * @example At runtime, over Hyperdrive
 * ```ts skip-type-checking
 * import * as Postgres from "@thomasfosterau/effect-auth-alchemy-postgres";
 *
 * const AppLayer = Auth.layer.pipe(Layer.provide(Postgres.layer(env.HYPERDRIVE)));
 * ```
 *
 * @example On deploy, by URL
 * ```ts skip-type-checking
 * AuthSchemaProvider({ database: Postgres.database(Redacted.make(process.env.DATABASE_URL)) });
 * ```
 *
 * @module effect-auth-alchemy-postgres
 */

import { Effect, Layer, Redacted } from "effect";
import type { SqlClient, SqlError } from "effect/sql";
import * as PgClient from "@effect/sql-pg/PgClient";
import * as Sql from "@thomasfosterau/effect-auth/sql";
import type * as Auth from "@thomasfosterau/effect-auth";
import { postgresDatabase, type PostgresDatabase } from "./AuthSchema.ts";

/** Every effect-auth store `@thomasfosterau/effect-auth/sql` implements. */
export type AuthStores = Layer.Success<typeof Sql.layer>;

/**
 * A Cloudflare Hyperdrive binding, typed structurally. effect-auth reads only
 * its connection string. `@cloudflare/workers-types`' `Hyperdrive` satisfies
 * this type, so no Cloudflare types package is a dependency.
 */
export interface Hyperdrive {
  readonly connectionString: string;
}

/** Where to connect: a Hyperdrive binding, or a Postgres URL. */
export type Source = Hyperdrive | Redacted.Redacted;

/** `@effect/sql-pg` pool settings. The connection itself comes from the {@link Source}. */
export type ClientOptions = Omit<PgClient.PgPoolConfig, "url">;

const urlOf = (source: Source): Redacted.Redacted =>
  Redacted.isRedacted(source) ? source : Redacted.make(source.connectionString);

/**
 * The `SqlClient` for a Hyperdrive binding or a Postgres URL, as a layer.
 * The options are `@effect/sql-pg`'s pool settings.
 */
export const clientLayer = (
  source: Source,
  options: ClientOptions = {},
): Layer.Layer<SqlClient.SqlClient, SqlError.SqlError> =>
  PgClient.layer({ ...options, url: urlOf(source) });

/**
 * Every effect-auth store, backed by Postgres through a Hyperdrive binding
 * (or a URL).
 */
export const layer = (
  source: Source,
  options?: ClientOptions,
): Layer.Layer<AuthStores, SqlError.SqlError> =>
  Sql.layer.pipe(Layer.provide(clientLayer(source, options)));

/**
 * Apply the effect-auth schema to a Postgres database. The DDL is
 * `@thomasfosterau/effect-auth/sql`'s and every statement is `IF NOT EXISTS`. Inside an Alchemy
 * program, declare `AuthSchema` with a {@link database} target instead.
 */
export const migrate = (
  source: Source,
  options?: ClientOptions,
): Effect.Effect<void, Auth.AuthError | SqlError.SqlError> =>
  Sql.migrate.pipe(Effect.provide(clientLayer(source, options)));

/**
 * Delete every expired row through `@thomasfosterau/effect-auth/sql`'s
 * `purgeExpired` (which lists them). Schedule it from a cron trigger.
 */
export const purgeExpired = (
  source: Source,
  options?: ClientOptions,
): Effect.Effect<Sql.PurgeExpiredResult, Auth.AuthError | SqlError.SqlError> =>
  Sql.purgeExpired.pipe(Effect.provide(clientLayer(source, options)));

/**
 * A Postgres database for `AuthSchemaProvider` to reconcile, reached by URL.
 * The provider holds the target as it holds a D1 binding, so a destroy, which
 * runs from persisted state, can still reach the database.
 */
export const database = (url: Redacted.Redacted, options?: ClientOptions): PostgresDatabase =>
  postgresDatabase(clientLayer(url, options));
