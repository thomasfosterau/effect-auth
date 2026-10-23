/**
 * Postgres for effect-auth on Alchemy. This module provides a `SqlClient` over
 * a Cloudflare Hyperdrive binding (or any Postgres URL), wires the
 * effect-auth-sql stores to it, and supplies the {@link database} target that
 * lets `AuthSchemaProvider` reconcile the schema in Postgres on deploy.
 *
 * It mirrors the package root's D1 wiring, as the separate entry point
 * `@thomasfosterau/effect-auth-alchemy/postgres`. `@effect/sql-pg` is an
 * optional peer that only this entry needs, so a D1 app never installs it.
 *
 * ### At runtime: the Hyperdrive binding
 *
 * A Worker reaches Postgres through Hyperdrive. Its binding carries a
 * `connectionString` that points at Hyperdrive's pooler, and {@link layer}
 * provides every effect-auth store over it:
 *
 * ```ts skip-type-checking
 * import * as Postgres from "@thomasfosterau/effect-auth-alchemy/postgres";
 *
 * const AppLayer = Auth.layer.pipe(Layer.provide(Postgres.layer(env.HYPERDRIVE)));
 * ```
 *
 * `@effect/sql-pg` opens its connections with `node:net` and `node:tls`, so
 * the Worker needs the `nodejs_compat` compatibility flag.
 *
 * ### On deploy: the `AuthSchema` target
 *
 * A Hyperdrive binding exists only inside a Worker. The deploy-time provider
 * therefore connects to the origin database by URL:
 *
 * ```ts skip-type-checking
 * AuthSchemaProvider({ database: Postgres.database(Redacted.make(process.env.DATABASE_URL)) });
 * ```
 *
 * @module postgres
 */

import { Effect, Layer, Redacted } from "effect";
import type { SqlClient, SqlError } from "effect/sql";
import * as PgClient from "@effect/sql-pg/PgClient";
import * as Sql from "@thomasfosterau/effect-auth-sql";
import type * as Auth from "@thomasfosterau/effect-auth";
import { postgresDatabase, type PostgresDatabase } from "./AuthSchema.ts";
import type { AuthStores } from "./Storage.ts";

export type { PostgresDatabase };

/**
 * A Cloudflare Hyperdrive binding, typed structurally. effect-auth reads only
 * its connection string. `@cloudflare/workers-types`' `Hyperdrive` satisfies
 * this type, so no Cloudflare types package is a dependency.
 */
export interface Hyperdrive {
  readonly connectionString: string;
}

/** Where to connect: a Hyperdrive binding, or a Postgres URL. */
export type Source = Hyperdrive | Redacted.Redacted<string>;

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
 * effect-auth-sql's and every statement is `IF NOT EXISTS`. Inside an Alchemy
 * program, declare `AuthSchema` with a {@link database} target instead.
 */
export const migrate = (
  source: Source,
  options?: ClientOptions,
): Effect.Effect<void, Auth.AuthError | SqlError.SqlError> =>
  Sql.migrate.pipe(Effect.provide(clientLayer(source, options)));

/**
 * Delete the expired magic-link and email-OTP rows, through effect-auth-sql's
 * `purgeExpired`. Schedule it from a cron trigger.
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
export const database = (
  url: Redacted.Redacted<string>,
  options?: ClientOptions,
): PostgresDatabase => postgresDatabase(clientLayer(url, options));
