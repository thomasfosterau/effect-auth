/**
 * `AuthSchema` — an Alchemy v2 resource that keeps the effect-auth schema
 * reconciled inside a Cloudflare D1 database or a Postgres database.
 *
 * {@link AuthSchema} is built with Alchemy's own `Resource` constructor and
 * {@link AuthSchemaProvider} with Alchemy's own `Provider.succeed`, exactly
 * like `Alchemy.Random` or `Cloudflare.D1.Database`. Declare it in an Alchemy
 * program and the *engine* runs the lifecycle — read, diff, reconcile,
 * delete — nothing in this package re-implements any of that.
 *
 * The DDL is not this package's either: it is
 * `@thomasfosterau/effect-auth-sql`'s `schemaStatements`, run through the
 * `SqlClient` that {@link D1Client} builds from a D1 binding, or the one a
 * {@link PostgresDatabase} carries (`Postgres.database(url)` from
 * `@thomasfosterau/effect-auth-alchemy/postgres`).
 *
 * ### Where the D1 binding lives
 *
 * The live binding is given to the **provider**, not to the resource:
 *
 * ```ts
 * providers: Layer.mergeAll(Cloudflare.providers(), AuthSchemaProvider({ database: db }))
 * const schema = yield* AuthSchema("auth-schema", { dropOnDelete: true });
 * ```
 *
 * Resource props are *persisted state*. Alchemy strips every non-plain-data
 * value out of them at the commit boundary (`Diff.stripUnresolved`: "persisted
 * resource state must only ever hold plain data"), and a destroy runs entirely
 * from that persisted state — so a live handle passed as a prop is present on
 * deploy and gone on delete, which would silently break
 * {@link AuthSchemaProps.dropOnDelete}. Alchemy's own providers take their
 * live clients the same way this one does: captured once when the provider
 * layer is built and closed over (see `Cloudflare.D1.ProviderLocal` and
 * `Drizzle.SchemaProvider`), with only serializable identifiers in props.
 *
 * A stack that reconciles more than one database registers them by name and
 * each resource selects one with {@link AuthSchemaProps.database}.
 *
 * This resource owns the *schema*, not the database, so tearing the stack down
 * leaves auth data in place unless you opt in with
 * {@link AuthSchemaProps.dropOnDelete}.
 */

import { Array as Arr, Clock, Data, Effect, type Layer, Record as Rec } from "effect";
import { SqlClient, SqlError } from "effect/sql";
import * as Sql from "@thomasfosterau/effect-auth-sql";
import * as Provider from "alchemy/Provider";
import { Resource } from "alchemy/Resource";
import { authTableNames } from "./AuthTables.ts";
import * as D1Client from "./D1Client.ts";

/** Every table the effect-auth schema creates (defined alchemy-free in `AuthTables.ts`). */
export { authTableNames };

/**
 * The name a single-database {@link AuthSchemaProvider} registers its binding
 * under, and the one {@link AuthSchemaProps.database} defaults to.
 */
export const DEFAULT_DATABASE = "default";

/** Input props for the {@link AuthSchema} resource. */
export interface AuthSchemaProps {
  /**
   * Which of the provider's databases to reconcile — the key used in
   * `AuthSchemaProvider({ databases: { … } })`. Omit it for the
   * single-database form (`AuthSchemaProvider({ database })`), which
   * registers under {@link DEFAULT_DATABASE}.
   *
   * This is a *name*, not a binding: props are persisted to state and a
   * destroy replays them, so they may only hold plain data.
   */
  readonly database?: string;
  /**
   * When `true`, deleting this resource drops every auth table (destroying all
   * auth data). Defaults to `false` so a stack teardown leaves the data in
   * place — the safe choice for a shared database.
   */
  readonly dropOnDelete?: boolean;
}

/** Output attributes returned by the {@link AuthSchema} resource. */
export interface AuthSchemaAttributes {
  /** The auth tables observed in the database after reconciling, sorted. */
  readonly tables: readonly string[];
  /** Number of DDL statements in the applied schema. */
  readonly statements: number;
  /** Epoch milliseconds at which the schema was last reconciled. */
  readonly appliedAt: number;
}

/** The resource's Alchemy type tag, and the key its provider is registered under. */
export const AUTH_SCHEMA_TYPE = "effect-auth::AuthSchema";

/** The `AuthSchema` resource shape, as Alchemy models resources. */
export type AuthSchema = Resource<typeof AUTH_SCHEMA_TYPE, AuthSchemaProps, AuthSchemaAttributes>;

/** The declared {@link AuthSchema} resource. Yield it in an Alchemy program. */
export const AuthSchema = Resource<AuthSchema>(AUTH_SCHEMA_TYPE);

/**
 * An {@link AuthSchema} names a database its provider does not hold a binding
 * for. Raised instead of skipping the work: a silently-skipped `reconcile`
 * would leave the schema unapplied, and a silently-skipped `delete` would
 * break the {@link AuthSchemaProps.dropOnDelete} contract.
 */
export class UnknownDatabaseError extends Data.TaggedError("UnknownDatabaseError")<{
  readonly message: string;
  /** The database name the resource asked for. */
  readonly database: string;
  /** The names the provider was built with. */
  readonly registered: readonly string[];
}> {}

/**
 * A Postgres database an {@link AuthSchemaProvider} reconciles: the
 * `SqlClient` layer each lifecycle operation connects with. Build one with
 * `Postgres.database(url)` from `@thomasfosterau/effect-auth-alchemy/postgres`,
 * or with {@link postgresDatabase} over any Postgres `SqlClient` layer.
 */
export interface PostgresDatabase {
  readonly _tag: "PostgresDatabase";
  readonly client: Layer.Layer<SqlClient.SqlClient, SqlError.SqlError>;
}

/**
 * A Postgres database for {@link AuthSchemaProvider}, over any layer that
 * provides a Postgres `SqlClient`. The layer is built once per lifecycle
 * operation, so it should connect rather than hold a connection.
 */
export const postgresDatabase = (
  client: Layer.Layer<SqlClient.SqlClient, SqlError.SqlError>,
): PostgresDatabase => ({ _tag: "PostgresDatabase", client });

/** A database {@link AuthSchemaProvider} can reconcile: a D1 binding or a Postgres database. */
export type AuthSchemaDatabase = D1Client.D1Database | PostgresDatabase;

const isPostgres = (database: AuthSchemaDatabase): database is PostgresDatabase =>
  "_tag" in database && database._tag === "PostgresDatabase";

const clientOf = (database: AuthSchemaDatabase) =>
  isPostgres(database) ? database.client : D1Client.layer({ db: database });

/**
 * The auth tables that currently exist, sorted. `_` is escaped so the `LIKE`
 * pattern matches a literal underscore and never the application's own tables.
 * Postgres reads the current schema only, the one the DDL created them in.
 */
const listAuthTables = (
  database: AuthSchemaDatabase,
): Effect.Effect<readonly string[], SqlError.SqlError> =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rows = isPostgres(database)
      ? yield* sql<{ readonly name: string }>`
          SELECT table_name AS name FROM information_schema.tables
          WHERE table_schema = current_schema() AND table_name LIKE ${"auth\\_%"} ESCAPE '\\'
          ORDER BY table_name`
      : yield* sql<{ readonly name: string }>`
          SELECT name FROM sqlite_master
          WHERE type = 'table' AND name LIKE ${"auth\\_%"} ESCAPE '\\'
          ORDER BY name`;
    return rows.map((row) => row.name);
  }).pipe(Effect.provide(clientOf(database)));

/** Drop every auth table. Idempotent (`DROP TABLE IF EXISTS`). */
const dropAuthTables = (database: AuthSchemaDatabase): Effect.Effect<void, SqlError.SqlError> =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* Effect.forEach(authTableNames, (name) => sql.unsafe(`DROP TABLE IF EXISTS ${name}`), {
      concurrency: 1,
      discard: true,
    });
  }).pipe(Effect.provide(clientOf(database)));

/** Apply effect-auth-sql's DDL. Every statement is `IF NOT EXISTS`. */
const migrate = (database: AuthSchemaDatabase) =>
  Sql.migrate.pipe(Effect.provide(clientOf(database)));

const observe = (
  database: AuthSchemaDatabase,
  appliedAt: number,
): Effect.Effect<AuthSchemaAttributes, SqlError.SqlError> =>
  listAuthTables(database).pipe(
    Effect.map((tables) => ({
      tables,
      statements: Sql.schemaStatements.length,
      appliedAt,
    })),
  );

/**
 * The databases an {@link AuthSchemaProvider} drives: live D1 bindings, or
 * {@link PostgresDatabase}s.
 *
 * Either one database for the whole stack, or several keyed by the name each
 * resource selects with {@link AuthSchemaProps.database}.
 */
export type AuthSchemaProviderOptions =
  | {
      /** The database every {@link AuthSchema} with no `database` prop uses. */
      readonly database: AuthSchemaDatabase;
    }
  | {
      /** Databases by name, selected per resource with `database`. */
      readonly databases: Readonly<Record<string, AuthSchemaDatabase>>;
    };

/**
 * The provider that drives the {@link AuthSchema} lifecycle, as a `Layer`.
 * Provide it to your stack alongside the other providers, with the D1
 * binding(s) or Postgres database(s) it should reconcile:
 *
 * ```ts
 * Alchemy.Stack("app", {
 *   providers: Layer.mergeAll(Cloudflare.providers(), AuthSchemaProvider({ database: db })),
 *   state: Cloudflare.state(),
 * }, program);
 * ```
 *
 * A Postgres database is reached by URL, since a Hyperdrive binding only
 * exists inside a Worker:
 *
 * ```ts
 * import * as Postgres from "@thomasfosterau/effect-auth-alchemy/postgres";
 *
 * AuthSchemaProvider({ database: Postgres.database(Redacted.make(process.env.DATABASE_URL)) });
 * ```
 *
 * Several databases in one stack are registered by name, and each resource
 * picks one:
 *
 * ```ts
 * AuthSchemaProvider({ databases: { primary: primaryDb, tenants: tenantDb } });
 * yield* AuthSchema("tenant-auth", { database: "tenants" });
 * ```
 *
 * The bindings are held by the provider closure, so every lifecycle
 * operation — including the `delete` a real `alchemy destroy` replays from
 * persisted state — has a live handle. See the module docs for why they
 * cannot travel in props.
 */
export const AuthSchemaProvider = (options: AuthSchemaProviderOptions) => {
  const databases: Readonly<Record<string, AuthSchemaDatabase>> =
    "database" in options ? { [DEFAULT_DATABASE]: options.database } : options.databases;

  const resolve = (
    id: string,
    props: AuthSchemaProps,
  ): Effect.Effect<AuthSchemaDatabase, UnknownDatabaseError> =>
    Effect.suspend(() => {
      const name = props.database ?? DEFAULT_DATABASE;
      const database = databases[name];
      if (database !== undefined) return Effect.succeed(database);
      const registered = Rec.keys(databases);
      return Effect.fail(
        new UnknownDatabaseError({
          message:
            `AuthSchema '${id}' targets database '${name}', which AuthSchemaProvider ` +
            `was not given. Registered: ${Arr.match(registered, { onEmpty: () => "(none)", onNonEmpty: (names) => names.join(", ") })}. ` +
            "Pass the binding to AuthSchemaProvider — it must stay registered for " +
            "destroys too, which run from persisted state.",
          database: name,
          registered,
        }),
      );
    });

  return Provider.succeed(AuthSchema, {
    read: ({ id, olds = {}, output }) =>
      resolve(id, olds).pipe(
        Effect.flatMap(listAuthTables),
        Effect.map((tables) =>
          Arr.match(tables, {
            onEmpty: () => undefined,
            onNonEmpty: (present) => ({
              tables: present,
              statements: Sql.schemaStatements.length,
              appliedAt: output?.appliedAt ?? 0,
            }),
          }),
        ),
      ),

    // The schema is additive and idempotent: changes are always applied in
    // place by re-running the migration. The bound database is never a
    // replacement trigger, so a diff can never destroy auth data.
    diff: () => Effect.succeed({ action: "update" as const }),

    reconcile: ({ id, news = {} }) =>
      Effect.gen(function* () {
        const database = yield* resolve(id, news);
        yield* migrate(database);
        const appliedAt = yield* Clock.currentTimeMillis;
        return yield* observe(database, appliedAt);
      }),

    // `olds` here is the resource's *persisted* props, replayed by the engine
    // during a destroy — plain data only. The binding comes from the closure,
    // so the drop works on a real `alchemy destroy` and not just in-process.
    delete: ({ id, olds = {} }) =>
      olds.dropOnDelete === true ? Effect.flatMap(resolve(id, olds), dropAuthTables) : Effect.void,

    // Non-listable: the schema lives inside a database the caller already
    // holds a binding to. There is no account-wide API that enumerates
    // effect-auth schemas, so `alchemy nuke` sees nothing here.
    list: () => Effect.succeed([]),
  });
};
