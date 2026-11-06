/**
 * `AuthSchema` — an Alchemy Action that applies the effect-auth schema to a
 * `Cloudflare.D1.Database` on deploy.
 *
 * It is built from Alchemy's own pieces, exactly as `@alchemy.run/cloudflare`
 * documents deploy-time database work: an `Action` whose init binds the
 * database with `Cloudflare.D1.QueryDatabase(database)` and whose body runs
 * the DDL through that client. The engine runs it in dependency order (after
 * the database exists, in the same deploy) and again whenever its input — the
 * database id and the schema's statements — changes.
 *
 * ```ts
 * const db = yield* Cloudflare.D1.Database("auth-db");
 * yield* AuthSchema("auth-schema", db).pipe(Effect.provide(Cloudflare.D1.QueryDatabaseLocal));
 * ```
 *
 * `Cloudflare.D1.QueryDatabaseLocal` is the provider's deploy-time
 * `QueryDatabase`: it talks to D1 over the Cloudflare HTTP API with the
 * stack's credentials, or to the local simulator under `alchemy dev`.
 *
 * ### Why not `Cloudflare.D1.Database({ migrations })`
 *
 * The database resource's `migrations` reads a directory of `.sql` files, and
 * a database takes one; the application's own migrations hold it. The auth
 * DDL is code — `@thomasfosterau/effect-auth/sql`'s `schemaStatements`, the
 * same statements every other SQL deployment runs — so it is applied beside
 * them, idempotently (`CREATE … IF NOT EXISTS`).
 *
 * ### What it does not do
 *
 * An Action has no delete: removing `AuthSchema` from the stack, or destroying
 * it, leaves the tables in place. They go with the database when the
 * `Cloudflare.D1.Database` resource is destroyed.
 */

import type { Database } from "@alchemy.run/cloudflare/D1/Database";
import { QueryDatabase } from "@alchemy.run/cloudflare/D1/QueryDatabase";
import { Action } from "alchemy/Action";
import { Clock, Effect } from "effect";
import { SqlClient, type SqlError } from "effect/sql";
import * as Sql from "@thomasfosterau/effect-auth/sql";
import * as D1Client from "./D1Client.ts";

/** Every table the effect-auth schema creates (`@thomasfosterau/effect-auth/sql`'s list). */
export const authTableNames: readonly string[] = Sql.authTableNames;

/** The Action's Alchemy type tag. */
export const AUTH_SCHEMA_TYPE = "effect-auth::D1AuthSchema";

/** The input the engine hashes: a change to either re-runs the Action. */
export interface AuthSchemaInput {
  /** The target database's id, so a replaced database is migrated again. */
  readonly databaseId: string;
  /** `@thomasfosterau/effect-auth/sql`'s DDL, so a schema change is applied. */
  readonly statements: readonly string[];
}

/** What a run of the {@link AuthSchema} Action outputs. */
export interface AuthSchemaAttributes {
  /** The auth tables observed in the database after applying, sorted. */
  readonly tables: readonly string[];
  /** Number of DDL statements in the applied schema. */
  readonly statements: number;
  /** Epoch milliseconds at which the schema was last applied. */
  readonly appliedAt: number;
}

/**
 * The auth tables that currently exist, sorted. `_` is escaped so the `LIKE`
 * pattern matches a literal underscore and never the application's own tables.
 */
const listAuthTables: () => Effect.Effect<
  readonly string[],
  SqlError.SqlError,
  SqlClient.SqlClient
> = Effect.fn("AuthSchema.listAuthTables")(function* () {
  const sql = yield* SqlClient.SqlClient;
  const rows = yield* sql<{ readonly name: string }>`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name LIKE ${"auth\\_%"} ESCAPE '\\'
      ORDER BY name`;
  return rows.map((row) => row.name);
});

/**
 * Apply the effect-auth schema to `database` on deploy, as an Alchemy Action
 * with logical id `id`. Yield it in an Alchemy program with a
 * `Cloudflare.D1.QueryDatabase` provided (`Cloudflare.D1.QueryDatabaseLocal`
 * on deploy); it outputs the {@link AuthSchemaAttributes} of the run.
 *
 * Each call declares its own Action, so one stack can apply the schema to
 * several databases under distinct ids. Its type (`effect-auth::D1AuthSchema`)
 * differs from the Postgres package's resource.
 */
export const AuthSchema = (id: string, database: Database) =>
  Action(
    AUTH_SCHEMA_TYPE,
    Effect.gen(function* () {
      const db = yield* QueryDatabase(database);
      return (_input: AuthSchemaInput) =>
        Effect.gen(function* () {
          yield* Sql.migrate;
          const tables = yield* listAuthTables();
          const appliedAt = yield* Clock.currentTimeMillis;
          return {
            tables,
            statements: Sql.schemaStatements.length,
            appliedAt,
          } satisfies AuthSchemaAttributes;
        }).pipe(Effect.provide(D1Client.layer({ db })));
    }),
  )(id, { databaseId: database.databaseId, statements: Sql.schemaStatements });
