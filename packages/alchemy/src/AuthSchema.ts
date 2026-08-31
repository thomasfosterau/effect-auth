/**
 * `AuthSchema` — an Alchemy v2 resource that keeps the effect-auth schema
 * reconciled inside a Cloudflare D1 database.
 *
 * {@link AuthSchema} is built with Alchemy's own `Resource` constructor and
 * {@link AuthSchemaProvider} with Alchemy's own `Provider.succeed`, exactly
 * like `Alchemy.Random` or `Cloudflare.D1.Database`. Declare it in an Alchemy
 * program and the *engine* runs the lifecycle — read, diff, reconcile,
 * delete — nothing in this package re-implements any of that.
 *
 * The DDL is not this package's either: it is
 * `@thomasfosterau/effect-auth-sql`'s `schemaStatements`, run through the
 * `SqlClient` that {@link D1Client} builds from the binding.
 *
 * This resource owns the *schema*, not the database, so tearing the stack down
 * leaves auth data in place unless you opt in with
 * {@link AuthSchemaProps.dropOnDelete}.
 *
 * @example
 * ```ts
 * const schema = yield* AuthSchema("auth-schema", { database: db });
 * ```
 */

import { Clock, Effect } from "effect";
import { SqlClient, SqlError } from "effect/unstable/sql";
import * as Sql from "@thomasfosterau/effect-auth-sql";
import * as Provider from "alchemy/Provider";
import { Resource } from "alchemy/Resource";
import * as D1Client from "./D1Client.ts";
import { migrate } from "./Storage.ts";

/** Input props for the {@link AuthSchema} resource. */
export interface AuthSchemaProps {
  /**
   * The Cloudflare D1 binding to apply the schema to — anything satisfying
   * {@link D1Client.D1Database}.
   */
  readonly database: D1Client.D1Database;
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

const CREATE_TABLE = /create\s+table\s+if\s+not\s+exists\s+(\w+)/i;

/**
 * Every table the effect-auth schema creates, parsed from the shared
 * `schemaStatements` so it cannot drift from the DDL that is actually applied.
 */
export const authTableNames: readonly string[] = Sql.schemaStatements.flatMap((sql) => {
  const match = CREATE_TABLE.exec(sql);
  return match ? [match[1] as string] : [];
});

/**
 * The auth tables that currently exist, sorted. `_` is escaped so the `LIKE`
 * pattern matches a literal underscore and never the application's own tables.
 */
const listAuthTables = (
  database: D1Client.D1Database,
): Effect.Effect<readonly string[], SqlError.SqlError> =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rows = yield* sql<{ readonly name: string }>`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name LIKE ${"auth\\_%"} ESCAPE '\\'
      ORDER BY name`;
    return rows.map((row) => row.name);
  }).pipe(Effect.provide(D1Client.layer({ db: database })));

/** Drop every auth table. Idempotent (`DROP TABLE IF EXISTS`). */
const dropAuthTables = (database: D1Client.D1Database): Effect.Effect<void, SqlError.SqlError> =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* Effect.forEach(authTableNames, (name) => sql.unsafe(`DROP TABLE IF EXISTS ${name}`), {
      discard: true,
    });
  }).pipe(Effect.provide(D1Client.layer({ db: database })));

const observe = (
  database: D1Client.D1Database,
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
 * The provider that drives the {@link AuthSchema} lifecycle, as a `Layer`.
 * Provide it to your stack alongside the other providers:
 *
 * ```ts
 * Alchemy.Stack("app", {
 *   providers: Layer.mergeAll(Cloudflare.providers(), AuthSchemaProvider()),
 *   state: Cloudflare.state(),
 * }, program);
 * ```
 */
export const AuthSchemaProvider = () =>
  Provider.succeed(AuthSchema, {
    read: ({ olds, output }) =>
      listAuthTables(olds.database).pipe(
        Effect.map((tables) =>
          tables.length === 0
            ? undefined
            : {
                tables,
                statements: Sql.schemaStatements.length,
                appliedAt: output?.appliedAt ?? 0,
              },
        ),
      ),

    // The schema is additive and idempotent: changes are always applied in
    // place by re-running the migration. The bound database is never a
    // replacement trigger, so a diff can never destroy auth data.
    diff: () => Effect.succeed({ action: "update" as const }),

    reconcile: ({ news }) =>
      Effect.gen(function* () {
        yield* migrate(news.database);
        const appliedAt = yield* Clock.currentTimeMillis;
        return yield* observe(news.database, appliedAt);
      }),

    delete: ({ olds }) =>
      olds.dropOnDelete === true ? dropAuthTables(olds.database) : Effect.void,

    // Non-listable: the schema lives inside a database the caller already
    // holds a binding to. There is no account-wide API that enumerates
    // effect-auth schemas, so `alchemy nuke` sees nothing here.
    list: () => Effect.succeed([]),
  });
