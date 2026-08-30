/**
 * `AuthSchema` — an Alchemy v2 resource that provisions and manages the
 * effect-auth schema inside a Cloudflare D1 database.
 *
 * Declare it once in your Alchemy program against a bound D1 database and the
 * engine keeps the auth tables (`auth_users`, `auth_sessions`, ...) reconciled
 * on every deploy. Because the underlying DDL is fully idempotent
 * (`CREATE TABLE IF NOT EXISTS`), reconciling is cheap and safe to repeat, and
 * additive schema changes from a library upgrade are picked up automatically.
 *
 * The D1 database itself is supplied as a binding in {@link AuthSchemaProps} —
 * provision it with `Cloudflare.D1Database(...)` and pass the bound handle in.
 * This resource owns only the *schema*, not the database, so tearing the stack
 * down never destroys auth data unless you opt in with {@link AuthSchemaProps.dropOnDelete}.
 */

import { Clock, Effect } from "effect";
import type * as Auth from "@thomasfosterau/effect-auth";
import { type D1Database } from "./D1.ts";
import { migrate, schemaStatements } from "./Schema.ts";
import { type Provider, Resource } from "./Alchemy.ts";
import { dropAuthTables, listAuthTables } from "./Tables.ts";

/** Input props for the {@link AuthSchema} resource. */
export interface AuthSchemaProps {
  /**
   * The bound Cloudflare D1 database to apply the schema to. Any handle
   * satisfying the structural `D1Database` shape works — the binding returned
   * by Alchemy's `Cloudflare.D1Database.bind(...)`, the
   * `@cloudflare/workers-types` `D1Database`, or Miniflare's local engine.
   */
  readonly database: D1Database;
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

/**
 * The declared {@link AuthSchema} resource type. Yield it in an Alchemy program:
 *
 * ```ts
 * const schema = yield* AuthSchema("auth-schema", { database: db });
 * ```
 */
export const AuthSchema = Resource<
  "effect-auth::AuthSchema",
  AuthSchemaProps,
  AuthSchemaAttributes
>("effect-auth::AuthSchema");

const observe = (
  database: D1Database,
  appliedAt: number,
): Effect.Effect<AuthSchemaAttributes, Auth.AuthError> =>
  listAuthTables(database).pipe(
    Effect.map((tables) => ({ tables, statements: schemaStatements.length, appliedAt })),
  );

/**
 * The provider that drives the {@link AuthSchema} lifecycle. In a real Alchemy
 * program mount it with `Layer.effect(Provider, ...)`; in tests or one-off
 * migrations drive it with {@link provision}/{@link deprovision} from
 * `./Alchemy.ts`.
 */
export const AuthSchemaProvider: Provider<AuthSchemaProps, AuthSchemaAttributes, Auth.AuthError> = {
  read: ({ props, output }) =>
    listAuthTables(props.database).pipe(
      Effect.map((tables) =>
        tables.length === 0
          ? undefined
          : {
              tables,
              statements: schemaStatements.length,
              appliedAt: output?.appliedAt ?? 0,
            },
      ),
    ),

  // The schema is additive and idempotent: changes are always applied in place
  // by re-running the migration. The bound database is treated as a binding,
  // never a replacement trigger, so auth data is never destroyed by a diff.
  diff: () => "update",

  reconcile: ({ news }) =>
    Effect.gen(function* () {
      yield* migrate(news.database);
      const appliedAt = yield* Clock.currentTimeMillis;
      return yield* observe(news.database, appliedAt);
    }),

  delete: ({ props }) =>
    props.dropOnDelete === true ? dropAuthTables(props.database) : Effect.void,
};
