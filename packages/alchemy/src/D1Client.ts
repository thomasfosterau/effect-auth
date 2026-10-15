/**
 * A `SqlClient` for Cloudflare D1.
 *
 * This is the only D1-specific code in the package: it turns a D1 binding into
 * an `effect/sql` {@link SqlClient.SqlClient} and stops there. Every
 * auth query lives in `@thomasfosterau/effect-auth-sql`, which is written
 * against `SqlClient` and shared with every other SQL deployment, so nothing
 * here knows what a session or a credential is.
 *
 * ### Why not `@effect/sql-d1`?
 *
 * `@effect/sql-d1` is the same idea and would be the obvious dependency, but
 * its client defines `transactionAcquirer` as `Effect.die("transactions are
 * not supported in D1")`. `@thomasfosterau/effect-auth-sql` calls
 * `sql.withTransaction` in four store methods (`ChallengeStore.create`,
 * `OAuthStateStore.create`, `EmailOtpStore.upsert`, `IdentifierStore.replace`),
 * so WebAuthn, the OAuth handshake, email OTP and email change would all die
 * at runtime on D1 — the stores this package exists to reuse.
 *
 * D1 genuinely has no explicit transactions (`BEGIN` / `COMMIT` /
 * `SAVEPOINT` are rejected by the binding; `batch()` is the only atomic
 * primitive it offers), so the honest adaptation is to let those three
 * `DELETE`-then-`INSERT` upserts, and `replace`'s `INSERT`-then-`DELETE`, run
 * as autocommitted statements rather than to fail. That is what {@link make} does: the connection answers the
 * transaction-control statements the `SqlClient` transaction machinery emits
 * without sending them to D1, so `withTransaction` degrades to "run the
 * effect" instead of dying.
 *
 * **This means nested writes on D1 are not atomic.** Callers that need
 * atomicity on D1 must express it as a single statement (`ON CONFLICT … DO
 * UPDATE`, `UPDATE … RETURNING`), which is what the rest of the SQL stores
 * already do.
 */

import { Effect, Layer, Stream } from "effect";
import { Reactivity } from "effect/reactivity";
import { SqlClient, SqlConnection, SqlError, Statement } from "effect/sql";

/**
 * The part of a Cloudflare D1 binding this client uses.
 *
 * Structural on purpose, so no Cloudflare type dependency is needed: the
 * `D1Database` from `@cloudflare/workers-types`, the handle Miniflare and
 * `wrangler dev` expose, and the `raw` binding behind Alchemy's
 * `Cloudflare.D1.QueryDatabase` all satisfy it.
 */
export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

/** The part of a D1 prepared statement this client uses. */
export interface D1PreparedStatement {
  bind(...values: ReadonlyArray<unknown>): D1PreparedStatement;
  all<T = unknown>(): Promise<D1Result<T>>;
  raw<T = unknown>(): Promise<ReadonlyArray<T>>;
}

/** The result envelope D1 returns from `all` / `raw`. */
export interface D1Result<T = unknown> {
  readonly results?: ReadonlyArray<T> | undefined;
  readonly error?: unknown;
}

/**
 * Statements the `SqlClient` transaction machinery emits (`BEGIN`, `COMMIT`,
 * `ROLLBACK`, `SAVEPOINT …`, `RELEASE …`). D1 rejects all of them, so the
 * connection answers them locally — see the module docs.
 */
const TRANSACTION_CONTROL = /^\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b/i;

const sqlError = (cause: unknown, message: string, operation: string): SqlError.SqlError =>
  new SqlError.SqlError({ reason: new SqlError.UnknownError({ cause, message, operation }) });

const makeConnection = (db: D1Database): SqlConnection.Connection => {
  const rows = (
    sql: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<unknown>, SqlError.SqlError> =>
    Effect.tryPromise({
      try: async () => {
        if (TRANSACTION_CONTROL.test(sql)) return [];
        const response = await db
          .prepare(sql)
          .bind(...params)
          .all();
        if (response.error != null) throw response.error;
        return response.results ?? [];
      },
      catch: (cause) => sqlError(cause, "Failed to execute statement", "execute"),
    });

  const values = (
    sql: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<ReadonlyArray<unknown>>, SqlError.SqlError> =>
    Effect.tryPromise({
      try: async () => {
        if (TRANSACTION_CONTROL.test(sql)) return [];
        return (await db
          .prepare(sql)
          .bind(...params)
          .raw()) as ReadonlyArray<ReadonlyArray<unknown>>;
      },
      catch: (cause) => sqlError(cause, "Failed to execute statement", "execute"),
    });

  const execute = (
    sql: string,
    params: ReadonlyArray<unknown>,
    transformRows: (<A extends object>(row: ReadonlyArray<A>) => ReadonlyArray<A>) | undefined,
  ) =>
    transformRows === undefined
      ? rows(sql, params)
      : Effect.map(rows(sql, params), transformRows as (rows: ReadonlyArray<unknown>) => never);

  return {
    execute,
    executeUnprepared: execute,
    executeRaw: rows,
    executeValues: values,
    executeValuesUnprepared: values,
    // D1 has no cursor API: the binding materializes every row before it
    // answers, so a "stream" would be a lie.
    executeStream: (sql, params, transformRows) =>
      Stream.fromArrayEffect(execute(sql, params, transformRows)),
  };
};

/**
 * Build a `SqlClient` over a D1 binding.
 *
 * @example
 * ```ts
 * const sql = yield* D1Client.make({ db: env.DB });
 * ```
 */
export const make = (options: {
  readonly db: D1Database;
  /** Extra attributes to attach to every `sql.*` span. */
  readonly spanAttributes?: ReadonlyArray<readonly [string, unknown]>;
}): Effect.Effect<SqlClient.SqlClient, never, Reactivity.Reactivity> =>
  SqlClient.make({
    acquirer: Effect.succeed(makeConnection(options.db)),
    compiler: Statement.makeCompilerSqlite(),
    spanAttributes: [["db.system.name", "sqlite"], ...(options.spanAttributes ?? [])],
  });

/**
 * {@link make} as a `Layer`, with `Reactivity` provided.
 *
 * @example
 * ```ts
 * const stores = Sql.layer.pipe(Layer.provide(D1Client.layer({ db: env.DB })));
 * ```
 */
export const layer = (options: {
  readonly db: D1Database;
  readonly spanAttributes?: ReadonlyArray<readonly [string, unknown]>;
}): Layer.Layer<SqlClient.SqlClient> =>
  Layer.effect(SqlClient.SqlClient, make(options)).pipe(Layer.provide(Reactivity.layer));
