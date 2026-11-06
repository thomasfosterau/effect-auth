/**
 * A `SqlClient` over Alchemy's Effect-native D1 client.
 *
 * This is the only D1-specific code in the package: it turns the
 * `QueryDatabaseClient` that `Cloudflare.D1.QueryDatabase(database)` binds
 * into an `effect/sql` {@link SqlClient.SqlClient} and stops there. Every auth
 * query lives in `@thomasfosterau/effect-auth/sql`, which is written against
 * `SqlClient` and shared with every other SQL deployment, so nothing here
 * knows what a session or a credential is. Statements go through the client's
 * `prepare` / `bind` / `all` / `raw` / `batch`, so the database is bound,
 * named and typed the way the rest of an Alchemy Worker binds it.
 *
 * The client's statements need Alchemy's `RuntimeContext` (they run inside a
 * Worker or Durable Object event, or a deploy-time Action); {@link make}
 * captures it once, so the `SqlClient` it returns needs nothing. The client
 * reports a failed statement as a defect (its effects have no error channel);
 * this client turns that defect into a `SqlError`.
 *
 * ### Transactions are batches
 *
 * D1 has no interactive transactions: `BEGIN` / `COMMIT` / `SAVEPOINT` are
 * rejected, and `batch()` — statements run in order and rolled back together
 * on failure — is its only atomic primitive. `@thomasfosterau/effect-auth/sql`
 * calls `sql.withTransaction` around its multi-step writes (the
 * `DELETE`-then-`INSERT` upserts of `ChallengeStore.create`,
 * `OAuthStateStore.create` and `EmailOtpStore.upsert`,
 * `PendingMultiFactorStore.delete`'s two deletes and `IdentifierStore.replace`'s
 * claim-then-release), so a transaction here is mapped onto `batch()`:
 *
 * - `BEGIN` opens a buffer instead of being sent.
 * - A write that returns no rows (`INSERT` / `UPDATE` / `DELETE` / `REPLACE`
 *   without `RETURNING`) is buffered and answers no rows.
 * - A statement that returns rows (a `SELECT`, or a write with `RETURNING`)
 *   is sent in one batch together with every buffered write before it, so it
 *   sees them and they commit or fail together.
 * - `COMMIT` sends what is still buffered as one batch; `ROLLBACK` discards it;
 *   `ROLLBACK TO SAVEPOINT` discards what was buffered after the savepoint.
 *
 * So every write between two reads commits atomically, and so does the read
 * that ends the group. What `batch()` cannot give is atomicity across a read:
 * a group already sent stays committed when a later one fails or the effect
 * rolls back. Of the stores above only `IdentifierStore.replace` reads in the
 * middle (its `DELETE … RETURNING`), and its claim and release are sent in one
 * batch; the undo of a stale claim that follows is its own batch. D1 has no
 * isolation between batches either: another request's statements can run
 * between two of them.
 */

import type {
  PreparedStatement,
  QueryDatabaseClient,
} from "@alchemy.run/cloudflare/D1/QueryDatabase";
import { RuntimeContext } from "alchemy/RuntimeContext";
import { Array as Arr, Effect, Layer, Option, Stream } from "effect";
import { Reactivity } from "effect/reactivity";
import { SqlClient, type SqlConnection, SqlError, Statement } from "effect/sql";

const TRANSACTION_CONTROL = /^\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b/i;
const SAVEPOINT = /^\s*SAVEPOINT\s+("?)(\w+)\1/i;
const ROLLBACK_TO = /^\s*ROLLBACK\s+TO\s+(?:SAVEPOINT\s+)?("?)(\w+)\1/i;
const RELEASE = /^\s*RELEASE\s+(?:SAVEPOINT\s+)?("?)(\w+)\1/i;
/** A write that answers no rows, so it can wait for the batch it commits in. */
const DEFERRABLE_WRITE = /^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i;
const RETURNING = /\bRETURNING\b/i;

const isDeferrable = (sql: string): boolean => DEFERRABLE_WRITE.test(sql) && !RETURNING.test(sql);

const sqlError = (cause: unknown, message: string, operation: string): SqlError.SqlError =>
  new SqlError.SqlError({ reason: new SqlError.UnknownError({ cause, message, operation }) });

/** The rows of a D1 result envelope (`all()`, or one entry of `batch()`). */
const resultRows = (result: { readonly results?: unknown } | undefined): ReadonlyArray<unknown> =>
  Arr.isArray(result?.results) ? result.results : [];

/** Run one provider statement with the captured runtime context; a failed statement is a `SqlError`. */
type Run = <A>(
  operation: string,
  statement: Effect.Effect<A, never, RuntimeContext>,
) => Effect.Effect<A, SqlError.SqlError>;

/**
 * The transaction state of one leased connection: the writes buffered since
 * `BEGIN`, and the buffer length at each open savepoint.
 */
interface TransactionState {
  open: boolean;
  pending: Array<PreparedStatement>;
  savepoints: Array<readonly [name: string, index: number]>;
}

const makeConnection = (
  db: QueryDatabaseClient,
  run: Run,
  tx: TransactionState | undefined,
): SqlConnection.Connection => {
  /** Send the buffered writes, and `last` after them, in one batch; answer `last`'s rows. */
  const flush = (
    last: PreparedStatement | undefined,
  ): Effect.Effect<ReadonlyArray<unknown>, SqlError.SqlError> =>
    Effect.suspend(() => {
      const statements = tx === undefined ? [] : tx.pending.splice(0);
      if (tx !== undefined) tx.savepoints = tx.savepoints.map(([name]) => [name, 0] as const);
      if (last !== undefined) statements.push(last);
      return Arr.match(statements, {
        onEmpty: () => Effect.succeed([]),
        onNonEmpty: (batch) =>
          // One statement needs no batch; `last`'s rows are the last result's.
          last !== undefined && batch.length === 1
            ? run("execute", last.all()).pipe(Effect.map(resultRows))
            : run("batch", db.batch(batch)).pipe(
                Effect.map((results) =>
                  last === undefined
                    ? []
                    : resultRows(Arr.last(results).pipe(Option.getOrUndefined)),
                ),
              ),
      });
    });

  /** Answer a transaction-control statement locally. */
  const control = (sql: string): Effect.Effect<ReadonlyArray<unknown>, SqlError.SqlError> =>
    Effect.suspend(() => {
      if (tx === undefined) return Effect.succeed([]);
      const rollbackTo = ROLLBACK_TO.exec(sql);
      if (rollbackTo !== null) {
        const mark = tx.savepoints.findLast(([name]) => name === rollbackTo[2]);
        if (mark !== undefined) tx.pending.length = Math.min(tx.pending.length, mark[1]);
        return Effect.succeed([]);
      }
      const savepoint = SAVEPOINT.exec(sql);
      if (savepoint !== null) {
        tx.savepoints.push([savepoint[2] ?? "", tx.pending.length]);
        return Effect.succeed([]);
      }
      const release = RELEASE.exec(sql);
      if (release !== null) {
        tx.savepoints = tx.savepoints.filter(([name]) => name !== release[2]);
        return Effect.succeed([]);
      }
      if (/^\s*BEGIN\b/i.test(sql)) {
        tx.open = true;
        tx.pending = [];
        tx.savepoints = [];
        return Effect.succeed([]);
      }
      if (/^\s*COMMIT\b/i.test(sql)) {
        return flush(undefined).pipe(Effect.ensuring(Effect.sync(() => void (tx.open = false))));
      }
      // ROLLBACK
      tx.open = false;
      tx.pending = [];
      tx.savepoints = [];
      return Effect.succeed([]);
    });

  const rows = (
    sql: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<unknown>, SqlError.SqlError> =>
    Effect.suspend(() => {
      if (TRANSACTION_CONTROL.test(sql)) return control(sql);
      const statement = db.prepare(sql).bind(...params);
      if (tx?.open === true) {
        if (isDeferrable(sql)) {
          tx.pending.push(statement);
          return Effect.succeed([]);
        }
        return flush(statement);
      }
      return run("execute", statement.all()).pipe(Effect.map(resultRows));
    });

  const values = (
    sql: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<ReadonlyArray<unknown>>, SqlError.SqlError> =>
    Effect.suspend(() => {
      if (TRANSACTION_CONTROL.test(sql)) return Effect.as(control(sql), []);
      // `batch()` answers rows as objects, so a positional read is sent on its
      // own, after the buffered writes it must see.
      const pendingFirst = tx?.open === true ? flush(undefined) : Effect.void;
      return Effect.andThen(
        pendingFirst,
        run(
          "execute",
          db
            .prepare(sql)
            .bind(...params)
            .raw<ReadonlyArray<unknown>>(),
        ),
      );
    });

  const execute = (
    sql: string,
    params: ReadonlyArray<unknown>,
    transformRows: (<A extends object>(row: ReadonlyArray<A>) => ReadonlyArray<A>) | undefined,
  ) =>
    transformRows === undefined
      ? rows(sql, params)
      : Effect.map(
          rows(sql, params),
          // SAFETY: `all()` returns one plain object per row, which is the `object`
          // bound `transformRows` (the client's column-name transform) is generic over.
          transformRows as (rows: ReadonlyArray<unknown>) => never,
        );

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
 * Build a `SqlClient` over the D1 client `Cloudflare.D1.QueryDatabase(database)`
 * binds. Needs the `RuntimeContext` of the Worker, Durable Object or Action it
 * runs in, which it captures for every statement the client sends.
 *
 * @example
 * ```ts
 * const db = yield* Cloudflare.D1.QueryDatabase(AuthDatabase);
 * const sql = yield* D1Client.make({ db });
 * ```
 */
export const make = (options: {
  readonly db: QueryDatabaseClient;
  /** Extra attributes to attach to every `sql.*` span. */
  readonly spanAttributes?: ReadonlyArray<readonly [string, unknown]> | undefined;
}): Effect.Effect<SqlClient.SqlClient, never, Reactivity.Reactivity | RuntimeContext> =>
  Effect.gen(function* () {
    const runtime = yield* RuntimeContext;
    const run: Run = (operation, statement) =>
      statement.pipe(
        Effect.provideService(RuntimeContext, runtime),
        Effect.catchDefect((cause) =>
          Effect.fail(sqlError(cause, `Failed to ${operation} statement`, operation)),
        ),
      );
    return yield* SqlClient.make({
      acquirer: Effect.succeed(makeConnection(options.db, run, undefined)),
      // A transaction leases a connection of its own, whose buffer becomes one
      // `batch()` (see the module docs).
      transactionAcquirer: Effect.sync(() =>
        makeConnection(options.db, run, { open: false, pending: [], savepoints: [] }),
      ),
      compiler: Statement.makeCompilerSqlite(),
      driver: "d1",
      spanAttributes: [["db.system.name", "sqlite"], ...(options.spanAttributes ?? [])],
    });
  });

/**
 * {@link make} as a `Layer`, with `Reactivity` provided. It still needs the
 * `RuntimeContext` of the event it is built in.
 *
 * @example
 * ```ts
 * const stores = Sql.layer.pipe(Layer.provide(D1Client.layer({ db })));
 * ```
 */
export const layer = (options: {
  readonly db: QueryDatabaseClient;
  readonly spanAttributes?: ReadonlyArray<readonly [string, unknown]> | undefined;
}): Layer.Layer<SqlClient.SqlClient, never, RuntimeContext> =>
  Layer.effect(SqlClient.SqlClient, make(options)).pipe(Layer.provide(Reactivity.layer));
