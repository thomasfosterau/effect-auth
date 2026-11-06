/**
 * Alchemy's D1 client over an in-memory SQLite database, for tests only.
 *
 * D1 *is* SQLite behind an async, statement-at-a-time API, so the fastest
 * honest way to exercise {@link D1Client} without a Worker runtime is to put
 * that API in front of a real SQLite engine. The client is the provider's own
 * shape: its `PreparedStatement` class over a fake of the raw workerd binding,
 * as `@alchemy.run/cloudflare` builds every `QueryDatabaseClient`. The fake
 * implements only what that class calls: `prepare`, `bind` (a new statement,
 * as on the real binding), `all` / `raw` / `run`, and a `batch` that runs its
 * statements in one SQLite transaction, rolled back on failure, as D1's does.
 *
 * Excluded from the published build (see `tsconfig.json`).
 */

import {
  PreparedStatement,
  type QueryDatabaseClient,
} from "@alchemy.run/cloudflare/D1/QueryDatabase";
import { RuntimeContext } from "alchemy/RuntimeContext";
import Database from "better-sqlite3";
import { Effect, Layer } from "effect";

interface RawStatement {
  bind: (...values: ReadonlyArray<unknown>) => RawStatement;
  all: () => Promise<{ results: ReadonlyArray<unknown> }>;
  run: () => Promise<{ results: ReadonlyArray<unknown> }>;
  raw: () => Promise<ReadonlyArray<ReadonlyArray<unknown>>>;
  /** Run synchronously, for `batch`. */
  readonly execute: () => ReadonlyArray<unknown>;
}

const statement = (db: Database.Database, sql: string): RawStatement => {
  const withParams = (bound: ReadonlyArray<unknown>): RawStatement => {
    const execute = () => {
      const prepared = db.prepare(sql);
      if (prepared.reader) return prepared.all(...bound);
      prepared.run(...bound);
      return [];
    };
    return {
      bind: (...values) => withParams(values),
      execute,
      all: () => Promise.resolve().then(() => ({ results: execute() })),
      run: () => Promise.resolve().then(() => ({ results: execute() })),
      raw: () =>
        Promise.resolve().then(() => {
          const prepared = db.prepare<unknown[], ReadonlyArray<unknown>>(sql);
          if (prepared.reader) return prepared.raw(true).all(...bound);
          prepared.run(...bound);
          return [];
        }),
    };
  };
  return withParams([]);
};

/** A fake of workerd's raw D1 binding over a fresh in-memory SQLite database. */
export const makeRawD1 = () => {
  const db = new Database(":memory:");
  return {
    prepare: (sql: string) => statement(db, sql),
    batch: (statements: ReadonlyArray<RawStatement>) =>
      Promise.resolve().then(() =>
        db.transaction(() => statements.map((s) => ({ results: s.execute() })))(),
      ),
    exec: (sql: string) => Promise.resolve().then(() => void db.exec(sql)),
  };
};

/** A raw binding from {@link makeRawD1}. */
export type RawD1 = ReturnType<typeof makeRawD1>;

/**
 * Type a partial fake as the binding it stands in for. A `RawD1` implements the
 * members of workerd's `D1Database` that `PreparedStatement` and `batch` call
 * (`prepare`, and on its statements `bind` / `all` / `run` / `raw`; `batch`;
 * `exec`); the full type carries many more, which nothing here reaches.
 */
// SAFETY: see above; only the faked members are ever called.
const fakeBinding = (fake: object): D1Binding => fake as D1Binding;

/** Workerd's `D1Database`, as the provider's client types its binding. */
type D1Binding = Effect.Success<QueryDatabaseClient["raw"]>;

/**
 * Alchemy's D1 client over a (deferred) raw binding, built the way the
 * provider builds its own: `PreparedStatement`s over the binding, and `batch`
 * as one call of the binding's `batch`.
 */
export const clientOver = (binding: Effect.Effect<RawD1>): QueryDatabaseClient => {
  const raw = Effect.map(binding, (fake) => fakeBinding(fake));
  // A rejected call is a defect, as in the provider's own client.
  const call = <A>(promise: (database: Effect.Success<typeof raw>) => Promise<A>) =>
    Effect.flatMap(raw, (database) =>
      Effect.tryPromise(() => promise(database)).pipe(Effect.orDie),
    );
  return {
    raw,
    prepare: (query) => new PreparedStatement(query, [], raw),
    exec: (query) => call((database) => database.exec(query)),
    batch: (statements) =>
      call((database) => database.batch(statements.map((prepared) => prepared._build(database)))),
  };
};

/** A fresh in-memory database behind Alchemy's D1 client. */
export const makeTestD1 = (): QueryDatabaseClient => clientOver(Effect.succeed(makeRawD1()));

/** Alchemy's runtime context, as an event carries it. Nothing here reads it. */
export const runtimeContext = Layer.succeed(RuntimeContext, {
  Type: "Test",
  id: "test",
  env: {},
  get: () => Effect.undefined,
  set: (id) => Effect.succeed(id),
});
