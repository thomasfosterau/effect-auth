/**
 * A D1-shaped binding over an in-memory SQLite database, for tests only.
 *
 * D1 *is* SQLite behind an async, statement-at-a-time API, so the fastest
 * honest way to exercise {@link D1Client} without a Worker runtime is to put
 * that API in front of a real SQLite engine. Only the surface
 * {@link D1Client.D1Database} declares is implemented — `bind` returns a new
 * statement, exactly like the real binding, so concurrent queries can't share
 * bound parameters.
 *
 * Excluded from the published build (see `tsconfig.json`).
 */

import Database from "better-sqlite3";
import type { D1Database, D1PreparedStatement, D1Result } from "./D1Client.ts";

const statement = (db: Database.Database, sql: string): D1PreparedStatement => {
  const withParams = (bound: ReadonlyArray<unknown>): D1PreparedStatement => ({
    bind: (...values: ReadonlyArray<unknown>) => withParams(values),
    all: <T = unknown>(): Promise<D1Result<T>> => {
      const prepared = db.prepare<unknown[], T>(sql);
      if (prepared.reader) {
        return Promise.resolve({ results: prepared.all(...bound) });
      }
      prepared.run(...bound);
      return Promise.resolve<D1Result<T>>({ results: [] });
    },
    raw: <T = unknown>(): Promise<ReadonlyArray<T>> => {
      const prepared = db.prepare<unknown[], T>(sql);
      if (prepared.reader) {
        return Promise.resolve(prepared.raw(true).all(...bound));
      }
      prepared.run(...bound);
      return Promise.resolve<ReadonlyArray<T>>([]);
    },
  });
  return withParams([]);
};

/** A fresh in-memory database exposed as a D1 binding. */
export const makeTestD1 = (): D1Database => {
  const db = new Database(":memory:");
  return { prepare: (sql: string) => statement(db, sql) };
};
