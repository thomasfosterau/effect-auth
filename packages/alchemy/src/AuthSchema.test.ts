import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import type { D1Database, D1PreparedStatement, D1Result } from "./D1.ts";
import { AuthSchema, AuthSchemaProvider, type AuthSchemaProps } from "./AuthSchema.ts";
import { authTableNames, listAuthTables } from "./Tables.ts";
import { deprovision, provision, type ResourceId } from "./Alchemy.ts";

type SqlValue = null | number | bigint | string | Uint8Array;

interface SqliteStatement {
  all(...params: SqlValue[]): unknown[];
  get(...params: SqlValue[]): unknown;
  run(...params: SqlValue[]): unknown;
}
interface SqliteDatabase {
  prepare(sql: string): SqliteStatement;
}

/**
 * Load whichever embedded SQLite engine is available — Node's built-in
 * `node:sqlite` (Node >= 22.13) or `better-sqlite3`. Both are real SQLite
 * engines, like D1. The suite skips if neither can be loaded.
 */
const loadSqlite = async (): Promise<(() => SqliteDatabase) | null> => {
  try {
    const { DatabaseSync } = await import("node:sqlite");
    return () => new DatabaseSync(":memory:") as unknown as SqliteDatabase;
  } catch {
    // node:sqlite unavailable or requires --experimental-sqlite
  }
  try {
    const { default: Database } = await import("better-sqlite3");
    return () => new Database(":memory:") as unknown as SqliteDatabase;
  } catch {
    // better-sqlite3 not installed
  }
  return null;
};

const newSqlite = await loadSqlite();

/** Wrap an embedded SQLite engine in the minimal async D1 client shape. */
const makeTestDb = (): D1Database => {
  const sqlite = newSqlite!();
  return {
    prepare(sql: string): D1PreparedStatement {
      let bound: SqlValue[] = [];
      const statement: D1PreparedStatement = {
        bind(...values: readonly unknown[]): D1PreparedStatement {
          bound = values as SqlValue[];
          return statement;
        },
        first<T>(): Promise<T | null> {
          const row = sqlite.prepare(sql).get(...bound) as T | undefined;
          return Promise.resolve(row ?? null);
        },
        all<T>(): Promise<D1Result<T>> {
          const results = sqlite.prepare(sql).all(...bound) as T[];
          return Promise.resolve({ results, success: true, meta: {} });
        },
        run<T>(): Promise<D1Result<T>> {
          sqlite.prepare(sql).run(...bound);
          return Promise.resolve({ results: [] as T[], success: true, meta: {} });
        },
      };
      return statement;
    },
  };
};

const id: ResourceId = { logicalId: "auth-schema" };

describe("@thomasfosterau/effect-auth-alchemy resources", () => {
  it("derives the auth table list from the shared schema statements", () => {
    expect(authTableNames).toContain("auth_users");
    expect(authTableNames).toContain("auth_sessions");
    expect(authTableNames).toContain("auth_oauth_accounts");
    expect(authTableNames).toContain("auth_multi_factor");
    expect(authTableNames).toContain("auth_pending_multi_factor");
    expect(authTableNames).toContain("auth_identifiers");
    // Every entry is prefixed and the list is non-trivial.
    expect(authTableNames.length).toBeGreaterThanOrEqual(10);
    expect(authTableNames.every((name) => name.startsWith("auth_"))).toBe(true);
  });

  it("declares an AuthSchema resource type", () => {
    expect(AuthSchema.type).toBe("effect-auth::AuthSchema");
    // diff always asks for an in-place update — the schema is never replaced.
    expect(
      AuthSchemaProvider.diff({ id, news: {} as AuthSchemaProps, olds: {} as AuthSchemaProps }),
    ).toBe("update");
  });
});

const suite = newSqlite ? describe : describe.skip;

suite("AuthSchema provider", () => {
  it("read reports undefined before the schema exists", async () => {
    const database = makeTestDb();
    const live = await Effect.runPromise(
      AuthSchemaProvider.read({ id, props: { database }, output: undefined }),
    );
    expect(live).toBeUndefined();
  });

  it("reconcile creates every auth table and is idempotent", async () => {
    const database = makeTestDb();

    const first = await Effect.runPromise(
      AuthSchemaProvider.reconcile({ id, news: { database }, olds: undefined, output: undefined }),
    );
    expect(first.tables).toEqual([...authTableNames].sort());
    expect(first.statements).toBeGreaterThan(0);
    expect(first.appliedAt).toBeGreaterThan(0);

    // Running again must converge to the same state without error.
    const second = await Effect.runPromise(
      AuthSchemaProvider.reconcile({ id, news: { database }, olds: { database }, output: first }),
    );
    expect(second.tables).toEqual(first.tables);
  });

  it("read reflects the live tables after reconciling", async () => {
    const database = makeTestDb();
    await Effect.runPromise(
      AuthSchemaProvider.reconcile({ id, news: { database }, olds: undefined, output: undefined }),
    );

    const live = await Effect.runPromise(
      AuthSchemaProvider.read({ id, props: { database }, output: undefined }),
    );
    expect(live?.tables).toEqual([...authTableNames].sort());
  });

  it("delete preserves data by default and drops tables when opted in", async () => {
    const database = makeTestDb();
    const output = await Effect.runPromise(
      AuthSchemaProvider.reconcile({ id, news: { database }, olds: undefined, output: undefined }),
    );

    // Default: leave the tables in place.
    await Effect.runPromise(AuthSchemaProvider.delete({ id, props: { database }, output }));
    const stillThere = await Effect.runPromise(listAuthTables(database));
    expect(stillThere).toEqual([...authTableNames].sort());

    // Opt in: drop everything.
    await Effect.runPromise(
      AuthSchemaProvider.delete({ id, props: { database, dropOnDelete: true }, output }),
    );
    const gone = await Effect.runPromise(listAuthTables(database));
    expect(gone).toEqual([]);
  });

  it("provision/deprovision drive the full lifecycle outside the engine", async () => {
    const database = makeTestDb();
    const props: AuthSchemaProps = { database, dropOnDelete: true };

    const output = await Effect.runPromise(provision(AuthSchemaProvider, id, props));
    expect(output.tables).toEqual([...authTableNames].sort());

    await Effect.runPromise(deprovision(AuthSchemaProvider, id, { props, output }));
    const gone = await Effect.runPromise(listAuthTables(database));
    expect(gone).toEqual([]);
  });
});
