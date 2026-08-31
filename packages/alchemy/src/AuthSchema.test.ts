import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import type { D1Database, D1PreparedStatement, D1Result } from "./D1.ts";
import {
  AUTH_SCHEMA_TYPE,
  AuthSchema,
  AuthSchemaProvider,
  type AuthSchemaProps,
} from "./AuthSchema.ts";
import { authTableNames, listAuthTables } from "./Tables.ts";
import { deprovision, provision, silentSession, type ResourceIdentity } from "./Alchemy.ts";

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

const ref: ResourceIdentity = { id: "auth-schema" };
/** What the engine passes every lifecycle operation for {@link ref}. */
const self = { id: ref.id, fqn: ref.id, instanceId: ref.id };

/**
 * Build the resource's provider exactly the way an Alchemy stack does: the
 * `Provider.succeed(...)` Layer is mounted and the service is read back off
 * Alchemy's own `Provider` tag.
 */
const provider = await Effect.runPromise(
  AuthSchema.Provider.pipe(Effect.provide(AuthSchemaProvider())),
);

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

  it("declares a real Alchemy resource and registers a provider for it", async () => {
    expect(AuthSchema.Type).toBe(AUTH_SCHEMA_TYPE);
    // The provider resolved off Alchemy's `Provider` tag implements the
    // lifecycle the engine drives.
    expect(typeof provider.reconcile).toBe("function");
    expect(typeof provider.delete).toBe("function");
    expect(typeof provider.list).toBe("function");

    // diff always asks for an in-place update — the schema is never replaced.
    const diff = await Effect.runPromise(
      provider.diff!({
        ...self,
        olds: {} as AuthSchemaProps,
        news: {} as AuthSchemaProps,
        oldBindings: [],
        newBindings: [],
        output: undefined,
      }),
    );
    expect(diff).toEqual({ action: "update" });

    // Nothing to enumerate account-wide.
    expect(await Effect.runPromise(provider.list())).toEqual([]);
  });
});

const suite = newSqlite ? describe : describe.skip;

suite("AuthSchema provider", () => {
  it("read reports undefined before the schema exists", async () => {
    const database = makeTestDb();
    const live = await Effect.runPromise(
      provider.read!({ ...self, olds: { database }, output: undefined }),
    );
    expect(live).toBeUndefined();
  });

  it("reconcile creates every auth table and is idempotent", async () => {
    const database = makeTestDb();

    const first = await Effect.runPromise(
      provider.reconcile({
        ...self,
        news: { database },
        olds: undefined,
        output: undefined,
        session: silentSession,
        bindings: [],
      }),
    );
    expect(first.tables).toEqual([...authTableNames].sort());
    expect(first.statements).toBeGreaterThan(0);
    expect(first.appliedAt).toBeGreaterThan(0);

    // Running again must converge to the same state without error.
    const second = await Effect.runPromise(
      provider.reconcile({
        ...self,
        news: { database },
        olds: { database },
        output: first,
        session: silentSession,
        bindings: [],
      }),
    );
    expect(second.tables).toEqual(first.tables);
  });

  it("read reflects the live tables after reconciling", async () => {
    const database = makeTestDb();
    await Effect.runPromise(provision(provider, ref, { database }));

    const live = await Effect.runPromise(
      provider.read!({ ...self, olds: { database }, output: undefined }),
    );
    expect(live?.tables).toEqual([...authTableNames].sort());
  });

  it("delete preserves data by default and drops tables when opted in", async () => {
    const database = makeTestDb();
    const output = await Effect.runPromise(provision(provider, ref, { database }));

    // Default: leave the tables in place.
    await Effect.runPromise(deprovision(provider, ref, { props: { database }, output }));
    const stillThere = await Effect.runPromise(listAuthTables(database));
    expect(stillThere).toEqual([...authTableNames].sort());

    // Opt in: drop everything.
    await Effect.runPromise(
      deprovision(provider, ref, { props: { database, dropOnDelete: true }, output }),
    );
    const gone = await Effect.runPromise(listAuthTables(database));
    expect(gone).toEqual([]);
  });

  it("provision/deprovision drive the full lifecycle outside the engine", async () => {
    const database = makeTestDb();
    const props: AuthSchemaProps = { database, dropOnDelete: true };

    const output = await Effect.runPromise(provision(provider, ref, props));
    expect(output.tables).toEqual([...authTableNames].sort());

    // A second apply carries the prior state, so read + diff run too.
    const again = await Effect.runPromise(provision(provider, ref, props, { props, output }));
    expect(again.tables).toEqual(output.tables);

    await Effect.runPromise(deprovision(provider, ref, { props, output }));
    const gone = await Effect.runPromise(listAuthTables(database));
    expect(gone).toEqual([]);
  });
});
