/**
 * The exported table objects, the DDL they are equivalent to, and the custom
 * table names both must honour — checked against a real PostgreSQL engine
 * (PGlite — Postgres compiled to WASM, in-process, no server).
 */

import { PGlite } from "@electric-sql/pglite";
import { getTableName } from "drizzle-orm";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { layer } from "./Layers.ts";
import {
  defineTables,
  identifiersTable,
  migrationSql,
  migrationStatements,
  sessionsTable,
  type Tables,
  tables as defaultTables,
  usersTable,
} from "./PgSchema.ts";
import type { TableNames } from "./Schema.ts";

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

/**
 * Spin up a fresh in-memory Postgres, apply the exported DDL, run `build`'s
 * program against all three stores, then tear the database down.
 */
const runFresh = async <A, E>(
  build: (db: PgliteDatabase, tables: Tables) => Effect.Effect<A, E, StoreServices>,
  names?: Partial<TableNames>,
): Promise<A> => {
  const client = await PGlite.create();
  try {
    for (const statement of migrationStatements(names)) {
      await client.exec(statement);
    }
    const db = drizzle(client);
    const tables = names === undefined ? defaultTables : defineTables(names);
    return await Effect.runPromise(
      build(db, tables).pipe(
        Effect.provide(layer(tables).pipe(Layer.provide(databaseLayer(db)))),
      ) as Effect.Effect<A, E>,
    );
  } finally {
    await client.close();
  }
};

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const makeSession = (overrides: Partial<Auth.Session> = {}): Auth.Session => ({
  id: "session-1",
  userId: "user-1",
  expiresAt: at(60_000),
  createdAt: at(0),
  lastActivityAt: at(0),
  attributes: {},
  ...overrides,
});

const identifier = (overrides: Partial<Auth.Identifier> = {}): Auth.Identifier => ({
  id: "identifier-1",
  userId: "user-1",
  type: "email",
  value: "ada@example.com",
  verified: false,
  createdAt: at(0),
  ...overrides,
});

/** Insert a user row directly — `UserStore` is read-only by contract. */
const seedUser = (
  db: PgliteDatabase,
  tables: Tables,
  row: Partial<Tables["users"]["$inferInsert"]> = {},
): Effect.Effect<string> =>
  Effect.promise(async () => {
    const id = row.id ?? "user-1";
    await db
      .insert(tables.users)
      .values({
        id,
        name: null,
        image: null,
        passwordHash: null,
        attributes: {},
        createdAt: at(0),
        updatedAt: at(0),
        ...row,
      })
      .execute();
    return id;
  });

describe("Schema", () => {
  it("drives every store from custom table names", async () => {
    const names: TableNames = {
      sessions: "app_sessions",
      users: "app_users",
      identifiers: "app_identifiers",
    };

    const result = await runFresh(
      (db, tables) =>
        Effect.gen(function* () {
          yield* seedUser(db, tables, { id: "user-1", passwordHash: "hash" });

          const sessions = yield* Auth.SessionStore;
          const users = yield* Auth.UserStore;
          const identifiers = yield* Auth.IdentifierStore;

          yield* sessions.create(makeSession({ attributes: { via: "custom" } }));
          yield* identifiers.create(identifier());

          const present = yield* Effect.promise(async () => {
            const rows = await db.execute(
              `SELECT table_name FROM information_schema.tables
                 WHERE table_schema = 'public' ORDER BY table_name`,
            );
            const list = Array.isArray(rows) ? rows : (rows as { rows: unknown[] }).rows;
            return list.map((row) => (row as { table_name: string }).table_name);
          });

          return {
            present,
            session: yield* sessions.get("session-1"),
            credentials: yield* users.getCredentials("user-1"),
            identifier: yield* identifiers.getByValue("email", "ada@example.com"),
          };
        }),
      names,
    );

    expect(result.present).toEqual(["app_identifiers", "app_sessions", "app_users"]);
    expect(result.session?.attributes).toEqual({ via: "custom" });
    expect(result.credentials).toBe("hash");
    expect(result.identifier?.id).toBe("identifier-1");
  });

  it("emits DDL matching the requested table names", () => {
    const statements = migrationStatements();
    expect(statements).toHaveLength(6);
    expect(statements[0]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_users");
    expect(statements[1]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_sessions");
    expect(statements[3]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_identifiers");
    expect(statements[4]).toContain(
      "CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_identifiers_type_value_key",
    );
    // No email columns on users: handles live in the identifiers table.
    expect(statements[0]).not.toContain("email");

    const custom = migrationSql({ users: "app_users" });
    expect(custom).toContain("CREATE TABLE IF NOT EXISTS app_users");
    expect(custom).toContain("CREATE TABLE IF NOT EXISTS effect_auth_sessions");
    expect(custom.endsWith(";\n")).toBe(true);
  });

  it("names the exported tables effect_auth_* and honours per-table overrides", () => {
    expect([
      getTableName(sessionsTable),
      getTableName(usersTable),
      getTableName(identifiersTable),
    ]).toEqual(["effect_auth_sessions", "effect_auth_users", "effect_auth_identifiers"]);
    expect(sessionsTable).toBe(defaultTables.sessions);

    const custom = defineTables({ sessions: "app_sessions" });
    expect(getTableName(custom.sessions)).toBe("app_sessions");
    // Unspecified names keep their defaults.
    expect(getTableName(custom.users)).toBe("effect_auth_users");
  });
});
