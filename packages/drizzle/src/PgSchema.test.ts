/**
 * The exported table objects, the DDL they are equivalent to, and the custom
 * table names both must honour — checked against a real PostgreSQL engine
 * (PGlite — Postgres compiled to WASM, in-process, no server).
 */

import type { PGlite } from "@electric-sql/pglite";
import { getTableName } from "drizzle-orm";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { Array as Arr, Effect, Layer, Schema } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
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
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

/** The custom names the first test binds every store to. */
const names: TableNames = {
  sessions: "app_sessions",
  users: "app_users",
  identifiers: "app_identifiers",
};
const customTables = defineTables(names);

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291). The template holds this package's default `effect_auth_*` tables,
 * and the stores here are bound to the custom names, so the file drops the
 * defaults and applies its own DDL on top. Emptied before each test.
 */
let client: PGlite;
let db: PgliteDatabase;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(
    `DROP TABLE ${Object.values(defaultTables)
      .map((table) => getTableName(table))
      .join(", ")}`,
  );
  await Arr.reduce(migrationStatements(names), Promise.resolve(), async (previous, statement) => {
    await previous;
    await client.exec(statement);
  });
  db = drizzle(client);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(
    client,
    Object.values(customTables).map((table) => getTableName(table)),
  );
});

/** Run `build`'s program against all three stores under the custom names. */
const runWithCustomNames = <A, E>(
  build: (db: PgliteDatabase, tables: Tables) => Effect.Effect<A, E, StoreServices>,
): Promise<A> =>
  Effect.runPromise(
    build(db, customTables).pipe(
      Effect.provide(layer(customTables).pipe(Layer.provide(databaseLayer(db)))),
    ),
  );

/** `information_schema.tables` rows, read for their names. */
const TableNameRows = Schema.Array(Schema.Struct({ table_name: Schema.String }));

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
  Effect.orDie(
    Effect.tryPromise(async () => {
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
    }),
  );

describe("Schema", () => {
  it("drives every store from custom table names", async () => {
    const result = await runWithCustomNames((db, tables) =>
      Effect.gen(function* () {
        yield* seedUser(db, tables, { id: "user-1" });

        const sessions = yield* Auth.SessionStore;
        const users = yield* Auth.UserStore;
        const identifiers = yield* Auth.IdentifierStore;

        yield* sessions.create(makeSession({ attributes: { via: "custom" } }));
        yield* identifiers.create(identifier());

        const present = yield* Effect.orDie(
          Effect.tryPromise(async () => {
            const rows = await db.execute(
              `SELECT table_name FROM information_schema.tables
                 WHERE table_schema = 'public' ORDER BY table_name`,
            );
            return Schema.decodeUnknownSync(TableNameRows)(rows.rows).map((row) => row.table_name);
          }),
        );

        return {
          present,
          session: yield* sessions.get("session-1"),
          user: yield* users.get("user-1"),
          identifier: yield* identifiers.getByValue("email", "ada@example.com"),
        };
      }),
    );

    expect(result.present).toEqual(["app_identifiers", "app_sessions", "app_users"]);
    expect(result.session?.attributes).toEqual({ via: "custom" });
    expect(result.user?.id).toBe("user-1");
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
