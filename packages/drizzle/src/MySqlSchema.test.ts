/**
 * MySQL coverage — without a MySQL server.
 *
 * There is none available to this suite, so the dialect is pinned two ways
 * instead.
 *
 * 1. **Behaviourally, through `drizzle-orm/mysql-proxy`.** That driver is a real
 *    `MySqlDatabase`: it compiles the very same store calls down to real MySQL
 *    SQL and hands the statement to a callback instead of a socket. So the
 *    assertions below are about the SQL and the bound parameters a MySQL server
 *    would actually receive — backtick quoting, `?` placeholders,
 *    `YYYY-MM-DD HH:MM:SS.mmm` datetimes, JSON-stringified attribute bags — and
 *    about the rows the store maps back out of a MySQL driver's wire shape.
 * 2. **Structurally, at the type level.** `MySql.tables` is a member of the
 *    shared `Tables` union, a `MySqlDatabase` handle satisfies `databaseLayer`,
 *    and MySQL's row types are interchangeable with PostgreSQL's — which is what
 *    lets one store implementation serve all three dialects.
 *
 * What is *not* covered: the server's own behaviour (that a duplicate
 * `(type, value)` really is rejected, that `DATETIME(3)` really keeps
 * milliseconds). The PostgreSQL and SQLite suites cover the store's reaction to
 * those events on engines that are available.
 */

import { getTableColumns } from "drizzle-orm";
import {
  mysqlTable,
  type MySqlDatabase,
  type MySqlQueryResultHKT,
  type PreparedQueryHKTBase,
} from "drizzle-orm/mysql-core";
import { drizzle, type MySqlRemoteDatabase } from "drizzle-orm/mysql-proxy";
import { DateTime, Effect, Layer, Struct } from "effect";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { fromTables } from "./Columns.ts";
import { databaseLayer } from "./Database.ts";
import { mysqlProxyConfig, normalizeSql } from "./testing/DrizzleLine.ts";
import { layer } from "./Layers.ts";
import {
  binaryVarchar,
  collationMigrationStatements,
  defineTables,
  identifierCollation,
  migrationStatements,
  tables,
  type Tables,
} from "./MySqlSchema.ts";
import type * as Pg from "./PgSchema.ts";
import * as Requests from "./Requests.ts";
import type { Tables as AnyTables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface Statement {
  readonly sql: string;
  readonly params: ReadonlyArray<unknown>;
}

interface Proxy {
  readonly db: MySqlRemoteDatabase;
  /** Every statement the store sent, in order. */
  readonly statements: ReadonlyArray<Statement>;
  /** Queue the rows the next `SELECT` resolves to, in driver wire shape. */
  readonly respondWith: (rows: ReadonlyArray<ReadonlyArray<unknown>>) => void;
}

const makeProxy = (): Proxy => {
  const statements: Array<Statement> = [];
  let queued: ReadonlyArray<ReadonlyArray<unknown>> = [];
  const db = drizzle(async (sql, params, method) => {
    statements.push({ sql: normalizeSql(sql), params });
    if (method === "all") {
      const rows = queued;
      queued = [];
      return { rows: rows.map((row) => row.slice()) };
    }
    // What mysql2 hands back for an INSERT/UPDATE/DELETE.
    return { rows: [{ insertId: 0, affectedRows: 1 }] };
  }, mysqlProxyConfig);
  return {
    db,
    statements,
    respondWith: (rows) => {
      queued = rows;
    },
  };
};

/** Which column of each table holds each field the stores read. */
const projection = fromTables(tables);

/**
 * A row in the shape the MySQL driver delivers it: positional, in the order the
 * store projects its columns, carrying driver values rather than domain values.
 */
const wireRow = (
  names: Readonly<Record<string, string>>,
  values: Readonly<Record<string, Schema.Json>>,
): ReadonlyArray<unknown> => R.values(names).map((field) => values[field]);

const run = <A, E>(
  proxy: Proxy,
  program: Effect.Effect<A, E, Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    program.pipe(Effect.provide(layer(tables).pipe(Layer.provide(databaseLayer(proxy.db))))),
  );

const at = (offsetMs: number): Date =>
  DateTime.toDateUtc(
    DateTime.add(DateTime.makeUnsafe("2026-01-01T00:00:00.000Z"), { milliseconds: offsetMs }),
  );

// ---------------------------------------------------------------------------
// The SQL a MySQL server would receive
// ---------------------------------------------------------------------------

describe("MySQL / statements", () => {
  it("writes a session as MySQL INSERT with driver-shaped parameters", async () => {
    const proxy = makeProxy();

    await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        return yield* store.create({
          id: "session-1",
          userId: "user-1",
          expiresAt: at(60_000),
          createdAt: at(0),
          lastActivityAt: at(0),
          attributes: { device: "laptop" },
        });
      }),
    );

    expect(proxy.statements).toHaveLength(1);
    const [insert] = proxy.statements;
    expect(insert?.sql).toBe(
      "insert into `effect_auth_sessions` (`id`, `user_id`, `expires_at`, `created_at`, `last_activity_at`, `attributes`) values (?, ?, ?, ?, ?, ?)",
    );
    // `datetime(3)` goes out as MySQL's literal format, not an ISO string, and
    // the attribute bag as JSON text.
    expect(insert?.params).toEqual([
      "session-1",
      "user-1",
      "2026-01-01 00:01:00.000",
      "2026-01-01 00:00:00.000",
      "2026-01-01 00:00:00.000",
      '{"device":"laptop"}',
    ]);
  });

  it("reads a session back out of MySQL's wire shape", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow(projection.sessions.names, {
        id: "session-1",
        userId: "user-1",
        expiresAt: "2026-01-01 00:01:00.000",
        createdAt: "2026-01-01 00:00:00.000",
        lastActivityAt: "2026-01-01 00:00:00.000",
        // mysql2 parses JSON columns for you.
        attributes: { device: "laptop" },
      }),
    ]);

    const session = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        return yield* store.get("session-1");
      }),
    );

    expect(proxy.statements[0]?.sql).toBe(
      "select `id`, `user_id`, `expires_at`, `created_at`, `last_activity_at`, `attributes` from `effect_auth_sessions` where `effect_auth_sessions`.`id` = ? limit ?",
    );
    expect(proxy.statements[0]?.params).toEqual(["session-1", 1]);
    expect(session).toEqual({
      id: "session-1",
      userId: "user-1",
      expiresAt: at(60_000),
      createdAt: at(0),
      lastActivityAt: at(0),
      attributes: { device: "laptop" },
    });
  });

  it("verifies an identifier with UPDATE then SELECT, never RETURNING", async () => {
    // MySQL has no `RETURNING`; the store re-reads instead, on every dialect.
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow(projection.identifiers.names, {
        id: "identifier-1",
        userId: "user-1",
        type: "email",
        value: "ada@example.com",
        // tinyint, not a boolean.
        verified: 1,
        verifiedAt: "2026-01-01 00:00:09.000",
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const verified = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.setVerified("identifier-1", at(9000));
      }),
    );

    expect(proxy.statements.map((statement) => statement.sql)).toEqual([
      "update `effect_auth_identifiers` set `verified` = ?, `verified_at` = ? where `effect_auth_identifiers`.`id` = ?",
      "select `id`, `user_id`, `type`, `value`, `verified`, `verified_at`, `created_at` from `effect_auth_identifiers` where `effect_auth_identifiers`.`id` = ? limit ?",
    ]);
    expect(proxy.statements.every((statement) => !statement.sql.includes("returning"))).toBe(true);
    // `1` came back a real `boolean`, the datetime a real `Date`.
    expect(verified).toEqual({
      id: "identifier-1",
      userId: "user-1",
      type: "email",
      value: "ada@example.com",
      verified: true,
      verifiedAt: at(9000),
      createdAt: at(0),
    });
  });

  it("replaces an identifier with a guarded read, then INSERT, then DELETE", async () => {
    const proxy = makeProxy();
    // The guarded read finds the identifier being replaced.
    proxy.respondWith([["identifier-1"]]);
    const from: Auth.Identifier = {
      id: "identifier-1",
      userId: "user-1",
      type: "email",
      value: "ada@example.com",
      verified: true,
      createdAt: at(0),
    };
    const to: Auth.Identifier = {
      ...from,
      id: "identifier-2",
      value: "ada-new@example.com",
      verifiedAt: at(9000),
      createdAt: at(9000),
    };

    const replaced = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.replace(from, to);
      }),
    );

    expect(replaced).toEqual(to);
    expect(proxy.statements.map((statement) => statement.sql)).toEqual([
      "select `id` from `effect_auth_identifiers` where (`effect_auth_identifiers`.`id` = ? and `effect_auth_identifiers`.`user_id` = ? and `effect_auth_identifiers`.`type` = ? and `effect_auth_identifiers`.`value` = ?) limit ?",
      "insert into `effect_auth_identifiers` (`id`, `user_id`, `type`, `value`, `verified`, `verified_at`, `created_at`) values (?, ?, ?, ?, ?, ?, ?)",
      "delete from `effect_auth_identifiers` where `effect_auth_identifiers`.`id` = ?",
    ]);
    expect(proxy.statements[0]?.params).toEqual([
      "identifier-1",
      "user-1",
      "email",
      "ada@example.com",
      1,
    ]);
    expect(proxy.statements[2]?.params).toEqual(["identifier-1"]);
  });

  it("nulls a miss and omits an absent verifiedAt", async () => {
    const proxy = makeProxy();
    proxy.respondWith([]);
    const missing = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.getByValue("email", "nobody@example.com");
      }),
    );
    expect(missing).toBeNull();

    const proxyWithRow = makeProxy();
    proxyWithRow.respondWith([
      wireRow(projection.identifiers.names, {
        id: "identifier-1",
        userId: "user-1",
        type: "email",
        value: "ada@example.com",
        verified: 0,
        verifiedAt: null,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);
    const unverified = await run(
      proxyWithRow,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.getByValue("email", "ada@example.com");
      }),
    );

    expect(unverified?.verified).toBe(false);
    expect(unverified && "verifiedAt" in unverified).toBe(false);
    expect(proxyWithRow.statements[0]?.sql).toContain(
      "where (`effect_auth_identifiers`.`type` = ? and `effect_auth_identifiers`.`value` = ?)",
    );
  });

  it("never resolves the row an unmigrated case- and accent-insensitive column returns for a look-alike (#602)", async () => {
    // A table still under `utf8mb4_0900_ai_ci` answers `bob@exämple.com` with
    // Bob's row. The lookup goes out unchanged; core refuses the answer.
    const bobRow = wireRow(projection.identifiers.names, {
      id: "identifier-bob",
      userId: "user-bob",
      type: "email",
      value: "bob@example.com",
      verified: 1,
      verifiedAt: "2026-01-01 00:00:00.000",
      createdAt: "2026-01-01 00:00:00.000",
    });
    const proxy = makeProxy();
    proxy.respondWith([bobRow]);

    const resolved = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        const users = yield* Auth.UserStore;
        return yield* Auth.resolveUserByIdentifier(store, users.get, "email", "bob@exämple.com");
      }),
    );

    expect(resolved).toBeNull();
    expect(proxy.statements).toHaveLength(1);
    expect(proxy.statements[0]?.sql).toContain(
      "where (`effect_auth_identifiers`.`type` = ? and `effect_auth_identifiers`.`value` = ?)",
    );
    expect(proxy.statements[0]?.params).toEqual(["email", "bob@exämple.com", 1]);

    // The exact address still resolves through the same path.
    const exact = makeProxy();
    exact.respondWith([bobRow]);
    const found = await run(
      exact,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* Auth.lookupIdentifier(store, "email", "bob@example.com");
      }),
    );
    expect(found?.userId).toBe("user-bob");
  });

  it("batches the same way through the request resolvers", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow(projection.users.names, {
        id: "user-1",
        name: "Ada",
        image: null,
        passwordHash: "argon2id$hash",
        attributes: {},
        createdAt: "2026-01-01 00:00:00.000",
        updatedAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const [user, missing] = await Effect.runPromise(
      Effect.all([Requests.getUser("user-1"), Requests.getUser("ghost")], {
        concurrency: "unbounded",
      }).pipe(Effect.provide(Requests.layer(tables).pipe(Layer.provide(databaseLayer(proxy.db))))),
    );

    // Two reads, two ids, one query.
    expect(proxy.statements).toHaveLength(1);
    expect(proxy.statements[0]?.sql).toContain("`id` in (?, ?)");
    expect(user?.id).toBe("user-1");
    expect(missing).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

describe("MySQL / Schema", () => {
  it("emits MySQL DDL with the indexes inline", () => {
    const statements = migrationStatements();
    // One per table: MySQL has no `CREATE INDEX IF NOT EXISTS`.
    expect(statements).toHaveLength(6);
    expect(statements[0]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_users");
    expect(statements[0]).toContain("id VARCHAR(255) NOT NULL PRIMARY KEY");
    expect(statements[0]).toContain("attributes JSON NOT NULL");
    expect(statements[0]).toContain("created_at DATETIME(3) NOT NULL");
    // No email columns on users: handles live in the identifiers table.
    expect(statements[0]).not.toContain("email");
    expect(statements[1]).toContain("KEY effect_auth_sessions_user_id_idx (user_id)");
    expect(statements[2]).toContain("verified TINYINT NOT NULL DEFAULT 0");
    expect(statements[2]).toContain(
      "UNIQUE KEY effect_auth_identifiers_type_value_key (type, value)",
    );
  });

  it("declares identifier values under a binary collation, in the table and the DDL (#602)", () => {
    expect(identifierCollation).toBe("utf8mb4_bin");
    // The drizzle column, as drizzle-kit emits it.
    expect(tables.identifiers.value.getSQLType()).toBe(
      "varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
    );
    expect(tables.identifiers.value.notNull).toBe(true);
    expect(migrationStatements()[2]).toContain(
      "value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,",
    );
    // The unique key covers that column, so it is binary too.
    expect(migrationStatements()[2]).toContain("(type, value)");
    // An application's own identifier column gets the same type.
    const appUsers = mysqlTable("app_users", {
      email: binaryVarchar("email", { length: 320 }).unique(),
    });
    expect(appUsers.email.getSQLType()).toBe(
      "varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
    );
  });

  it("converts an existing identifiers table with a one-off migration (#602)", () => {
    expect(collationMigrationStatements()).toEqual([
      "ALTER TABLE effect_auth_identifiers MODIFY value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
    ]);
    expect(collationMigrationStatements({ identifiers: "app_handles" })).toEqual([
      "ALTER TABLE app_handles MODIFY value VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
    ]);
    // The everyday script stays replayable and leaves existing tables alone.
    expect(migrationStatements().join("\n")).not.toContain("ALTER TABLE");
  });

  it("honours custom table names in both the tables and the DDL", () => {
    const custom = defineTables({ sessions: "app_sessions" });
    expect(Struct.keys(getTableColumns(custom.sessions))).toEqual([
      "id",
      "userId",
      "expiresAt",
      "createdAt",
      "lastActivityAt",
      "attributes",
    ]);
    const sql = migrationStatements({ sessions: "app_sessions" }).join("\n");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS app_sessions");
    expect(sql).toContain("KEY app_sessions_user_id_idx (user_id)");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS effect_auth_users");
  });

  it("keeps the same column names as the other dialects", () => {
    const columnNames = (table: Tables[keyof Tables]) =>
      R.values<string, { readonly name: string }>(getTableColumns(table)).map(
        (column) => column.name,
      );
    expect(columnNames(tables.sessions)).toEqual([
      "id",
      "user_id",
      "expires_at",
      "created_at",
      "last_activity_at",
      "attributes",
    ]);
    expect(columnNames(tables.identifiers)).toEqual([
      "id",
      "user_id",
      "type",
      "value",
      "verified",
      "verified_at",
      "created_at",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

describe("MySQL / types", () => {
  it("is a member of the shared Tables union and a valid database handle", () => {
    // Compile-time assertions; the runtime expectations only keep them live.
    const asAnyTables: AnyTables = tables;
    const anyMySqlHandle = (
      db: MySqlDatabase<MySqlQueryResultHKT, PreparedQueryHKTBase, Record<string, never>>,
    ) => databaseLayer(db);

    expect(asAnyTables.sessions).toBe(tables.sessions);
    expect(P.isFunction(anyMySqlHandle)).toBe(true);
  });

  it("produces rows interchangeable with the PostgreSQL ones", () => {
    // A MySQL row is usable everywhere a PostgreSQL row is, and vice versa —
    // which is exactly why one store implementation covers both.
    const fromMySql = (row: Tables["sessions"]["$inferSelect"]): Pg.SessionRow => row;
    const fromPg = (row: Pg.IdentifierRow): Tables["identifiers"]["$inferSelect"] => row;
    const session = {
      id: "s",
      userId: "u",
      expiresAt: at(0),
      createdAt: at(0),
      lastActivityAt: at(0),
      attributes: {},
    };

    expect(fromMySql(session)).toBe(session);
    expect(P.isFunction(fromPg)).toBe(true);
  });
});
