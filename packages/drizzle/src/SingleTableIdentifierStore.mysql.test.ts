/**
 * The single-table `IdentifierStore` over MySQL, without a MySQL server.
 *
 * As in `MySqlSchema.test.ts`, the dialect is exercised through
 * `drizzle-orm/mysql-proxy`: the statements the store sends are the statements a
 * MySQL server would receive, and rows are answered in the driver's wire shape.
 * The engine is not here, so the contract suites (which need a unique index to
 * refuse a duplicate, and real rows to read back) cannot run on this dialect.
 * What is pinned instead: the SQL each method sends, the mapping of wire rows
 * (`tinyint` booleans, datetimes, a `NULL` email holding no identifier), and the
 * refusals that happen before any statement is sent.
 */

import { boolean, datetime, mysqlTable, varchar } from "drizzle-orm/mysql-core";
import { drizzle, type MySqlRemoteDatabase } from "drizzle-orm/mysql-proxy";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer } from "./SingleTableIdentifierStore.ts";

const appUsers = mysqlTable("app_users", {
  userId: varchar("id", { length: 255 }).primaryKey(),
  name: varchar("name", { length: 255 }),
  email: varchar("email", { length: 255 }).unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
  updatedAt: datetime("updated_at", { mode: "date", fsp: 3 }).notNull(),
});

const usersMapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

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
    statements.push({ sql, params });
    if (method === "all") {
      const rows = queued;
      queued = [];
      return { rows: rows as Array<Array<unknown>> };
    }
    return { rows: [{ insertId: 0, affectedRows: 1 }] };
  });
  return {
    db,
    statements,
    respondWith: (rows) => {
      queued = rows;
    },
  };
};

/** A row in the order the store projects its columns, carrying driver values. */
const wireRow = (values: {
  readonly id: unknown;
  readonly email: unknown;
  readonly emailVerified: unknown;
  readonly createdAt: unknown;
}): ReadonlyArray<unknown> => [values.id, values.email, values.emailVerified, values.createdAt];

const run = <A, E>(proxy: Proxy, program: Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(layer(usersMapping).pipe(Layer.provide(databaseLayer(proxy.db)))),
    ) as Effect.Effect<A, E>,
  );

const USER_ID = "5e1f0c3a-7b1d-4a53-9c0e-00000000000a";

// ---------------------------------------------------------------------------
// The SQL a MySQL server would receive
// ---------------------------------------------------------------------------

describe("single-table MySQL / statements", () => {
  it("looks an email up on users.email, and answers a NULL-email row with no identifier", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow({
        id: USER_ID,
        email: "ada@example.com",
        emailVerified: 1,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const found = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.getByValue("email", "ada@example.com");
      }),
    );

    expect(proxy.statements).toHaveLength(1);
    expect(proxy.statements[0]?.sql).toContain("`app_users`.`email` = ?");
    expect(proxy.statements[0]?.params).toContain("ada@example.com");
    // tinyint 1 read back as a real boolean; the id doubles as the identifier id.
    expect(found).toEqual({
      id: USER_ID,
      userId: USER_ID,
      type: "email",
      value: "ada@example.com",
      verified: true,
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
  });

  it("holds no identifier for a row whose email is NULL", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow({ id: USER_ID, email: null, emailVerified: 0, createdAt: "2026-01-01 00:00:00.000" }),
    ]);

    const listed = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.listByUser(USER_ID);
      }),
    );

    expect(listed).toEqual([]);
    expect(proxy.statements[0]?.sql).toContain("is not null");
  });

  it("resolves a non-email type to null without sending a statement", async () => {
    const proxy = makeProxy();

    const found = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.getByValue("username", "ada");
      }),
    );

    expect(found).toBeNull();
    expect(proxy.statements).toEqual([]);
  });

  it("refuses to create a non-email identifier without sending a statement", async () => {
    const proxy = makeProxy();

    const error = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* Effect.flip(
          store.create(
            Auth.makeIdentifier({ userId: USER_ID, type: "phone", value: "+61400000000" }),
          ),
        );
      }),
    );

    expect(error._tag).toBe("AuthError");
    expect(proxy.statements).toEqual([]);
  });

  it("clears the address with an UPDATE of the two email columns, keeping the row", async () => {
    const proxy = makeProxy();

    await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.delete(USER_ID);
      }),
    );

    expect(proxy.statements).toHaveLength(1);
    const [update] = proxy.statements;
    expect(update?.sql).toBe(
      "update `app_users` set `email` = ?, `email_verified` = ? where `app_users`.`id` = ?",
    );
    expect(update?.params).toEqual([null, false, USER_ID]);
    expect(proxy.statements.some((statement) => /\bdelete\b/i.test(statement.sql))).toBe(false);
  });
});
