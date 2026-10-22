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

/** The same table with `email` NOT NULL: the store cannot clear an address on it. */
const strictUsers = mysqlTable("app_users_strict", {
  userId: varchar("id", { length: 255 }).primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
});

const strictMapping = defineUsers({
  table: strictUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

/** The nullable table with the application's verification-time column mapped. */
const verifiedUsers = mysqlTable("app_users_verified", {
  userId: varchar("id", { length: 255 }).primaryKey(),
  email: varchar("email", { length: 255 }).unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  emailVerifiedAt: datetime("email_verified_at", { mode: "date", fsp: 3 }),
  createdAt: datetime("created_at", { mode: "date", fsp: 3 }).notNull(),
});

const verifiedMapping = defineUsers({
  table: verifiedUsers,
  columns: {
    id: "userId",
    email: "email",
    emailVerified: "emailVerified",
    emailVerifiedAt: "emailVerifiedAt",
    createdAt: "createdAt",
  },
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

const runWith = <A, E>(
  proxy: Proxy,
  mapping: Parameters<typeof layer>[0],
  program: Effect.Effect<A, E, Auth.IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(layer(mapping).pipe(Layer.provide(databaseLayer(proxy.db)))),
    ) as Effect.Effect<A, E>,
  );

const run = <A, E>(proxy: Proxy, program: Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
  runWith(proxy, usersMapping, program);

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

    expect(error._tag).toBe("IdentifierRefusedError");
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

describe("single-table MySQL / replace", () => {
  const from: Auth.Identifier = {
    id: USER_ID,
    userId: USER_ID,
    type: "email",
    value: "ada@example.com",
    verified: true,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  };
  const to = Auth.makeIdentifier({
    userId: USER_ID,
    type: "email",
    value: "ada-new@example.com",
    verified: true,
  });

  it("rewrites the address with one UPDATE guarded on the old address, then reads the row", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow({
        id: USER_ID,
        email: "ada-new@example.com",
        emailVerified: 1,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const replaced = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.replace(from, to);
      }),
    );

    expect(proxy.statements).toHaveLength(2);
    const [update, read] = proxy.statements;
    expect(update?.sql).toBe(
      "update `app_users` set `email` = ?, `email_verified` = ? where (`app_users`.`id` = ? and `app_users`.`email` = ?)",
    );
    expect(update?.params).toEqual(["ada-new@example.com", true, USER_ID, "ada@example.com"]);
    expect(read?.sql).toMatch(/^select /);
    expect(replaced?.id).toBe(USER_ID);
    expect(replaced?.value).toBe("ada-new@example.com");
  });

  it("sends the same UPDATE on a NOT NULL column: no NULL is ever written", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow({
        id: USER_ID,
        email: "ada-new@example.com",
        emailVerified: 1,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    await runWith(
      proxy,
      strictMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.replace(from, to);
      }),
    );

    expect(proxy.statements[0]?.sql).toBe(
      "update `app_users_strict` set `email` = ?, `email_verified` = ? where (`app_users_strict`.`id` = ? and `app_users_strict`.`email` = ?)",
    );
    expect(proxy.statements[0]?.params).not.toContain(null);
  });

  it("writes the replacement's verification time when the column is mapped", async () => {
    const proxy = makeProxy();
    const verifiedAt = new Date("2026-01-02T09:30:00.000Z");

    await runWith(
      proxy,
      verifiedMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.replace(from, { ...to, verifiedAt });
      }),
    );

    expect(proxy.statements[0]?.sql).toBe(
      "update `app_users_verified` set `email` = ?, `email_verified` = ?, `email_verified_at` = ? where (`app_users_verified`.`id` = ? and `app_users_verified`.`email` = ?)",
    );
    expect(proxy.statements[0]?.params).toEqual([
      "ada-new@example.com",
      true,
      "2026-01-02 09:30:00.000",
      USER_ID,
      "ada@example.com",
    ]);
  });

  it("refuses a replacement for another user without sending a statement", async () => {
    const proxy = makeProxy();

    const error = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* Effect.flip(store.replace(from, { ...to, userId: "someone-else" }));
      }),
    );

    expect(error._tag).toBe("AuthError");
    expect(proxy.statements).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// NOT NULL email and the mapped verification time
// ---------------------------------------------------------------------------

describe("single-table MySQL / NOT NULL email", () => {
  it("refuses a targeted delete while the row holds the address, sending no UPDATE", async () => {
    const proxy = makeProxy();
    // The row exists and holds an address: the read the refusal depends on.
    proxy.respondWith([
      wireRow({
        id: USER_ID,
        email: "ada@example.com",
        emailVerified: 0,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const error = await runWith(
      proxy,
      strictMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* Effect.flip(store.delete(USER_ID));
      }),
    );

    expect(error._tag).toBe("AuthError");
    expect(error.message).toContain("NOT NULL");
    expect(proxy.statements).toHaveLength(1);
    expect(proxy.statements[0]?.sql).toMatch(/^select /i);
    expect(proxy.statements.some((statement) => /^update /i.test(statement.sql))).toBe(false);
  });

  it("sends no statement for deleteByUser, so account deletion's row delete removes the address", async () => {
    const proxy = makeProxy();

    await runWith(
      proxy,
      strictMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.deleteByUser(USER_ID);
      }),
    );

    expect(proxy.statements).toEqual([]);
  });
});

describe("single-table MySQL / mapped emailVerifiedAt", () => {
  const wireVerifiedRow = (verifiedAt: string | null) => [
    USER_ID,
    "ada@example.com",
    1,
    "2026-01-01 00:00:00.000",
    verifiedAt,
  ];

  it("writes the verification time to its own column on setVerified, and reads it back", async () => {
    const proxy = makeProxy();
    proxy.respondWith([wireVerifiedRow("2026-01-02 09:30:00.000")]);
    const verifiedAt = new Date("2026-01-02T09:30:00.000Z");

    const verified = await runWith(
      proxy,
      verifiedMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.setVerified(USER_ID, verifiedAt);
      }),
    );

    const [update] = proxy.statements;
    expect(update?.sql).toBe(
      "update `app_users_verified` set `email_verified` = ?, `email_verified_at` = ? where (`app_users_verified`.`id` = ? and `app_users_verified`.`email` is not null)",
    );
    expect(update?.params).toEqual([true, "2026-01-02 09:30:00.000", USER_ID]);
    expect(verified?.verifiedAt).toEqual(verifiedAt);
  });

  it("clears the verification time with the address on delete", async () => {
    const proxy = makeProxy();

    await runWith(
      proxy,
      verifiedMapping,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.delete(USER_ID);
      }),
    );

    expect(proxy.statements).toHaveLength(1);
    expect(proxy.statements[0]?.sql).toBe(
      "update `app_users_verified` set `email` = ?, `email_verified` = ?, `email_verified_at` = ? where `app_users_verified`.`id` = ?",
    );
    expect(proxy.statements[0]?.params).toEqual([null, false, null, USER_ID]);
  });

  it("writes no verification-time column when the mapping omits it", async () => {
    const proxy = makeProxy();
    proxy.respondWith([
      wireRow({
        id: USER_ID,
        email: "ada@example.com",
        emailVerified: 1,
        createdAt: "2026-01-01 00:00:00.000",
      }),
    ]);

    const verified = await run(
      proxy,
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        return yield* store.setVerified(USER_ID, new Date("2026-01-02T09:30:00.000Z"));
      }),
    );

    expect(proxy.statements[0]?.sql).not.toContain("email_verified_at");
    expect(verified && "verifiedAt" in verified).toBe(false);
  });
});
