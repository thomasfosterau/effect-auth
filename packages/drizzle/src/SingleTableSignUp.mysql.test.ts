/**
 * Core sign-up over the single-table `IdentifierStore` on MySQL, without a MySQL
 * server (#380).
 *
 * As in `SingleTableIdentifierStore.mysql.test.ts`, the dialect runs through
 * `drizzle-orm/mysql-proxy`: what is pinned is the SQL a server would receive.
 * On a NOT NULL `email` column the application's writer inserts the row with
 * the address core passes it, and the claim that follows reads the address back
 * from the row and writes nothing.
 */

import { boolean, datetime, mysqlTable, varchar } from "drizzle-orm/mysql-core";
import { drizzle, type MySqlRemoteDatabase } from "drizzle-orm/mysql-proxy";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer } from "./SingleTableIdentifierStore.ts";
import { makeAppWriter, type UserRowInsert } from "./testing/SingleTableSignUpContract.ts";

/** The application's users table with `email` NOT NULL. */
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

interface Statement {
  readonly sql: string;
  readonly params: ReadonlyArray<unknown>;
}

/**
 * A proxy that records every statement and answers each `SELECT` on `email` with
 * the row the last `INSERT` wrote, or no row before any insert: the table as a
 * server would hold it after the application's writer ran.
 */
const makeProxy = () => {
  const statements: Array<Statement> = [];
  let inserted: ReadonlyArray<unknown> | null = null;
  const db: MySqlRemoteDatabase = drizzle(async (sql, params, method) => {
    statements.push({ sql, params });
    if (sql.startsWith("insert")) {
      // (`id`, `email`, `email_verified`, `created_at`), in the projection's order.
      inserted = [params[0], params[1], params[2] ? 1 : 0, "2026-10-15 00:00:00.000"];
    }
    if (method === "all") return { rows: inserted === null ? [] : [inserted as Array<unknown>] };
    return { rows: [{ insertId: 0, affectedRows: 1 }] };
  });
  return { db, statements };
};

describe("single-table MySQL / core sign-up on a NOT NULL email", () => {
  it("inserts the row with the address, then reads it back on users.email and writes nothing more", async () => {
    const proxy = makeProxy();
    const writer = makeAppWriter(async (row: UserRowInsert) => {
      await proxy.db
        .insert(strictUsers)
        .values({ ...row, userId: row.id, email: row.email as string });
    }, "writes");

    const result = await Effect.runPromise(
      writer
        .withService((service) =>
          service.signUp({ email: "ada@example.com", password: "correct horse battery staple" }),
        )
        .pipe(Effect.provide(layer(strictMapping).pipe(Layer.provide(databaseLayer(proxy.db))))),
    );

    const select =
      "select `id`, `email`, `email_verified`, `created_at` from `app_users_strict` where `app_users_strict`.`email` = ? limit ?";
    expect(proxy.statements.map((statement) => statement.sql)).toEqual([
      // Core's check that the address is free.
      select,
      // The application's writer, with the address core passed it.
      "insert into `app_users_strict` (`id`, `email`, `email_verified`, `created_at`) values (?, ?, ?, ?)",
      // The claim finds the address on the row, and the re-read confirms it is
      // this user's: no UPDATE follows.
      select,
      select,
    ]);
    expect(proxy.statements[1]?.params.slice(0, 3)).toEqual([
      result.user.id,
      "ada@example.com",
      false,
    ]);
    expect(writer.createdWith).toEqual([
      { type: "email", value: "ada@example.com", verified: false },
    ]);
    expect(result.identifier).toEqual({ type: "email", value: "ada@example.com" });
  });
});
