/**
 * Core sign-up over the single-table `IdentifierStore` on SQLite (better-sqlite3,
 * in-process), on a NOT NULL `email` column and on a nullable one (#380).
 *
 * The same suite as the PostgreSQL file (`testing/SingleTableSignUpContract.ts`),
 * on a synchronous driver with text keys and an integer boolean.
 */

import Database from "better-sqlite3";
import { count, eq } from "drizzle-orm";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { Effect, Layer } from "effect";
import { afterEach, beforeEach } from "vite-plus/test";
import type * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer, type SingleTableUsers } from "./SingleTableIdentifierStore.ts";
import { signUpContract, type UserRowInsert } from "./testing/SingleTableSignUpContract.ts";

/** The application's users table with `email` NOT NULL. */
const strictUsers = sqliteTable("app_users_strict", {
  userId: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

/** The same table with a nullable `email`. */
const appUsers = sqliteTable("app_users", {
  userId: text("id").primaryKey(),
  email: text("email").unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

const columns = {
  id: "userId",
  email: "email",
  emailVerified: "emailVerified",
  createdAt: "createdAt",
} as const;
const strictMapping = defineUsers({ table: strictUsers, columns });
const mapping = defineUsers({ table: appUsers, columns });

/** A fresh in-memory database per test, so no row outlives its test. */
let client: Database.Database;
let db: BetterSQLite3Database;

beforeEach(() => {
  client = new Database(":memory:");
  client.exec(`
    CREATE TABLE app_users_strict (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE app_users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
  `);
  db = drizzle(client);
});

afterEach(() => {
  client.close();
});

const runWith =
  (users: SingleTableUsers) =>
  <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    Effect.runPromise(
      build().pipe(
        Effect.provide(layer(users).pipe(Layer.provide(databaseLayer(db)))),
      ) as Effect.Effect<A, E>,
    );

signUpContract("single-table SQLite", false, {
  run: runWith(strictMapping),
  insertUser: async (row: UserRowInsert) => {
    db.insert(strictUsers)
      // A row without an address sends NULL, which the column's NOT NULL refuses.
      .values({ ...row, userId: row.id, email: row.email as string })
      .run();
  },
  readUserRow: async (userId) =>
    db
      .select({ email: strictUsers.email, emailVerified: strictUsers.emailVerified })
      .from(strictUsers)
      .where(eq(strictUsers.userId, userId))
      .all()[0] ?? null,
  countUserRows: async () => db.select({ n: count() }).from(strictUsers).all()[0]?.n ?? 0,
});

signUpContract("single-table SQLite", true, {
  run: runWith(mapping),
  insertUser: async (row: UserRowInsert) => {
    db.insert(appUsers)
      .values({ ...row, userId: row.id })
      .run();
  },
  readUserRow: async (userId) =>
    db
      .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
      .from(appUsers)
      .where(eq(appUsers.userId, userId))
      .all()[0] ?? null,
  countUserRows: async () => db.select({ n: count() }).from(appUsers).all()[0]?.n ?? 0,
});
