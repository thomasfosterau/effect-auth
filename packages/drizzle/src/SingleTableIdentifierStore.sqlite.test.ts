/**
 * The single-table `IdentifierStore` over SQLite (better-sqlite3, in-process),
 * against application-shaped users tables: text keys, a unique `email` that is
 * nullable or NOT NULL, the verified flag as an integer boolean, and optionally
 * the verification time.
 *
 * Runs the same shared contract suites as the PostgreSQL file, on a synchronous
 * driver: the nullable table, the NOT NULL table, and the mapped
 * `email_verified_at`.
 */

import Database from "better-sqlite3";
import { eq } from "drizzle-orm";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { Effect, Layer } from "effect";
import { afterEach, beforeEach } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer } from "./SingleTableIdentifierStore.ts";
import {
  identifierStoreContract,
  notNullContract,
  singleTableContract,
  USER,
  USER_CREATED_AT,
  verifiedAtContract,
} from "./testing/IdentifierStoreContract.ts";

/** The application's users table: text key, nullable unique email. */
const appUsers = sqliteTable("app_users", {
  userId: text("id").primaryKey(),
  name: text("name"),
  email: text("email").unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

/** The same, with `email` NOT NULL. */
const strictUsers = sqliteTable("app_users_strict", {
  userId: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

/** The nullable table, with the application's verification-time column. */
const verifiedUsers = sqliteTable("app_users_verified", {
  userId: text("id").primaryKey(),
  email: text("email").unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  emailVerifiedAt: integer("email_verified_at", { mode: "timestamp_ms" }),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
});

const usersMapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

const strictMapping = defineUsers({
  table: strictUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
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

/** A fresh in-memory database per test, so no row outlives its test. */
let client: Database.Database;
let db: BetterSQLite3Database;

beforeEach(() => {
  client = new Database(":memory:");
  client.exec(`
    CREATE TABLE app_users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE app_users_strict (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE app_users_verified (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      email_verified_at INTEGER,
      created_at INTEGER NOT NULL
    );
  `);
  db = drizzle(client);
});

afterEach(() => {
  client.close();
});

const runWith = <A, E>(
  mapping: Parameters<typeof layer>[0],
  build: () => Effect.Effect<A, E, Auth.IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    build().pipe(
      Effect.provide(layer(mapping).pipe(Layer.provide(databaseLayer(db)))),
    ) as Effect.Effect<A, E>,
  );

const run = <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
  runWith(usersMapping, build);

const harness = {
  run,
  seedUsers: async (): Promise<void> => {
    db.insert(appUsers)
      .values([
        { userId: USER.ada, createdAt: USER_CREATED_AT, updatedAt: USER_CREATED_AT },
        { userId: USER.grace, createdAt: USER_CREATED_AT, updatedAt: USER_CREATED_AT },
      ])
      .run();
  },
  readUserRow: async (userId: string) =>
    db
      .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
      .from(appUsers)
      .where(eq(appUsers.userId, userId))
      .limit(1)
      .all()[0] ?? null,
};

identifierStoreContract("single-table SQLite", harness);
singleTableContract("single-table SQLite", harness);

notNullContract("single-table SQLite", {
  run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    runWith(strictMapping, build),
  seedUsers: async () => {
    db.insert(strictUsers)
      .values([
        { userId: USER.ada, email: "ada@example.com", createdAt: USER_CREATED_AT },
        { userId: USER.grace, email: "grace@example.com", createdAt: USER_CREATED_AT },
      ])
      .run();
  },
  readUserRow: async (userId: string) =>
    db
      .select({ email: strictUsers.email, emailVerified: strictUsers.emailVerified })
      .from(strictUsers)
      .where(eq(strictUsers.userId, userId))
      .limit(1)
      .all()[0] ?? null,
  deleteUserRow: async (userId: string) => {
    db.delete(strictUsers).where(eq(strictUsers.userId, userId)).run();
  },
});

verifiedAtContract("single-table SQLite", {
  run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    runWith(verifiedMapping, build),
  seedUsers: async () => {
    db.insert(verifiedUsers)
      .values([
        { userId: USER.ada, createdAt: USER_CREATED_AT },
        { userId: USER.grace, createdAt: USER_CREATED_AT },
      ])
      .run();
  },
  readUserRow: async (userId: string) =>
    db
      .select({ email: verifiedUsers.email, emailVerified: verifiedUsers.emailVerified })
      .from(verifiedUsers)
      .where(eq(verifiedUsers.userId, userId))
      .limit(1)
      .all()[0] ?? null,
  readVerifiedAt: async (userId: string) =>
    db
      .select({ verifiedAt: verifiedUsers.emailVerifiedAt })
      .from(verifiedUsers)
      .where(eq(verifiedUsers.userId, userId))
      .limit(1)
      .all()[0]?.verifiedAt ?? null,
});
