/**
 * The single-table `IdentifierStore` over SQLite (better-sqlite3, in-process),
 * against an application-shaped users table: text keys, a nullable unique
 * `email`, the verified flag as an integer boolean.
 *
 * Runs the same shared contract and single-table semantics as the PostgreSQL
 * suite, on a synchronous driver. The NOT NULL check is a PostgreSQL-only file;
 * the constraint itself is plain SQL on every engine.
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
  singleTableContract,
  USER,
  USER_CREATED_AT,
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

const usersMapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
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
    )
  `);
  db = drizzle(client);
});

afterEach(() => {
  client.close();
});

const run = <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
  Effect.runPromise(
    build().pipe(
      Effect.provide(layer(usersMapping).pipe(Layer.provide(databaseLayer(db)))),
    ) as Effect.Effect<A, E>,
  );

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
