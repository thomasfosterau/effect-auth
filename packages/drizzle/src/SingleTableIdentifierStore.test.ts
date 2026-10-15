/**
 * The single-table `IdentifierStore` over PostgreSQL (PGlite), against
 * application-shaped users tables: `uuid` keys, a unique `email` that is either
 * nullable or NOT NULL, the verified flag on the row, and optionally the
 * verification time.
 *
 * Runs the shared contract (`testing/IdentifierStoreContract.ts`) for each shape:
 * the nullable table, the NOT NULL table (where a delete is refused and account
 * deletion removes the row), and the table that maps `email_verified_at`.
 */

import type { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
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
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

/** The application's users table: `uuid` key, nullable unique email. */
const appUsers = pgTable("app_users", {
  userId: uuid("id").primaryKey(),
  name: text("name"),
  email: text("email").unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The same, with `email` NOT NULL: the store cannot clear an address on it. */
const strictUsers = pgTable("app_users_strict", {
  userId: uuid("id").primaryKey(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The nullable table, with the application's own verification-time column mapped. */
const verifiedUsers = pgTable("app_users_verified", {
  userId: uuid("id").primaryKey(),
  email: text("email").unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  emailVerifiedAt: timestamp("email_verified_at", { mode: "date", withTimezone: true }),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

const usersMapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

const strictMapping = defineUsers({
  table: strictUsers,
  columns: {
    id: "userId",
    email: "email",
    emailVerified: "emailVerified",
    createdAt: "createdAt",
  },
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

/** The file's one in-memory Postgres, opened from the run's migrated template. */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(`
    CREATE TABLE IF NOT EXISTS app_users (
      id uuid PRIMARY KEY,
      name text,
      email text UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    );
    CREATE TABLE IF NOT EXISTS app_users_strict (
      id uuid PRIMARY KEY,
      email text NOT NULL UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL
    );
    CREATE TABLE IF NOT EXISTS app_users_verified (
      id uuid PRIMARY KEY,
      email text UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      email_verified_at timestamptz,
      created_at timestamptz NOT NULL
    );
  `);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users", "app_users_strict", "app_users_verified"]);
});

/** Run `build` against a single-table store over `mapping`, on the file's database. */
const runWith = <A, E>(
  mapping: Parameters<typeof layer>[0],
  build: () => Effect.Effect<A, E, Auth.IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    build().pipe(
      Effect.provide(layer(mapping).pipe(Layer.provide(databaseLayer(drizzle(client))))),
    ) as Effect.Effect<A, E>,
  );

/** Insert the users the contract expects, with no login handle. */
const seedUsers = async (): Promise<void> => {
  await drizzle(client)
    .insert(appUsers)
    .values([
      { userId: USER.ada, createdAt: USER_CREATED_AT, updatedAt: USER_CREATED_AT },
      { userId: USER.grace, createdAt: USER_CREATED_AT, updatedAt: USER_CREATED_AT },
    ]);
};

const readUserRow = async (userId: string) => {
  const rows = await drizzle(client)
    .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
    .from(appUsers)
    .where(eq(appUsers.userId, userId))
    .limit(1);
  return rows[0] ?? null;
};

const harness = {
  run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    runWith(usersMapping, build),
  seedUsers,
  readUserRow,
};

identifierStoreContract("single-table PostgreSQL", harness);
singleTableContract("single-table PostgreSQL", harness);

// The NOT NULL table: both users hold an address from the start, as the
// application's own writer leaves them.
notNullContract("single-table PostgreSQL", {
  run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    runWith(strictMapping, build),
  seedUsers: async () => {
    await drizzle(client)
      .insert(strictUsers)
      .values([
        {
          userId: USER.ada,
          email: "ada@example.com",
          createdAt: USER_CREATED_AT,
        },
        {
          userId: USER.grace,
          email: "grace@example.com",
          createdAt: USER_CREATED_AT,
        },
      ]);
  },
  readUserRow: async (userId: string) => {
    const rows = await drizzle(client)
      .select({ email: strictUsers.email, emailVerified: strictUsers.emailVerified })
      .from(strictUsers)
      .where(eq(strictUsers.userId, userId))
      .limit(1);
    return rows[0] ?? null;
  },
  deleteUserRow: async (userId: string) => {
    await drizzle(client).delete(strictUsers).where(eq(strictUsers.userId, userId));
  },
});

// The mapped verification time: the table's own `email_verified_at` column.
verifiedAtContract("single-table PostgreSQL", {
  run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    runWith(verifiedMapping, build),
  seedUsers: async () => {
    await drizzle(client)
      .insert(verifiedUsers)
      .values([
        { userId: USER.ada, createdAt: USER_CREATED_AT },
        { userId: USER.grace, createdAt: USER_CREATED_AT },
      ]);
  },
  readUserRow: async (userId: string) => {
    const rows = await drizzle(client)
      .select({ email: verifiedUsers.email, emailVerified: verifiedUsers.emailVerified })
      .from(verifiedUsers)
      .where(eq(verifiedUsers.userId, userId))
      .limit(1);
    return rows[0] ?? null;
  },
  readVerifiedAt: async (userId: string) => {
    const rows = await drizzle(client)
      .select({ verifiedAt: verifiedUsers.emailVerifiedAt })
      .from(verifiedUsers)
      .where(eq(verifiedUsers.userId, userId))
      .limit(1);
    return rows[0]?.verifiedAt ?? null;
  },
});

describe("defineUsers: NOT NULL detection", () => {
  it("reads the email column's NOT NULL setting: a primary key is NOT NULL, a unique column alone is nullable", () => {
    // A primary key cannot hold NULL, so the column is NOT NULL without a notNull().
    const keyedUsers = pgTable("app_users_keyed", {
      email: text("email").primaryKey(),
      userId: uuid("id").notNull().unique(),
      emailVerified: boolean("email_verified").notNull().default(false),
      createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
    });
    const keyed = defineUsers({
      table: keyedUsers,
      columns: {
        id: "userId",
        email: "email",
        emailVerified: "emailVerified",
        createdAt: "createdAt",
      },
    });

    expect(keyed.emailNullable).toBe(false);
    expect(usersMapping.emailNullable).toBe(true);
    expect(strictMapping.emailNullable).toBe(false);
  });
});
