/**
 * Core sign-up over the single-table `IdentifierStore` on PostgreSQL (PGlite),
 * on a NOT NULL `email` column and on a nullable one (#380).
 *
 * Core hands the store's `createUser` the address it signs the user up with; the
 * application's writer inserts the row holding it, and the claim that follows
 * finds it there. The shared suite is `testing/SingleTableSignUpContract.ts`.
 */

import type { PGlite } from "@electric-sql/pglite";
import { count, eq } from "drizzle-orm";
import { boolean, pgTable, timestamp, uuid, varchar } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach } from "vite-plus/test";
import type * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer, type SingleTableUsers } from "./SingleTableIdentifierStore.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";
import { signUpContract, type UserRowInsert } from "./testing/SingleTableSignUpContract.ts";

/** The application's users table with `email` NOT NULL. */
const strictUsers = pgTable("app_users_sign_up_strict", {
  userId: uuid("id").primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The same table with a nullable `email`. */
const appUsers = pgTable("app_users_sign_up", {
  userId: uuid("id").primaryKey(),
  email: varchar("email", { length: 255 }).unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

const columns = {
  id: "userId",
  email: "email",
  emailVerified: "emailVerified",
  createdAt: "createdAt",
} as const;
const strictMapping = defineUsers({ table: strictUsers, columns });
const mapping = defineUsers({ table: appUsers, columns });

let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(`
    CREATE TABLE IF NOT EXISTS app_users_sign_up_strict (
      id uuid PRIMARY KEY,
      email varchar(255) NOT NULL UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL
    );
    CREATE TABLE IF NOT EXISTS app_users_sign_up (
      id uuid PRIMARY KEY,
      email varchar(255) UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL
    );
  `);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users_sign_up_strict", "app_users_sign_up"]);
});

const runWith =
  (users: SingleTableUsers) =>
  <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
    Effect.runPromise(
      build().pipe(
        Effect.provide(layer(users).pipe(Layer.provide(databaseLayer(drizzle(client))))),
      ),
    );

signUpContract("single-table PostgreSQL", false, {
  run: runWith(strictMapping),
  insertUser: async (row: UserRowInsert) => {
    await drizzle(client)
      .insert(strictUsers)
      .values({
        ...row,
        userId: row.id,
        // SAFETY: deliberately unchecked: a row without an address must reach the
        // database as NULL, which the column's NOT NULL refuses.
        email: row.email as string,
      });
  },
  readUserRow: async (userId) => {
    const rows = await drizzle(client)
      .select({ email: strictUsers.email, emailVerified: strictUsers.emailVerified })
      .from(strictUsers)
      .where(eq(strictUsers.userId, userId));
    return rows[0] ?? null;
  },
  countUserRows: async () => {
    const [row] = await drizzle(client).select({ n: count() }).from(strictUsers);
    return row?.n ?? 0;
  },
});

signUpContract("single-table PostgreSQL", true, {
  run: runWith(mapping),
  insertUser: async (row: UserRowInsert) => {
    await drizzle(client)
      .insert(appUsers)
      .values({ ...row, userId: row.id });
  },
  readUserRow: async (userId) => {
    const rows = await drizzle(client)
      .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
      .from(appUsers)
      .where(eq(appUsers.userId, userId));
    return rows[0] ?? null;
  },
  countUserRows: async () => {
    const [row] = await drizzle(client).select({ n: count() }).from(appUsers);
    return row?.n ?? 0;
  },
});
