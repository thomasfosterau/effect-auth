/**
 * The single-table `IdentifierStore` over PostgreSQL (PGlite), against an
 * application-shaped users table: `uuid` keys, a nullable unique `email`, the
 * verified flag on the row.
 *
 * Runs the shared contract (`testing/IdentifierStoreContract.ts`) and the
 * single-table semantics, then the one behaviour that depends on the database
 * rather than the store: a `NOT NULL` email column cannot be cleared.
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
  singleTableContract,
  USER,
  USER_CREATED_AT,
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
  `);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users", "app_users_strict"]);
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

describe("single-table PostgreSQL: NOT NULL email", () => {
  it("cannot clear an address on a NOT NULL column: delete fails with AuthError and the address stays", async () => {
    await drizzle(client).insert(strictUsers).values({
      userId: USER.ada,
      email: "ada@example.com",
      emailVerified: true,
      createdAt: USER_CREATED_AT,
    });

    const result = await runWith(strictMapping, () =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        const failed = yield* Effect.flip(store.delete(USER.ada));
        return {
          failed,
          still: yield* store.getByValue("email", "ada@example.com"),
        };
      }),
    );

    expect(result.failed._tag).toBe("AuthError");
    expect(result.failed.message).toBe("drizzle identifier.delete failed");
    expect(result.still?.userId).toBe(USER.ada);
  });
});
