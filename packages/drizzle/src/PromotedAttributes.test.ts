/**
 * Promoted attributes (#182): an attribute the application keeps as a real,
 * typed column — the applications' `users.role`, with its own `CHECK` — read
 * back into `user.attributes` by the user store, and a users table with no
 * `jsonb` attribute bag at all (the applications' `users` has none).
 *
 * Exercised against PGlite, with the `CHECK` enforced by Postgres.
 */

import type { PGlite } from "@electric-sql/pglite";
import { boolean, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer, Predicate } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { defineSchema } from "./Columns.ts";
import { databaseLayer } from "./Database.ts";
import { layer as storesLayer } from "./Layers.ts";
import * as Requests from "./Requests.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

// The applications' shape: uuid keys, `role` a real column, no attribute bag.
const users = pgTable("users", {
  id: uuid("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  role: text("role").notNull().default("user"),
  plan: text("plan"),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});
// The same, plus a bag — to pin which one wins.
const usersWithBag = pgTable("users_with_bag", {
  id: uuid("id").primaryKey(),
  name: text("name"),
  image: text("image"),
  meta: jsonb("meta").$type<Auth.Attributes>().notNull().default({}),
  role: text("role"),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});
const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: uuid("user_id").notNull(),
  expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  lastActivityAt: timestamp("last_activity_at", { mode: "date", withTimezone: true }).notNull(),
  attributes: jsonb("attributes").$type<Auth.Attributes>().notNull().default({}),
});
const identifiers = pgTable("identifiers", {
  id: uuid("id").primaryKey(),
  userId: uuid("user_id").notNull(),
  type: text("type").notNull(),
  value: text("value").notNull(),
  verified: boolean("verified").notNull().default(false),
  verifiedAt: timestamp("verified_at", { mode: "date", withTimezone: true }),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

const migration = `
  create table users (
    id uuid primary key, name text, image text,
    role text not null default 'user' constraint users_role_valid check (role in ('user', 'moderator', 'admin')),
    plan text,
    created_at timestamptz not null, updated_at timestamptz not null
  );
  create table users_with_bag (
    id uuid primary key, name text, image text, meta jsonb not null default '{}'::jsonb, role text,
    created_at timestamptz not null, updated_at timestamptz not null
  );
  create table sessions (id text primary key, user_id uuid not null, expires_at timestamptz not null,
    created_at timestamptz not null, last_activity_at timestamptz not null, attributes jsonb not null default '{}'::jsonb);
  create table identifiers (id uuid primary key, user_id uuid not null, type text not null, value text not null,
    verified boolean not null default false, verified_at timestamptz, created_at timestamptz not null);
`;

const sessionSpec = {
  table: sessions,
  columns: {
    id: "id",
    userId: "userId",
    expiresAt: "expiresAt",
    createdAt: "createdAt",
    lastActivityAt: "lastActivityAt",
    attributes: "attributes",
  },
} as const;
const identifierSpec = {
  table: identifiers,
  columns: {
    id: "id",
    userId: "userId",
    type: "type",
    value: "value",
    verified: "verified",
    verifiedAt: "verifiedAt",
    createdAt: "createdAt",
  },
} as const;

// No `attributes` mapping at all: every attribute this table has is a column.
const bagless = defineSchema({
  sessions: sessionSpec,
  users: {
    table: users,
    columns: {
      id: "id",
      name: "name",
      image: "image",
      createdAt: "createdAt",
      updatedAt: "updatedAt",
    },
    promoted: { role: "role", plan: "plan" },
  },
  identifiers: identifierSpec,
});

const withBag = defineSchema({
  sessions: sessionSpec,
  users: {
    table: usersWithBag,
    columns: {
      id: "id",
      name: "name",
      image: "image",
      attributes: "meta",
      createdAt: "createdAt",
      updatedAt: "updatedAt",
    },
    promoted: { role: "role" },
  },
  identifiers: identifierSpec,
});

/** Never called — compile-time assertions on the promoted mapping. */
const promotedRejects = () =>
  defineSchema({
    sessions: sessionSpec,
    users: {
      table: users,
      columns: {
        id: "id",
        name: "name",
        image: "image",
        createdAt: "createdAt",
        updatedAt: "updatedAt",
      },
      promoted: {
        // @ts-expect-error `createdAt` reads back as a Date, not an attribute value.
        joined: "createdAt",
        // @ts-expect-error no such column.
        tier: "tier",
      },
    },
    identifiers: identifierSpec,
  });

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);
const ids = {
  moderator: "3f1c0e8a-8b1a-4a5e-9c0e-0a1b2c3d4e5f",
  plain: "7a2d4b6c-1e3f-4058-9a7b-2c4d6e8f0a1b",
};

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291), with this file's applications tables applied on top, and emptied
 * before each test. The template's `effect_auth_*` tables are not used here.
 */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(migration);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["users", "users_with_bag", "sessions", "identifiers"]);
});

const withDatabase = async <A>(
  run: (client: PGlite, db: ReturnType<typeof drizzle>) => Promise<A>,
): Promise<A> => run(client, drizzle(client));

describe("promoted attributes", () => {
  it("rejects a promoted column that does not read back as an attribute value", () => {
    expect(Predicate.isFunction(promotedRejects)).toBe(true);
  });

  it("presents each promoted column in user.attributes, with no attribute bag at all", async () => {
    const [moderator, plain, batched] = await withDatabase(async (_client, db) => {
      await db.insert(users).values([
        {
          id: ids.moderator,
          name: "Mo",
          role: "moderator",
          plan: "pro",
          createdAt: at(0),
          updatedAt: at(0),
        },
        { id: ids.plain, name: "Pat", createdAt: at(0), updatedAt: at(0) },
      ]);
      const stores = Layer.mergeAll(storesLayer(bagless), Requests.layer(bagless)).pipe(
        Layer.provide(databaseLayer(db)),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* Auth.UserStore;
          return [
            yield* store.get(ids.moderator),
            yield* store.get(ids.plain),
            yield* Effect.all([Requests.getUser(ids.moderator), Requests.getUser(ids.plain)], {
              concurrency: "unbounded",
            }),
          ] as const;
        }).pipe(Effect.provide(stores)),
      );
    });

    expect(moderator?.attributes).toEqual({ role: "moderator", plan: "pro" });
    // The database default reads through; a NULL column leaves its key absent.
    expect(plain?.attributes).toEqual({ role: "user" });
    // The batched path projects the same way.
    expect(batched.map((user) => user?.attributes)).toEqual([
      { role: "moderator", plan: "pro" },
      { role: "user" },
    ]);
  });

  it("makes the column the sole authority for its key over the jsonb bag", async () => {
    const [promotedWins, nullColumn] = await withDatabase(async (_client, db) => {
      await db.insert(usersWithBag).values([
        {
          id: ids.moderator,
          meta: { role: "admin", theme: "dark" },
          role: "moderator",
          createdAt: at(0),
          updatedAt: at(0),
        },
        { id: ids.plain, meta: { role: "admin" }, role: null, createdAt: at(0), updatedAt: at(0) },
      ]);
      return Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* Auth.UserStore;
          return [yield* store.get(ids.moderator), yield* store.get(ids.plain)] as const;
        }).pipe(Effect.provide(storesLayer(withBag).pipe(Layer.provide(databaseLayer(db))))),
      );
    });

    // A stale `role` in the bag never leaks past the column that owns the key.
    expect(promotedWins?.attributes).toEqual({ role: "moderator", theme: "dark" });
    expect(nullColumn?.attributes).toEqual({});
  });

  it("is backed by the column's own CHECK: a rung off the ladder cannot be stored", async () => {
    await withDatabase(async (client) => {
      await expect(
        client.query(
          "insert into users (id, role, created_at, updated_at) values ($1, 'superadmin', now(), now())",
          [ids.plain],
        ),
      ).rejects.toThrow(/users_role_valid/);
    });
  });
});
