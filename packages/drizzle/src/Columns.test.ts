/**
 * The stores, bound to tables this package did not define.
 *
 * The schema below is deliberately nothing like `Pg.tables`: `uuid` primary
 * keys instead of `text`, every column under a different name in TypeScript
 * *and* in SQL, and two `NOT NULL` columns the stores know nothing about. It is
 * the shape an application adopting effect-auth in place actually has — one
 * whose entity graph already has foreign keys into `users.id` — and the point
 * of the mapping is that nothing about it has to change.
 *
 * Exercised against a real PostgreSQL engine (PGlite), so `uuid`, `jsonb` and
 * `timestamptz` behave as they do in production.
 */

import { PGlite } from "@electric-sql/pglite";
import { boolean, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { eq } from "drizzle-orm";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { type AuthSchema, defineSchema } from "./Columns.ts";
import { databaseLayer } from "./Database.ts";
import { layer as storesLayer } from "./Layers.ts";

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

// ---------------------------------------------------------------------------
// An application's own tables
// ---------------------------------------------------------------------------

const appUsers = pgTable("account", {
  /** `uuid`, not `text` — the rest of the application's graph points here. */
  key: uuid("account_id").primaryKey(),
  displayName: text("full_name"),
  avatar: text("avatar_url"),
  meta: jsonb("profile").$type<Record<string, unknown>>().notNull().default({}),
  /** A column the stores know nothing about, with a database-level default. */
  role: text("role").notNull().default("member"),
  born: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  touched: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

const appSessions = pgTable("login", {
  digest: text("token_digest").primaryKey(),
  account: uuid("account_id").notNull(),
  expires: timestamp("expires_at", { mode: "date", withTimezone: true }).notNull(),
  born: timestamp("started_at", { mode: "date", withTimezone: true }).notNull(),
  lastSeen: timestamp("last_seen_at", { mode: "date", withTimezone: true }).notNull(),
  meta: jsonb("context").$type<Record<string, unknown>>().notNull().default({}),
  /** Another one, likewise defaulted. */
  origin: text("origin").notNull().default("web"),
});

const appIdentifiers = pgTable("handle", {
  key: uuid("handle_id").primaryKey(),
  account: uuid("account_id").notNull(),
  /** Plain `text`, with no `$type` — an application's column usually is. */
  kind: text("kind").notNull(),
  normalized: text("normalized").notNull(),
  confirmed: boolean("is_confirmed").notNull().default(false),
  confirmedOn: timestamp("confirmed_at", { mode: "date", withTimezone: true }),
  born: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The application's own migration — this package emits none of it. */
const appMigration = [
  `CREATE TABLE account (
    account_id UUID PRIMARY KEY,
    full_name TEXT,
    avatar_url TEXT,
    profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE login (
    token_digest TEXT PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account(account_id),
    expires_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    origin TEXT NOT NULL DEFAULT 'web'
  )`,
  `CREATE TABLE handle (
    handle_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account(account_id),
    kind TEXT NOT NULL,
    normalized TEXT NOT NULL,
    is_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE UNIQUE INDEX handle_kind_normalized_key ON handle (kind, normalized)`,
];

// ---------------------------------------------------------------------------
// The mapping
// ---------------------------------------------------------------------------

const appSchema: AuthSchema = defineSchema({
  sessions: {
    table: appSessions,
    columns: {
      id: "digest",
      userId: "account",
      expiresAt: "expires",
      createdAt: "born",
      lastActivityAt: "lastSeen",
      attributes: "meta",
    },
  },
  users: {
    table: appUsers,
    columns: {
      id: "key",
      name: "displayName",
      image: "avatar",
      attributes: "meta",
      createdAt: "born",
      updatedAt: "touched",
    },
  },
  identifiers: {
    table: appIdentifiers,
    columns: {
      id: "key",
      userId: "account",
      type: "kind",
      value: "normalized",
      verified: "confirmed",
      verifiedAt: "confirmedOn",
      createdAt: "born",
    },
  },
});

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const userId = "3f1c0e8a-8b1a-4a5e-9c0e-0a1b2c3d4e5f";
const identifierId = "7a2d4b6c-1e3f-4058-9a7b-2c4d6e8f0a1b";

const runFresh = async <A, E>(
  build: (db: PgliteDatabase) => Effect.Effect<A, E, StoreServices>,
): Promise<A> => {
  const client = await PGlite.create();
  try {
    for (const statement of appMigration) {
      await client.exec(statement);
    }
    const db = drizzle(client);
    await db
      .insert(appUsers)
      .values({
        key: userId,
        displayName: "Ada",
        avatar: "https://example.com/ada.png",
        meta: { plan: "pro" },
        born: at(0),
        touched: at(5_000),
      })
      .execute();

    return await Effect.runPromise(
      build(db).pipe(
        Effect.provide(storesLayer(appSchema).pipe(Layer.provide(databaseLayer(db)))),
      ) as Effect.Effect<A, E>,
    );
  } finally {
    await client.close();
  }
};

// ---------------------------------------------------------------------------
// Type-level: what a mapping will and will not accept
// ---------------------------------------------------------------------------

/** Never called — every line is a compile-time assertion. */
const mappingRejects = (): unknown => [
  defineSchema({
    sessions: {
      table: appSessions,
      columns: {
        id: "digest",
        userId: "account",
        // @ts-expect-error `digest` is a text column; `expiresAt` needs a Date one.
        expiresAt: "digest",
        createdAt: "born",
        lastActivityAt: "lastSeen",
        attributes: "meta",
      },
    },
    users: {
      table: appUsers,
      columns: {
        id: "key",
        name: "displayName",
        image: "avatar",
        // @ts-expect-error `role` is text, not an attribute bag.
        attributes: "role",
        createdAt: "born",
        updatedAt: "touched",
      },
    },
    identifiers: {
      table: appIdentifiers,
      columns: {
        id: "key",
        userId: "account",
        type: "kind",
        // @ts-expect-error no such column on the application's table.
        value: "emailAddress",
        verified: "confirmed",
        verifiedAt: "confirmedOn",
        createdAt: "born",
      },
    },
  }),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("stores over an application's own schema", () => {
  it("rejects a mapping whose columns do not read back as the store needs", () => {
    expect(typeof mappingRejects).toBe("function");
  });

  it("reads a user out of uuid-keyed columns under the application's names", async () => {
    const user = await runFresh(() => Effect.flatMap(Auth.UserStore, (store) => store.get(userId)));

    expect(user).toEqual({
      id: userId,
      name: "Ada",
      image: "https://example.com/ada.png",
      attributes: { plan: "pro" },
      createdAt: at(0),
      updatedAt: at(5_000),
    });
  });

  it("round-trips a session, leaving the application's own columns to their defaults", async () => {
    const session: Auth.Session = {
      id: "digest-1",
      userId,
      expiresAt: at(60_000),
      createdAt: at(0),
      lastActivityAt: at(0),
      attributes: { device: "laptop" },
    };

    const result = await runFresh((db) =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(session);
        const read = yield* store.get("digest-1");
        yield* store.update({ ...session, lastActivityAt: at(30_000) });
        const listed = yield* store.listByUserId(userId);

        // The columns the stores know nothing about kept their defaults, which
        // is what makes an insert of "only the mapped columns" safe.
        const rows = yield* Effect.promise(() =>
          db.select().from(appSessions).where(eq(appSessions.digest, "digest-1")).execute(),
        );

        yield* store.delete("digest-1");
        return { read, listed, origin: rows[0]?.origin, afterDelete: yield* store.get("digest-1") };
      }),
    );

    expect(result.read).toEqual(session);
    expect(result.listed).toEqual([{ ...session, lastActivityAt: at(30_000) }]);
    expect(result.origin).toBe("web");
    expect(result.afterDelete).toBeNull();
  });

  it("claims and verifies an identifier through the application's columns", async () => {
    const identifier: Auth.Identifier = {
      id: identifierId,
      userId,
      type: "email",
      value: "ada@example.com",
      verified: false,
      createdAt: at(0),
    };

    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(identifier);
        const byValue = yield* store.getByValue("email", "ada@example.com");
        const verified = yield* store.setVerified(identifierId, at(10_000));
        const listed = yield* store.listByUser(userId);
        const missing = yield* store.getByValue("username", "ada");
        return { byValue, verified, listed, missing };
      }),
    );

    expect(result.byValue).toEqual(identifier);
    expect(result.verified).toEqual({
      ...identifier,
      verified: true,
      verifiedAt: at(10_000),
    });
    expect(result.listed).toHaveLength(1);
    expect(result.missing).toBeNull();
  });

  it("surfaces the application's own unique index as the claim mechanism", async () => {
    const exit = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create({
          id: identifierId,
          userId,
          type: "email",
          value: "ada@example.com",
          verified: false,
          createdAt: at(0),
        });
        return yield* Effect.exit(
          store.create({
            id: "2b3c4d5e-6f70-4812-9354-6a7b8c9d0e1f",
            userId,
            type: "email",
            value: "ada@example.com",
            verified: false,
            createdAt: at(1_000),
          }),
        );
      }),
    );

    expect(exit._tag).toBe("Failure");
  });
});
