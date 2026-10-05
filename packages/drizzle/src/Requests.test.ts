/**
 * The batched read interface, exercised against a real PostgreSQL engine
 * (PGlite — Postgres compiled to WASM, in-process, no server).
 *
 * These tests are about *how many* queries reach the database, not only what
 * comes back, so every handle is built with drizzle's own `logger` hook and the
 * emitted SQL is counted. Seeding happens first; the log is reset immediately
 * before the program under test, so the counts below are the program's alone.
 */

import type { PGlite } from "@electric-sql/pglite";
import type { Logger } from "drizzle-orm";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import type * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { tables } from "./PgSchema.ts";
import {
  AuthRequests,
  getIdentifierByValue,
  getSession,
  getUser,
  layer as requestsLayer,
  listIdentifiersByUser,
} from "./Requests.ts";
import { migratedPglite, truncateTables } from "./testing/PgliteTemplate.ts";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface QueryLog {
  readonly logger: Logger;
  readonly reset: () => void;
  /** Every `SELECT` this program sent to `table`. */
  readonly selectsOn: (table: string) => ReadonlyArray<string>;
}

const makeQueryLog = (): QueryLog => {
  let queries: Array<string> = [];
  return {
    logger: {
      logQuery: (query) => {
        queries.push(query);
      },
    },
    reset: () => {
      queries = [];
    },
    selectsOn: (table) =>
      queries.filter((query) => query.startsWith("select") && query.includes(`"${table}"`)),
  };
};

/**
 * The file's one in-memory Postgres, opened once from the run's migrated
 * template (#291) and shared by the tests.
 */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
});

afterAll(async () => {
  await client?.close();
});

/**
 * Empty tables + a fresh query-counting drizzle handle over the shared
 * database, so each test seeds and counts against nothing but its own rows.
 */
const withDatabase = async <A>(
  use: (db: PgliteDatabase, log: QueryLog) => Promise<A>,
): Promise<A> => {
  await truncateTables(client);
  const log = makeQueryLog();
  return await use(drizzle(client, { logger: log.logger }), log);
};

/**
 * Run a program against a single {@link requestsLayer} build — one build, so
 * one set of resolvers, which is what makes batching possible at all.
 */
const runRequests = <A, E>(db: PgliteDatabase, program: Effect.Effect<A, E, AuthRequests>) =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(requestsLayer(tables).pipe(Layer.provide(databaseLayer(db)))),
    ) as Effect.Effect<A, E>,
  );

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const seedUsers = (db: PgliteDatabase, rows: ReadonlyArray<{ id: string; hash?: string }>) =>
  db
    .insert(tables.users)
    .values(
      rows.map((row) => ({
        id: row.id,
        name: `name-${row.id}`,
        image: null,
        passwordHash: row.hash ?? null,
        attributes: {},
        createdAt: at(0),
        updatedAt: at(0),
      })),
    )
    .execute();

const seedIdentifiers = (
  db: PgliteDatabase,
  rows: ReadonlyArray<{
    id: string;
    userId: string;
    type: Auth.IdentifierType;
    value: string;
    createdAt?: Date;
  }>,
) =>
  db
    .insert(tables.identifiers)
    .values(
      rows.map((row) => ({
        id: row.id,
        userId: row.userId,
        type: row.type,
        value: row.value,
        verified: false,
        verifiedAt: null,
        createdAt: row.createdAt ?? at(0),
      })),
    )
    .execute();

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

describe("Requests / users", () => {
  it("de-duplicates concurrent reads of the same id into one query", async () => {
    await withDatabase(async (db, log) => {
      await seedUsers(db, [{ id: "user-1" }]);
      log.reset();

      const [first, second] = await runRequests(
        db,
        Effect.all([getUser("user-1"), getUser("user-1")], { concurrency: "unbounded" }),
      );

      // Two requests, one batch, one row read — and the identical id appears in
      // the `IN (...)` list exactly once.
      expect(log.selectsOn("effect_auth_users")).toHaveLength(1);
      expect(first?.id).toBe("user-1");
      expect(second).toEqual(first);
    });
  });

  it("coalesces different ids into a single IN (...) query and nulls the misses", async () => {
    await withDatabase(async (db, log) => {
      await seedUsers(db, [{ id: "user-1" }, { id: "user-2" }, { id: "user-3" }]);
      log.reset();

      const found = await runRequests(
        db,
        Effect.forEach(["user-1", "user-2", "user-3", "ghost"], getUser, {
          concurrency: "unbounded",
        }),
      );

      const queries = log.selectsOn("effect_auth_users");
      expect(queries).toHaveLength(1);
      expect(found.map((user) => user?.id ?? null)).toEqual(["user-1", "user-2", "user-3", null]);
      // Results are matched back by id, not by row order.
      expect(found[0]?.name).toBe("name-user-1");
    });
  });
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

describe("Requests / sessions", () => {
  it("batches session lookups and returns null for a miss", async () => {
    await withDatabase(async (db, log) => {
      await db
        .insert(tables.sessions)
        .values(
          ["session-1", "session-2"].map((id) => ({
            id,
            userId: "user-1",
            expiresAt: at(60_000),
            createdAt: at(0),
            lastActivityAt: at(0),
            attributes: { device: id },
          })),
        )
        .execute();
      log.reset();

      const [first, second, missing] = await runRequests(
        db,
        Effect.all([getSession("session-1"), getSession("session-2"), getSession("nope")], {
          concurrency: "unbounded",
        }),
      );

      expect(log.selectsOn("effect_auth_sessions")).toHaveLength(1);
      expect(first?.attributes).toEqual({ device: "session-1" });
      expect(second?.id).toBe("session-2");
      expect(missing).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

describe("Requests / identifiers", () => {
  it("batches (type, value) lookups across types into one query", async () => {
    await withDatabase(async (db, log) => {
      await seedIdentifiers(db, [
        { id: "email-1", userId: "user-1", type: "email", value: "ada@example.com" },
        { id: "name-1", userId: "user-1", type: "username", value: "ada" },
        { id: "email-2", userId: "user-2", type: "email", value: "grace@example.com" },
      ]);
      log.reset();

      const [email, username, other, crossType, missing] = await runRequests(
        db,
        Effect.all(
          [
            getIdentifierByValue("email", "ada@example.com"),
            getIdentifierByValue("username", "ada"),
            getIdentifierByValue("email", "grace@example.com"),
            // Same value as a real row, wrong type: the key is the pair.
            getIdentifierByValue("phone", "ada@example.com"),
            getIdentifierByValue("email", "nobody@example.com"),
          ],
          { concurrency: "unbounded" },
        ),
      );

      // Three types in the batch, still one round trip: the pairs are grouped
      // by type and OR-ed together.
      expect(log.selectsOn("effect_auth_identifiers")).toHaveLength(1);
      expect(email?.id).toBe("email-1");
      expect(username?.id).toBe("name-1");
      expect(other?.userId).toBe("user-2");
      expect(crossType).toBeNull();
      expect(missing).toBeNull();
    });
  });

  it("batches per-user identifier lists, preserving order and empty results", async () => {
    await withDatabase(async (db, log) => {
      await seedIdentifiers(db, [
        {
          id: "third",
          userId: "user-1",
          type: "email",
          value: "c@example.com",
          createdAt: at(3000),
        },
        {
          id: "first",
          userId: "user-1",
          type: "email",
          value: "a@example.com",
          createdAt: at(1000),
        },
        {
          id: "second",
          userId: "user-1",
          type: "email",
          value: "b@example.com",
          createdAt: at(2000),
        },
        { id: "other", userId: "user-2", type: "username", value: "grace" },
      ]);
      log.reset();

      const [mine, theirs, none] = await runRequests(
        db,
        Effect.all(
          [
            listIdentifiersByUser("user-1"),
            listIdentifiersByUser("user-2"),
            listIdentifiersByUser("ghost"),
          ],
          { concurrency: "unbounded" },
        ),
      );

      expect(log.selectsOn("effect_auth_identifiers")).toHaveLength(1);
      // The single ORDER BY carries through to each user's slice.
      expect(mine.map((row) => row.id)).toEqual(["first", "second", "third"]);
      expect(theirs.map((row) => row.id)).toEqual(["other"]);
      // A user with no identifiers gets `[]`, not a missing entry.
      expect(none).toEqual([]);
    });
  });
});
