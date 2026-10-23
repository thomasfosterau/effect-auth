/**
 * The drizzle `SessionStore` exercised against a real PostgreSQL engine.
 *
 * `@electric-sql/pglite` is Postgres compiled to WASM: it runs in-process with
 * no server, so `jsonb`, `timestamptz`, `RETURNING` and unique-index
 * violations behave exactly as they do in production — the very things a mock
 * would paper over.
 */

import type { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, assert, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { conformance } from "./testing/Conformance.ts";
import { databaseLayer } from "./Database.ts";
import { tables } from "./PgSchema.ts";
import { layer as sessionStoreLayer } from "./SessionStore.ts";
import { migratedPglite, truncateTables } from "./testing/PgliteTemplate.ts";

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291) and emptied before each test.
 */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncateTables(client);
});

/** Run `build`'s program against the session store on the file's database. */
const runWithDatabase = <A, E>(build: () => Effect.Effect<A, E, Auth.SessionStore>): Promise<A> =>
  Effect.runPromise(
    build().pipe(
      Effect.provide(sessionStoreLayer(tables).pipe(Layer.provide(databaseLayer(drizzle(client))))),
    ),
  );

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const makeSession = (overrides: Partial<Auth.Session> = {}): Auth.Session => ({
  id: "session-1",
  userId: "user-1",
  expiresAt: at(60_000),
  createdAt: at(0),
  lastActivityAt: at(0),
  attributes: {},
  ...overrides,
});

describe("SessionStore", () => {
  it("round-trips a session through create/get/update/delete", async () => {
    const result = await runWithDatabase(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const session = makeSession({ attributes: { device: "laptop" } });

        const created = yield* store.create(session);
        const loaded = yield* store.get(session.id);
        const updated = yield* store.update({
          ...session,
          expiresAt: at(120_000),
          lastActivityAt: at(30_000),
          attributes: { device: "phone" },
        });
        const reloaded = yield* store.get(session.id);
        yield* store.delete(session.id);
        const afterDelete = yield* store.get(session.id);

        return { created, loaded, updated, reloaded, afterDelete };
      }),
    );

    expect(result.created).toEqual(makeSession({ attributes: { device: "laptop" } }));
    expect(result.loaded?.id).toBe("session-1");
    expect(result.loaded?.userId).toBe("user-1");
    expect(result.loaded?.createdAt).toEqual(at(0));
    expect(result.loaded?.expiresAt).toEqual(at(60_000));
    expect(result.loaded?.attributes).toEqual({ device: "laptop" });
    expect(result.updated.attributes).toEqual({ device: "phone" });
    expect(result.reloaded?.expiresAt).toEqual(at(120_000));
    expect(result.reloaded?.lastActivityAt).toEqual(at(30_000));
    expect(result.reloaded?.attributes).toEqual({ device: "phone" });
    expect(result.afterDelete).toBeNull();
  });

  it("returns null on a miss and no-ops on deletes of absent rows", async () => {
    const result = await runWithDatabase(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const missing = yield* store.get("nope");
        yield* store.delete("nope");
        yield* store.deleteByUserId("nobody");
        const listed = yield* store.listByUserId("nobody");
        return { missing, listed };
      }),
    );

    expect(result.missing).toBeNull();
    expect(result.listed).toEqual([]);
  });

  it("stores expiry as timestamptz without interpreting it", async () => {
    // Expiry is the service layer's decision; the store persists and returns
    // whatever instant it was given, including one already in the past.
    const result = await runWithDatabase(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const expired = makeSession({ id: "expired", expiresAt: at(-60_000) });
        const future = makeSession({ id: "future", expiresAt: at(86_400_000) });
        yield* store.create(expired);
        yield* store.create(future);
        return {
          expired: yield* store.get("expired"),
          future: yield* store.get("future"),
        };
      }),
    );

    expect(result.expired?.expiresAt).toEqual(at(-60_000));
    assert(result.future !== null, "the future session is stored");
    expect(result.expired?.expiresAt.getTime()).toBeLessThan(result.future.expiresAt.getTime());

    expect(result.future?.expiresAt).toEqual(at(86_400_000));
  });

  it("round-trips nested attribute bags through jsonb", async () => {
    const attributes = {
      device: "laptop",
      count: 42,
      ratio: 0.5,
      active: true,
      missing: null,
      roles: ["admin", "editor"],
      nested: { ip: "10.0.0.1", tags: [1, 2, 3] },
    };

    const result = await runWithDatabase(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(makeSession({ attributes }));
        const empty = makeSession({ id: "session-2", attributes: {} });
        yield* store.create(empty);
        return {
          rich: yield* store.get("session-1"),
          empty: yield* store.get("session-2"),
        };
      }),
    );

    expect(result.rich?.attributes).toEqual(attributes);
    expect(result.empty?.attributes).toEqual({});
  });

  it("lists a user's sessions by createdAt and scopes deleteByUserId", async () => {
    const result = await runWithDatabase(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(makeSession({ id: "b", createdAt: at(2000) }));
        yield* store.create(makeSession({ id: "a", createdAt: at(1000) }));
        yield* store.create(makeSession({ id: "c", createdAt: at(3000) }));
        yield* store.create(makeSession({ id: "other", userId: "user-2" }));

        const listed = yield* store.listByUserId("user-1");
        yield* store.deleteByUserId("user-1");
        return {
          listed,
          afterDelete: yield* store.listByUserId("user-1"),
          untouched: yield* store.listByUserId("user-2"),
        };
      }),
    );

    expect(result.listed.map((session) => session.id)).toEqual(["a", "b", "c"]);
    expect(result.afterDelete).toEqual([]);
    expect(result.untouched.map((session) => session.id)).toEqual(["other"]);
  });
});

// The core's published SessionStore suite: every case mints its own ids, and
// the sessions table has no foreign key to users, so nothing is seeded.
conformance("PostgreSQL", Testing.sessionStoreConformance(), (effect) =>
  runWithDatabase(() => effect),
);
