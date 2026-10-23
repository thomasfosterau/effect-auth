/**
 * The drizzle `UserStore` exercised against a real PostgreSQL engine (PGlite —
 * Postgres compiled to WASM, in-process, no server), so `jsonb` and
 * `timestamptz` behave exactly as they do in production.
 */

import type { PGlite } from "@electric-sql/pglite";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import { DateTime, Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { conformance } from "./testing/Conformance.ts";
import { databaseLayer } from "./Database.ts";
import { type Tables, tables } from "./PgSchema.ts";
import { layer as userStoreLayer } from "./UserStore.ts";
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

/** Run `build`'s program against the user store on the file's database. */
const runWithDatabase = <A, E>(
  build: (db: PgliteDatabase) => Effect.Effect<A, E, Auth.UserStore>,
): Promise<A> => {
  const db = drizzle(client);
  return Effect.runPromise(
    build(db).pipe(Effect.provide(userStoreLayer(tables).pipe(Layer.provide(databaseLayer(db))))),
  );
};

const at = (offsetMs: number): Date =>
  DateTime.toDateUtc(
    DateTime.add(DateTime.makeUnsafe("2026-01-01T00:00:00.000Z"), { milliseconds: offsetMs }),
  );

/** Insert a user row directly — `UserStore` is read-only by contract. */
const seedUser = (
  db: PgliteDatabase,
  row: Partial<Tables["users"]["$inferInsert"]> = {},
): Effect.Effect<string> =>
  Effect.orDie(
    Effect.tryPromise(async () => {
      const id = row.id ?? "user-1";
      await db
        .insert(tables.users)
        .values({
          id,
          name: null,
          image: null,
          passwordHash: null,
          attributes: {},
          createdAt: at(0),
          updatedAt: at(0),
          ...row,
        })
        .execute();
      return id;
    }),
  );

describe("UserStore", () => {
  it("maps rows to users, omitting absent optional fields", async () => {
    const result = await runWithDatabase((db) =>
      Effect.gen(function* () {
        yield* seedUser(db, {
          id: "full",
          name: "Ada",
          image: "https://example.com/a.png",
          attributes: { plan: "pro", flags: { beta: true } },
          createdAt: at(0),
          updatedAt: at(5000),
        });
        yield* seedUser(db, { id: "bare" });

        const store = yield* Auth.UserStore;
        return {
          full: yield* store.get("full"),
          bare: yield* store.get("bare"),
          missing: yield* store.get("ghost"),
        };
      }),
    );

    expect(result.full).toEqual({
      id: "full",
      name: "Ada",
      image: "https://example.com/a.png",
      createdAt: at(0),
      updatedAt: at(5000),
      attributes: { plan: "pro", flags: { beta: true } },
    });
    expect(result.bare).toEqual({
      id: "bare",
      createdAt: at(0),
      updatedAt: at(0),
      attributes: {},
    });
    expect(result.bare && "name" in result.bare).toBe(false);
    expect(result.bare && "image" in result.bare).toBe(false);
    expect(result.missing).toBeNull();
  });
});

// The core's published UserStore suite: it writes its users straight into the
// table, as the application's own user writer would.
conformance(
  "PostgreSQL",
  Testing.userStoreConformance({
    seedUser: (user) =>
      Effect.tryPromise(() =>
        drizzle(client)
          .insert(tables.users)
          .values({
            id: user.id,
            name: user.name ?? null,
            image: user.image ?? null,
            passwordHash: null,
            attributes: user.attributes,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
          })
          .execute(),
      ).pipe(Effect.orDie),
  }),
  (effect) => runWithDatabase(() => effect),
);
