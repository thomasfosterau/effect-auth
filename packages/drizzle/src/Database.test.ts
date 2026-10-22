/**
 * The database seam: which drizzle handles fit through it, and when the handle
 * is chosen.
 *
 * Two properties are under test that the store tests cannot see:
 *
 * 1. A drizzle **Effect driver** — `drizzle-orm/effect-postgres` and its
 *    siblings, whose built queries *are* `Effect`s — binds through
 *    `effectDatabaseLayer` and reaches the database with no Promise boundary.
 * 2. A handle supplied as an **`Effect`** is resolved once per query, in the
 *    calling fiber, so two overlapping "requests" each talk to their own
 *    connection.
 *
 * `drizzle-orm-effect` is drizzle `1.0.0-rc` installed under an alias: the
 * Effect drivers only exist from `1.0`, while this package's peer range starts
 * at `0.44`, so the two are exercised side by side. The tables are this
 * package's ordinary `Pg.tables` — drizzle brands its schema objects with
 * `Symbol.for`, so one table definition serves both handles.
 */

import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import type { EffectPgDatabase } from "drizzle-orm-effect/effect-postgres";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";
import * as EffectPglite from "drizzle-orm-effect/effect-pglite";
import { Context, Effect, Latch, Layer, Predicate } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer, effectDatabaseLayer, type EffectDrizzleDatabase } from "./Database.ts";
import { layer as storesLayer } from "./Layers.ts";
import { tables } from "./PgSchema.ts";
import { migratedPglite, truncateTables } from "./testing/PgliteTemplate.ts";

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const makeSession = (id: string, userId: string): Auth.Session => ({
  id,
  userId,
  expiresAt: at(60_000),
  createdAt: at(0),
  lastActivityAt: at(0),
  attributes: {},
});

// ---------------------------------------------------------------------------
// Type-level: what each door accepts
// ---------------------------------------------------------------------------

/**
 * Never called — every line here is a compile-time assertion, checked by the
 * package's `tsc --noEmit -p tsconfig.test.json` run.
 */
const doorAccepts = (
  effectPg: EffectPgDatabase,
  promisePg: PgliteDatabase,
): ReadonlyArray<unknown> => [
  // #181: a real `drizzle-orm/effect-postgres` handle fits the Effect door.
  effectDatabaseLayer(effectPg),
  effectDatabaseLayer(Effect.succeed<EffectDrizzleDatabase>(effectPg)),
  // The Promise-shaped door still takes a handle, and now also an Effect of one.
  databaseLayer(promisePg),
  databaseLayer(Effect.succeed(promisePg)),
];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * The file's shared in-memory Postgres instance, emptied before each test: the
 * Effect-driver test borrows it, and the overlapping-requests suite uses it as
 * the empty default its reference falls back to. It is a separate PGlite
 * instance with its own Postgres backend, started from the run's migrated
 * template (#291) rather than from `initdb`.
 *
 * Each instance is opened in a hook of its own, never three in one hook: a
 * PGlite boot is the costly part on a loaded machine, and three boots in one
 * hook ran past Vitest's 10 s default hook timeout (#324).
 */
let primary: PGlite;

beforeAll(async () => {
  primary = await migratedPglite();
});

afterAll(async () => {
  await primary?.close();
});

beforeEach(async () => {
  await truncateTables(primary);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("databaseLayer doors", () => {
  it("accepts each documented handle shape", () => {
    expect(Predicate.isFunction(doorAccepts)).toBe(true);
  });

  it("binds a drizzle Effect driver, with no Promise boundary", async () => {
    /**
     * Every query the stores issue on this handle is a drizzle `Effect`; if the
     * seam still insisted on a `Promise`, `run` would reject the value rather
     * than run it, and none of the assertions below would be reachable.
     */
    const program = Effect.gen(function* () {
      const db = yield* EffectPglite.make();

      const work: Effect.Effect<
        {
          readonly created: Auth.Session;
          readonly read: Auth.Session | null;
          readonly afterDelete: Auth.Session | null;
        },
        Auth.AuthError,
        StoreServices
      > = Effect.gen(function* () {
        const sessions = yield* Auth.SessionStore;
        const created = yield* sessions.create(makeSession("effect-driver", "user-1"));
        const read = yield* sessions.get("effect-driver");
        yield* sessions.delete("effect-driver");
        return { created, read, afterDelete: yield* sessions.get("effect-driver") };
      });

      return yield* work.pipe(
        Effect.provide(storesLayer(tables).pipe(Layer.provide(effectDatabaseLayer(db)))),
      );
    });

    const result = await Effect.runPromise(
      program.pipe(
        Effect.provide(
          Layer.mergeAll(
            EffectPglite.DefaultServices,
            // The file's migrated instance, which the client borrows and leaves
            // open.
            PgliteClient.layer({ liveClient: primary }),
          ),
        ),
      ) as Effect.Effect<
        {
          readonly created: Auth.Session;
          readonly read: Auth.Session | null;
          readonly afterDelete: Auth.Session | null;
        },
        unknown
      >,
    );

    expect(result.created.id).toBe("effect-driver");
    expect(result.read).toEqual(makeSession("effect-driver", "user-1"));
    expect(result.afterDelete).toBeNull();
  });
});

describe("overlapping requests", () => {
  /**
   * One instance per "request", each opened in a hook of its own, so that a
   * hook boots one database and the two requests stay independent (#324).
   */
  let first: PGlite;
  let second: PGlite;

  beforeAll(async () => {
    first = await migratedPglite();
  });

  beforeAll(async () => {
    second = await migratedPglite();
  });

  afterAll(async () => {
    await Promise.all([first?.close(), second?.close()]);
  });

  beforeEach(async () => {
    await Promise.all([first, second].map(truncateTables));
  });

  it("resolves an Effect-supplied handle per query, so overlapping requests stay on their own connection", async () => {
    // Three databases: one per "request", plus the default the reference falls
    // back to. The default holds no rows at all, so a handle that leaked out of
    // its request would read `null` and fail the assertions loudly.
    const fallbackDb = drizzle(primary);
    const firstDb = drizzle(first);
    const secondDb = drizzle(second);

    const RequestDatabase: Context.Reference<PgliteDatabase> = Context.Reference<PgliteDatabase>(
      "test/RequestDatabase",
      {
        defaultValue: () => fallbackDb,
      },
    );

    // One store layer, built once, shared by both requests: the handle is not
    // in it.
    const stores = storesLayer(tables).pipe(Layer.provide(databaseLayer(RequestDatabase)));

    const seed = async (db: PgliteDatabase, userId: string): Promise<void> => {
      await db.insert(tables.sessions).values(makeSession("shared", userId)).execute();
    };
    await seed(firstDb, "first-request");
    await seed(secondDb, "second-request");

    const program = Effect.gen(function* () {
      // Each request reads, waits for the other to have read too, then reads
      // again — so the two are provably in flight at the same time.
      const firstHasRead = yield* Latch.make(false);
      const secondHasRead = yield* Latch.make(false);

      const request = (
        db: PgliteDatabase,
        arrived: Latch.Latch,
        other: Latch.Latch,
      ): Effect.Effect<ReadonlyArray<Auth.Session | null>, Auth.AuthError, StoreServices> =>
        Effect.gen(function* () {
          const sessions = yield* Auth.SessionStore;
          const before = yield* sessions.get("shared");
          yield* Latch.open(arrived);
          yield* other.await;
          const after = yield* sessions.get("shared");
          return [before, after];
        }).pipe(Effect.provide(Context.make(RequestDatabase, db)));

      return yield* Effect.all(
        [
          request(firstDb, firstHasRead, secondHasRead),
          request(secondDb, secondHasRead, firstHasRead),
        ],
        { concurrency: "unbounded" },
      );
    });

    const [firstReads, secondReads] = await Effect.runPromise(
      program.pipe(Effect.provide(stores)) as Effect.Effect<
        readonly [ReadonlyArray<Auth.Session | null>, ReadonlyArray<Auth.Session | null>],
        unknown
      >,
    );

    expect(firstReads.map((session) => session?.userId)).toEqual([
      "first-request",
      "first-request",
    ]);
    expect(secondReads.map((session) => session?.userId)).toEqual([
      "second-request",
      "second-request",
    ]);
  });
});
