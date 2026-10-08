/**
 * The stores inside an application's own drizzle **Effect** transaction.
 *
 * `drizzle-orm/effect-postgres`'s `db.transaction(tx => …)` opens `BEGIN` on
 * one connection and records it as a `TransactionConnection` service in the
 * transaction fiber's context; `@effect/sql`'s client picks the connection per
 * statement by reading that service out of the *current* fiber. So a store
 * query joins the transaction only if it runs on a fiber that carries the
 * transaction's services. The applications' Better Auth adapter
 * (preferenceflow `packages/database/src/adapters/effect-postgres-drizzle.ts`)
 * had to capture and re-provide those services by hand, because Better Auth
 * re-entered `runPromise` on fresh root fibers — and without the capture a
 * nested query ran autocommitted on a second connection (or, on a
 * one-connection pool, blocked forever on the one the transaction held).
 *
 * The stores here need no such capture: they are Effects run in the caller's
 * fiber, and the `effectDatabaseLayer` handle is resolved per query, in that
 * same fiber. These tests pin that, for the direct store methods **and** for
 * the batched `Requests` resolvers (whose batches run on the resolver's
 * fiber, the place a detached fiber would sneak in). PGlite has a single
 * connection, so "which connection" cannot be observed through the database
 * itself; instead the handle is supplied as an `Effect` that records, per
 * query, whether the fiber resolving it carries a `TransactionConnection`.
 */

import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import * as EffectPglite from "drizzle-orm-effect/effect-pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { effectDatabaseLayer, type EffectDrizzleDatabase } from "./Database.ts";
import { layer as storesLayer } from "./Layers.ts";
import { tables } from "./PgSchema.ts";
import * as Requests from "./Requests.ts";
import { migratedPglite, truncateTables } from "./testing/PgliteTemplate.ts";

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const makeSession = (id: string): Auth.Session => ({
  id,
  userId: "user-1",
  expiresAt: at(60_000),
  createdAt: at(0),
  lastActivityAt: at(0),
  attributes: {},
});

const TRANSACTION_CONNECTION = "effect/sql/SqlClient/TransactionConnection/";

/** Whether the calling fiber's context carries an open SQL transaction. */
const inTransaction: Effect.Effect<boolean> = Effect.map(Effect.context<never>(), (context) =>
  [...context.mapUnsafe.keys()].some((key) => key.startsWith(TRANSACTION_CONNECTION)),
);

interface Observed {
  readonly direct: string | null;
  readonly batched: ReadonlyArray<string | null>;
  readonly afterRollback: string | null;
  readonly committed: string | null;
  /** One entry per store query: did its fiber carry the transaction? */
  readonly fibers: ReadonlyArray<{ readonly phase: string; readonly inTransaction: boolean }>;
}

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291) and emptied before each test. The stores run on it through
 * `PgliteClient.layer({ liveClient })`, which borrows the instance and leaves
 * closing it to `afterAll`.
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

const run = (): Promise<Observed> => {
  const program = Effect.gen(function* () {
    const db = yield* EffectPglite.make();

    let phase = "outside";
    const fibers: Array<{ readonly phase: string; readonly inTransaction: boolean }> = [];
    // Resolved per query, in the fiber that runs it — see the module docs.
    const observedHandle = Effect.map(inTransaction, (transaction) => {
      fibers.push({ phase, inTransaction: transaction });
      return db as unknown as EffectDrizzleDatabase;
    });

    const stores = Layer.mergeAll(storesLayer(tables), Requests.layer(tables)).pipe(
      Layer.provide(effectDatabaseLayer(observedHandle)),
    );

    return yield* Effect.gen(function* () {
      const sessions = yield* Auth.SessionStore;

      // 1. A transaction that commits, with a direct read and a batch of
      //    concurrent reads issued inside it.
      const inside = yield* db.transaction(() =>
        Effect.gen(function* () {
          phase = "inside";
          yield* sessions.create(makeSession("committed"));
          const direct = yield* sessions.get("committed");
          const batched = yield* Effect.all(
            [Requests.getSession("committed"), Requests.getSession("committed")],
            { concurrency: "unbounded" },
          );
          return { direct: direct?.id ?? null, batched: batched.map((s) => s?.id ?? null) };
        }),
      );

      // 2. A transaction that fails after a store write: the write rolls back.
      yield* db
        .transaction(() =>
          Effect.gen(function* () {
            phase = "inside";
            yield* sessions.create(makeSession("rolled-back"));
            return yield* Effect.fail("boom" as const);
          }),
        )
        .pipe(Effect.ignore);

      phase = "outside";
      const afterRollback = yield* sessions.get("rolled-back");
      const committed = yield* sessions.get("committed");
      return {
        ...inside,
        afterRollback: afterRollback?.id ?? null,
        committed: committed?.id ?? null,
        fibers,
      };
    }).pipe(Effect.provide(stores), Effect.timeout("10 seconds"));
  });

  return Effect.runPromise(
    program.pipe(
      Effect.provide(
        Layer.mergeAll(EffectPglite.DefaultServices, PgliteClient.layer({ liveClient: client })),
      ),
    ) as Effect.Effect<Observed, unknown>,
  );
};

describe("the stores inside a drizzle Effect transaction", () => {
  it("run every query — direct and batched — on the transaction's own fiber", async () => {
    const observed = await run();
    const inside = observed.fibers.filter((fiber) => fiber.phase === "inside");
    const outside = observed.fibers.filter((fiber) => fiber.phase === "outside");
    // create + get + one batch in the committed transaction, create in the failed one.
    expect(inside.length).toBeGreaterThanOrEqual(4);
    expect(inside.every((fiber) => fiber.inTransaction)).toBe(true);
    // …and the probe is not vacuous: queries outside a transaction see none.
    expect(outside.length).toBeGreaterThanOrEqual(2);
    expect(outside.every((fiber) => !fiber.inTransaction)).toBe(true);
  });

  it("see their own uncommitted writes, commit with the transaction, and roll back with it", async () => {
    const observed = await run();
    expect(observed.direct).toBe("committed");
    expect(observed.batched).toEqual(["committed", "committed"]);
    expect(observed.committed).toBe("committed");
    expect(observed.afterRollback).toBeNull();
  });
});
