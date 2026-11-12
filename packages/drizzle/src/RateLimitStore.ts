/**
 * Drizzle-backed implementation of effect-auth's `RateLimitStore`: the store
 * `RateLimiter.layer()` counts through, and with it the `IPRateLimitPlugin` and
 * `RateLimitPlugin` hooks and `ApiKeyService`'s per-key limits.
 *
 * One row per rate-limit key in the `rateLimits` table of any dialect's
 * {@link Tables}: the open window's `count`, the instant it resets, and the
 * instant a block set by `RateLimiter` lifts.
 *
 * ### Contract notes
 *
 * - `get` returns `null` on a miss; `delete` of a missing key is a no-op.
 * - `increment` counts one request without a read-modify-write, so two
 *   concurrent callers never see the same count (the contract's atomic step,
 *   #455). It is two statements, each atomic on its own: an `UPDATE` that
 *   re-opens the key's window when it has expired (count `0`, a new reset time,
 *   no block), then an upsert that adds one to the count, inserting the row
 *   with a count of `1` when there is none. On PostgreSQL and SQLite the upsert
 *   returns the count it wrote (`RETURNING`). MySQL has no `RETURNING`, so the
 *   count is read back after the upsert; a concurrent increment between the two
 *   can only make it read higher, which refuses a request rather than letting
 *   one through.
 * - `ttl` is not stored: an expired window is re-opened by the next
 *   `increment`, and the rows of keys never seen again stay until the
 *   application deletes them (`reset_at` and `blocked_until` both in the past).
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { and, eq, lte, sql } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type DrizzleInsertValues,
  type DrizzleResult,
  type DrizzleUpsertSet,
  DrizzleDatabase,
} from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { RateLimitRow, Tables } from "./Schema.ts";

const toEntry = (row: RateLimitRow): Auth.RateLimitEntry => ({
  key: row.key,
  count: row.count,
  resetAt: row.resetAt.getTime(),
  ...(row.blockedUntil === null ? {} : { blockedUntil: row.blockedUntil.getTime() }),
});

const instant = (millis: number): Date => DateTime.toDateUtc(DateTime.makeUnsafe(millis));

/**
 * Insert `values`, or set `set` on the row whose key is taken, in whichever
 * spelling the handle has: `onConflictDoUpdate` returning the count it wrote
 * (PostgreSQL, SQLite), or `onDuplicateKeyUpdate`, which returns none (MySQL).
 */
const upsert = (
  insert: DrizzleInsertValues,
  target: Tables["rateLimits"],
  set: DrizzleUpsertSet,
): DrizzleResult<unknown> =>
  insert.onConflictDoUpdate === undefined
    ? (insert.onDuplicateKeyUpdate?.({ set }) ?? insert).execute()
    : insert
        .onConflictDoUpdate({ target: target.key, set })
        .returning({ count: target.count })
        .execute();

/**
 * The count an upsert returned: the `RETURNING` row's, or `None` for a driver
 * result that carries none (MySQL's `ResultSetHeader`).
 */
const returnedCount = Schema.decodeUnknownOption(
  Schema.NonEmptyArray(Schema.Struct({ count: Schema.Finite })),
);

/** Build a `RateLimitStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.RateLimitStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const table = tables.rateLimits;

    const get = (key: string, label: string) =>
      query(label, (db) =>
        db.select().from(table).where(eq(table.key, key)).limit(1).execute(),
      ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : toEntry(rows[0]))));

    const reopenExpired = (key: string, now: Date, resetAt: Date) =>
      query("rateLimit.increment.reopen", (db) =>
        db
          .update(table)
          .set({ count: 0, resetAt, blockedUntil: null })
          .where(and(eq(table.key, key), lte(table.resetAt, now)))
          .execute(),
      );

    const countOne = (key: string, resetAt: Date) =>
      query("rateLimit.increment", (db) =>
        upsert(db.insert(table).values({ key, count: 1, resetAt, blockedUntil: null }), table, {
          count: sql`${table.count} + 1`,
        }),
      );

    return {
      get: (key) => get(key, "rateLimit.get"),

      set: (key, entry) => {
        const values = {
          count: entry.count,
          resetAt: instant(entry.resetAt),
          blockedUntil: entry.blockedUntil === undefined ? null : instant(entry.blockedUntil),
        };
        return query("rateLimit.set", (db) =>
          upsert(db.insert(table).values({ key, ...values }), table, values),
        ).pipe(Effect.asVoid);
      },

      increment: (key, ttl) =>
        Effect.gen(function* () {
          const now = yield* DateTime.nowAsDate;
          const resetAt = instant(now.getTime() + ttl * 1000);
          yield* reopenExpired(key, now, resetAt);
          const returned = returnedCount(yield* countOne(key, resetAt));
          if (Option.isSome(returned)) return returned.value[0].count;
          const entry = yield* get(key, "rateLimit.increment.read");
          return entry?.count ?? 1;
        }),

      delete: (key) =>
        query("rateLimit.delete", (db) =>
          db.delete(table).where(eq(table.key, key)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.RateLimitStore.Service;
  });

/** `RateLimitStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.RateLimitStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.RateLimitStore, make(tables));
