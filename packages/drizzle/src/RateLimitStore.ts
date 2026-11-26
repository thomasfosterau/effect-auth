/**
 * Drizzle `RateLimitStore`, one row per key (a dialect's {@link Tables}, or a
 * table mapped with `defineRateLimitTable`). `increment` is two atomic
 * statements, never a read-modify-write; on MySQL the count is read back, which
 * can only refuse more. Rows of keys never seen again stay until {@link
 * purgeExpired}.
 */

import { and, eq, isNull, lte, or, sql } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type DrizzleInsertValues,
  type DrizzleResult,
  type DrizzleSelected,
  type DrizzleUpsertSet,
  DrizzleDatabase,
} from "./Database.ts";
import {
  type RateLimitColumns,
  type RateLimitSchema,
  type RateLimitTableInput,
  resolveRateLimitTable,
  writeValues,
} from "./Columns.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";

/** What a counter read projects, under the store's own field names. */
type RateLimitRow = DrizzleSelected<RateLimitColumns>;

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
  target: RateLimitSchema,
  set: DrizzleUpsertSet,
): DrizzleResult<unknown> =>
  insert.onConflictDoUpdate === undefined
    ? (insert.onDuplicateKeyUpdate?.({ set }) ?? insert).execute()
    : insert
        .onConflictDoUpdate({ target: target.columns.key, set })
        .returning({ count: target.columns.count })
        .execute();

/**
 * What an upsert sets, re-keyed into the mapped table's column keys.
 *
 * `writeValues` has already checked each value against its column.
 */
const upsertSet = (
  schema: RateLimitSchema,
  values: Parameters<typeof writeValues<RateLimitColumns>>[1],
): DrizzleUpsertSet =>
  // SAFETY: every value is a column value of `RateLimitColumns` (string, number,
  // `Date`, `null`) or a `SQL` expression, all of which `DrizzleUpsertValue` admits.
  writeValues(schema, values) as DrizzleUpsertSet;

/**
 * The count an upsert returned: the `RETURNING` row's, or `None` for a driver
 * result that carries none (MySQL's `ResultSetHeader`).
 */
const returnedCount = Schema.decodeUnknownOption(
  Schema.NonEmptyArray(Schema.Struct({ count: Schema.Finite })),
);

/** Build a `RateLimitStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  tables: RateLimitTableInput = defaultTables,
): Effect.Effect<typeof Auth.RateLimitStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const schema = resolveRateLimitTable(tables);
    const table = schema.table;
    const column = schema.columns;

    const get = (key: string, label: string) =>
      query(label, (db) =>
        db.select(column).from(table).where(eq(column.key, key)).limit(1).execute(),
      ).pipe(Effect.map((rows) => Option.map(Arr.head(rows), toEntry)));

    const reopenExpired = (key: string, now: Date, resetAt: Date) =>
      query("rateLimit.increment.reopen", (db) =>
        db
          .update(table)
          .set(writeValues(schema, { count: 0, resetAt, blockedUntil: null }))
          .where(and(eq(column.key, key), lte(column.resetAt, now)))
          .execute(),
      );

    const countOne = (key: string, resetAt: Date) =>
      query("rateLimit.increment", (db) =>
        upsert(
          db
            .insert(table)
            .values(writeValues(schema, { key, count: 1, resetAt, blockedUntil: null })),
          schema,
          upsertSet(schema, { count: sql`${column.count} + 1` }),
        ),
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
          upsert(
            db.insert(table).values(writeValues(schema, { key, ...values })),
            schema,
            upsertSet(schema, values),
          ),
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
          return Option.match(entry, { onNone: () => 1, onSome: (found) => found.count });
        }),

      delete: (key) =>
        query("rateLimit.delete", (db) =>
          db.delete(table).where(eq(column.key, key)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.RateLimitStore.Service;
  });

/** `RateLimitStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  tables: RateLimitTableInput = defaultTables,
): Layer.Layer<Auth.RateLimitStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.RateLimitStore, make(tables));

/**
 * Delete the rate-limit rows whose window and block have both passed, in one
 * `DELETE` over the ambient {@link DrizzleDatabase}.
 *
 * The table holds one row per key, IP and identifier ever counted, and no
 * store call deletes the row of a key that is never seen again, so without a
 * purge it grows by one row per distinct caller. A row goes once its
 * `reset_at` is not after now and its `blocked_until` is unset or not after
 * now: the limiter then treats the key as one it has never seen, so the next
 * request opens a fresh window either way. A row still inside its window or
 * still blocked stays. Schedule it from the host (a cron trigger, a timer on a
 * long-lived server); now is read from the `Clock`.
 *
 * With `options.limit` the `DELETE` takes at most that many of those
 * rows, chosen by key through a derived table, which PostgreSQL, SQLite and
 * MySQL all accept (MySQL refuses a `LIMIT` directly inside `IN`):
 * `DELETE … WHERE <spent> AND key IN (SELECT key FROM (SELECT key … WHERE
 * <spent> LIMIT n) AS spent)`; the outer `<spent>` keeps a row a concurrent
 * `increment` refreshed after the subquery picked it (PostgreSQL READ COMMITTED
 * rechecks only the outer `WHERE`). It returns nothing on any dialect (MySQL has no `RETURNING`, and
 * the drivers report affected rows each their own way), so a Workers cron that
 * must stay inside its budget runs a fixed number of bounded calls per tick;
 * whatever is left goes on the next tick. Which spent rows a capped call takes
 * is unspecified. A `limit` that is not a positive integer fails with
 * `AuthError` before any statement runs.
 */
export const purgeExpired = (
  tables: RateLimitTableInput = defaultTables,
  options?: PurgeExpiredOptions,
): Effect.Effect<void, Auth.AuthError, DrizzleDatabase> =>
  Effect.gen(function* () {
    const limit = options?.limit;
    yield* checkLimit(limit);
    const query = makeQuery(yield* DrizzleDatabase);
    const schema = resolveRateLimitTable(tables);
    const table = schema.table;
    const column = schema.columns;
    const now = yield* DateTime.nowAsDate;
    const spent = and(
      lte(column.resetAt, now),
      or(isNull(column.blockedUntil), lte(column.blockedUntil, now)),
    );
    const key = sql.identifier(column.key.name);
    yield* query("rateLimit.purgeExpired", (db) =>
      db
        .delete(table)
        .where(
          limit === undefined
            ? spent
            : sql`${spent} and ${column.key} in (select ${key} from (select ${column.key} from ${table} where ${spent} limit ${sql.raw(String(limit))}) as ${sql.identifier("spent")})`,
        )
        .execute(),
    );
  });

/** Refuse a purge `limit` that is not a positive integer; omitted is fine. */
const checkLimit = (limit: number | undefined): Effect.Effect<void, Auth.AuthError> =>
  limit === undefined || (Number.isSafeInteger(limit) && limit > 0)
    ? Effect.void
    : Effect.fail(
        new Auth.AuthError({
          message: `purgeExpired limit must be a positive integer, got ${String(limit)}`,
        }),
      );

/** Options for {@link purgeExpired}. */
export interface PurgeExpiredOptions {
  /**
   * The most rows one call deletes, a positive integer; omitted, every
   * spent row goes in one `DELETE`.
   */
  readonly limit?: number | undefined;
}
