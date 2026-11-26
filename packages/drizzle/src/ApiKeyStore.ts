/**
 * Drizzle `ApiKeyStore` (a dialect's {@link Tables}, or a table mapped with
 * `defineApiKeyTable`). It stores only the key's digest; `NULL` fields read
 * back absent and instants as epoch milliseconds. `recordUse` is one guarded
 * `UPDATE`, which on MySQL needs mysql2's matched-rows count.
 */

import { and, eq, gte, isNull, or, sql } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type ApiKeyColumns,
  type ApiKeyTableInput,
  resolveApiKeyTable,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { affectedRows, makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";

/** What a key read projects, under the store's own field names. */
type ApiKeyRow = DrizzleSelected<ApiKeyColumns>;

const instant = (millis: number): Date => DateTime.toDateUtc(DateTime.makeUnsafe(millis));

const toDate = (millis: number | undefined): Date | null =>
  millis === undefined ? null : instant(millis);

const toMillis = (date: Date | null): number | null => (date === null ? null : date.getTime());

/** The optional fields of a row, `NULL`s dropped. */
const optionalFields = (row: ApiKeyRow): Partial<Auth.ApiKey> =>
  R.filter(
    {
      name: row.name,
      prefix: row.prefix,
      expiresAt: toMillis(row.expiresAt),
      lastUsedAt: toMillis(row.lastUsedAt),
      permissions: row.permissions,
      remaining: row.remaining,
      refillAmount: row.refillAmount,
      refillInterval: row.refillInterval,
      refillMax: row.refillMax,
      lastRefillAt: toMillis(row.lastRefillAt),
    },
    (value) => value !== null,
  );

const rateLimitOf = (row: ApiKeyRow): Pick<Auth.ApiKey, "rateLimit"> =>
  row.rateLimitMaxRequests === null || row.rateLimitWindowMs === null
    ? {}
    : { rateLimit: { maxRequests: row.rateLimitMaxRequests, windowMs: row.rateLimitWindowMs } };

const toApiKey = (row: ApiKeyRow): Auth.ApiKey => ({
  id: row.id,
  start: row.start,
  keyHash: row.keyHash,
  userId: row.userId,
  enabled: row.enabled,
  metadata: row.metadata ?? {},
  createdAt: row.createdAt.getTime(),
  updatedAt: row.updatedAt.getTime(),
  ...optionalFields(row),
  ...rateLimitOf(row),
});

/** Every column but the primary key, from a key. */
const mutableValues = (apiKey: Auth.ApiKey) => ({
  userId: apiKey.userId,
  name: apiKey.name ?? null,
  prefix: apiKey.prefix ?? null,
  start: apiKey.start,
  keyHash: apiKey.keyHash,
  enabled: apiKey.enabled,
  expiresAt: toDate(apiKey.expiresAt),
  lastUsedAt: toDate(apiKey.lastUsedAt),
  permissions: apiKey.permissions ?? null,
  metadata: apiKey.metadata,
  remaining: apiKey.remaining ?? null,
  refillAmount: apiKey.refillAmount ?? null,
  refillInterval: apiKey.refillInterval ?? null,
  refillMax: apiKey.refillMax ?? null,
  lastRefillAt: toDate(apiKey.lastRefillAt),
  rateLimitMaxRequests: apiKey.rateLimit?.maxRequests ?? null,
  rateLimitWindowMs: apiKey.rateLimit?.windowMs ?? null,
  updatedAt: instant(apiKey.updatedAt),
});

/** Build an `ApiKeyStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  tables: ApiKeyTableInput = defaultTables,
): Effect.Effect<typeof Auth.ApiKeyStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const schema = resolveApiKeyTable(tables);
    const table = schema.table;
    const column = schema.columns;

    const one = (label: string, where: ReturnType<typeof eq>) =>
      query(label, (db) => db.select(column).from(table).where(where).limit(1).execute()).pipe(
        Effect.map((rows) => (rows[0] === undefined ? null : toApiKey(rows[0]))),
      );

    return {
      create: (apiKey) =>
        query("apiKey.create", (db) =>
          db
            .insert(table)
            .values(
              writeValues(schema, {
                id: apiKey.id,
                createdAt: instant(apiKey.createdAt),
                ...mutableValues(apiKey),
              }),
            )
            .execute(),
        ).pipe(Effect.as(apiKey)),

      get: (id) => one("apiKey.get", eq(column.id, id)),

      getByHash: (keyHash) => one("apiKey.getByHash", eq(column.keyHash, keyHash)),

      update: (apiKey) =>
        query("apiKey.update", (db) =>
          db
            .update(table)
            .set(writeValues(schema, mutableValues(apiKey)))
            .where(eq(column.id, apiKey.id))
            .execute(),
        ).pipe(Effect.as(apiKey)),

      recordUse: (id, use) =>
        Effect.gen(function* () {
          const refill = use.refill;
          const topped =
            refill === undefined
              ? sql`${column.remaining}`
              : refill.max === undefined
                ? sql`${column.remaining} + ${refill.amount}`
                : sql`case when ${column.remaining} + ${refill.amount} > ${refill.max} then ${refill.max} else ${column.remaining} + ${refill.amount} end`;
          const matched = yield* affectedRows(
            "apiKey.recordUse",
            query("apiKey.recordUse", (db) =>
              db
                .update(table)
                .set(
                  writeValues(schema, {
                    remaining: sql`${topped} - 1`,
                    ...(refill !== undefined && { lastRefillAt: instant(refill.to) }),
                    lastUsedAt: instant(use.usedAt),
                    updatedAt: instant(use.usedAt),
                  }),
                )
                .where(
                  and(
                    eq(column.id, id),
                    eq(column.enabled, true),
                    or(isNull(column.expiresAt), gte(column.expiresAt, instant(use.usedAt))),
                    or(isNull(column.remaining), sql`${topped} > 0`),
                    refill === undefined
                      ? undefined
                      : eq(column.lastRefillAt, instant(refill.from)),
                  ),
                )
                .execute(),
            ),
          );
          return matched > 0 ? yield* one("apiKey.recordUse.read", eq(column.id, id)) : null;
        }),

      delete: (id) =>
        query("apiKey.delete", (db) => db.delete(table).where(eq(column.id, id)).execute()).pipe(
          Effect.asVoid,
        ),

      listByUserId: (userId) =>
        query("apiKey.listByUserId", (db) =>
          db.select(column).from(table).where(eq(column.userId, userId)).execute(),
        ).pipe(Effect.map((rows) => rows.map(toApiKey))),

      deleteByUserId: (userId) =>
        query("apiKey.deleteByUserId", (db) =>
          db.delete(table).where(eq(column.userId, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.ApiKeyStore.Service;
  });

/** `ApiKeyStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  tables: ApiKeyTableInput = defaultTables,
): Layer.Layer<Auth.ApiKeyStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.ApiKeyStore, make(tables));
