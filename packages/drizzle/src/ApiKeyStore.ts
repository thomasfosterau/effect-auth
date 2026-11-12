/**
 * Drizzle-backed implementation of effect-auth's `ApiKeyStore`, over the
 * `apiKeys` table of any dialect's {@link Tables}.
 *
 * ### Contract notes
 *
 * - `keyHash` is the SHA-256 hex digest `ApiKeyService` computes; the
 *   plaintext key is returned to the caller once and never reaches the store.
 *   The column is unique, so `getByHash` reads at most one row.
 * - `get` and `getByHash` return `null` on a miss; `delete` of a missing key is
 *   a no-op. `deleteByUserId` deletes every key of one user in one `DELETE`
 *   (core's account deletion calls it before the user row goes, #601).
 * - Optional fields round-trip as absent: `NULL` reads back as a missing
 *   property, never as `null`. Instants are stored as timestamps and read
 *   back as the epoch milliseconds the contract uses.
 * - `update` writes every field but `id` and `createdAt`. The contract has no
 *   atomic "use" operation: `ApiKeyService.verify` reads the key and writes the
 *   decremented `remaining` back, so two concurrent verifies of one
 *   quota-limited key can both pass. That is the core contract's, not this
 *   store's, to close.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { eq } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { ApiKeyRow, Tables } from "./Schema.ts";

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
  metadata: row.metadata,
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
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.ApiKeyStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const table = tables.apiKeys;

    const one = (label: string, where: ReturnType<typeof eq>) =>
      query(label, (db) => db.select().from(table).where(where).limit(1).execute()).pipe(
        Effect.map((rows) => (rows[0] === undefined ? null : toApiKey(rows[0]))),
      );

    return {
      create: (apiKey) =>
        query("apiKey.create", (db) =>
          db
            .insert(table)
            .values({
              id: apiKey.id,
              createdAt: instant(apiKey.createdAt),
              ...mutableValues(apiKey),
            })
            .execute(),
        ).pipe(Effect.as(apiKey)),

      get: (id) => one("apiKey.get", eq(table.id, id)),

      getByHash: (keyHash) => one("apiKey.getByHash", eq(table.keyHash, keyHash)),

      update: (apiKey) =>
        query("apiKey.update", (db) =>
          db.update(table).set(mutableValues(apiKey)).where(eq(table.id, apiKey.id)).execute(),
        ).pipe(Effect.as(apiKey)),

      delete: (id) =>
        query("apiKey.delete", (db) => db.delete(table).where(eq(table.id, id)).execute()).pipe(
          Effect.asVoid,
        ),

      listByUserId: (userId) =>
        query("apiKey.listByUserId", (db) =>
          db.select().from(table).where(eq(table.userId, userId)).execute(),
        ).pipe(Effect.map((rows) => rows.map(toApiKey))),

      deleteByUserId: (userId) =>
        query("apiKey.deleteByUserId", (db) =>
          db.delete(table).where(eq(table.userId, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.ApiKeyStore.Service;
  });

/** `ApiKeyStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.ApiKeyStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.ApiKeyStore, make(tables));
