/**
 * Drizzle-backed implementation of effect-auth's `IdentifierStore`, plus the
 * `Request`/`RequestResolver` pairs that batch identifier reads.
 *
 * {@link make} is an `Effect` that reads {@link DrizzleDatabase} out of context
 * and returns a plain store object; {@link layer} lifts it into a `Layer` keyed
 * by `Auth.IdentifierStore`. Both take an optional {@link Tables} set — any
 * dialect's, under any names — so switching database or table names is a
 * one-argument change.
 *
 * ### Contract notes
 *
 * - `getByValue` and `setVerified` return `null` on a miss; they never fail
 *   with a "not found" error.
 * - Deletes are silent no-ops when the row does not exist.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`, including the unique-index violation raised when two
 *   users race for the same `(type, value)` identifier. `Auth.claimIdentifier`
 *   in core re-reads the pair on failure and turns that race into an
 *   `IdentifierTakenError`.
 */

import { and, asc, eq, inArray, or } from "drizzle-orm";
import { Effect, Exit, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { Tables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Build an `IdentifierStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.IdentifierStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const identifiers = tables.identifiers;

    return {
      getByValue: (type, value) =>
        query("identifier.getByValue", (db) =>
          db
            .select()
            .from(identifiers)
            .where(and(eq(identifiers.type, type), eq(identifiers.value, value)))
            .limit(1)
            .execute(),
        ).pipe(
          Effect.map((rows) => {
            const row = rows[0];
            return row === undefined
              ? null
              : {
                  id: row.id,
                  userId: row.userId,
                  type: row.type,
                  value: row.value,
                  verified: row.verified,
                  ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
                  createdAt: row.createdAt,
                };
          }),
        ),

      listByUser: (userId) =>
        query("identifier.listByUser", (db) =>
          db
            .select()
            .from(identifiers)
            .where(eq(identifiers.userId, userId))
            .orderBy(asc(identifiers.createdAt))
            .execute(),
        ).pipe(
          Effect.map((rows) =>
            rows.map((row) => ({
              id: row.id,
              userId: row.userId,
              type: row.type,
              value: row.value,
              verified: row.verified,
              ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
              createdAt: row.createdAt,
            })),
          ),
        ),

      // The `(type, value)` unique index is the claim mechanism: a losing
      // racer's INSERT is rejected by the database and surfaces here as an
      // `AuthError`, which `Auth.claimIdentifier` re-reads into an
      // `IdentifierTakenError`.
      create: (identifier) =>
        query("identifier.create", (db) =>
          db
            .insert(identifiers)
            .values({
              id: identifier.id,
              userId: identifier.userId,
              type: identifier.type,
              value: identifier.value,
              verified: identifier.verified,
              verifiedAt: identifier.verifiedAt ?? null,
              createdAt: identifier.createdAt,
            })
            .execute(),
        ).pipe(Effect.as(identifier)),

      // `UPDATE ... RETURNING` would be one statement, but MySQL has no
      // `RETURNING` clause, so the updated row is read back instead — the same
      // two statements on all three dialects rather than a per-dialect branch.
      setVerified: (id, verifiedAt) =>
        Effect.gen(function* () {
          yield* query("identifier.setVerified", (db) =>
            db
              .update(identifiers)
              .set({ verified: true, verifiedAt })
              .where(eq(identifiers.id, id))
              .execute(),
          );

          const rows = yield* query("identifier.setVerified.read", (db) =>
            db.select().from(identifiers).where(eq(identifiers.id, id)).limit(1).execute(),
          );

          const row = rows[0];
          return row === undefined
            ? null
            : {
                id: row.id,
                userId: row.userId,
                type: row.type,
                value: row.value,
                verified: row.verified,
                ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
                createdAt: row.createdAt,
              };
        }),

      delete: (id) =>
        query("identifier.delete", (db) =>
          db.delete(identifiers).where(eq(identifiers.id, id)).execute(),
        ).pipe(Effect.asVoid),

      deleteByUser: (userId) =>
        query("identifier.deleteByUser", (db) =>
          db.delete(identifiers).where(eq(identifiers.userId, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.IdentifierStore.Service;
  });

/** `IdentifierStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.IdentifierStore, make(tables));

// ---------------------------------------------------------------------------
// Requests / Resolvers
// ---------------------------------------------------------------------------

/**
 * Resolve one identifier by its `(type, value)` pair — the natural unique key.
 * Resolves to `null` on a miss, exactly like `IdentifierStore.getByValue`.
 * Issue it with `Requests.getIdentifierByValue(type, value)`.
 */
export class GetIdentifierByValue extends Request.TaggedClass("GetIdentifierByValue")<
  { readonly type: Auth.IdentifierType; readonly value: string },
  Auth.Identifier | null,
  Auth.AuthError
> {}

/**
 * List a user's identifiers, ordered by `createdAt` ascending. Resolves to `[]`
 * for a user with none, exactly like `IdentifierStore.listByUser`. Issue it
 * with `Requests.listIdentifiersByUser(userId)`.
 */
export class ListIdentifiersByUser extends Request.TaggedClass("ListIdentifiersByUser")<
  { readonly userId: string },
  ReadonlyArray<Auth.Identifier>,
  Auth.AuthError
> {}

/** `${type} ${value}` — the composite key, flattened for `Map` lookups. */
const pairKey = (type: Auth.IdentifierType, value: string): string => `${type} ${value}`;

/**
 * A resolver that collapses every {@link GetIdentifierByValue} in a batch into
 * a single query.
 *
 * `(type, value)` is a composite key, so the batch is grouped by type and
 * emitted as one `OR`-ed set of `type = $t AND value IN (...)` clauses — still
 * a single round trip even when the batch mixes emails, usernames and phone
 * numbers. Duplicate pairs are de-duplicated first.
 *
 * The returned resolver must be **shared** for batching to happen — requests
 * are grouped per resolver instance. Build it once behind
 * `Requests.AuthRequests`/`Requests.layer` rather than per call site.
 */
export const makeByValueResolver = (
  tables: Tables = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<GetIdentifierByValue>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const identifiers = tables.identifiers;
    return RequestResolver.make<GetIdentifierByValue>((entries) =>
      Effect.gen(function* () {
        const byType = new Map<Auth.IdentifierType, Set<string>>();
        for (const entry of entries) {
          const values = byType.get(entry.request.type);
          if (values === undefined) {
            byType.set(entry.request.type, new Set([entry.request.value]));
          } else {
            values.add(entry.request.value);
          }
        }

        const clauses = Array.from(byType, ([type, values]) =>
          and(eq(identifiers.type, type), inArray(identifiers.value, Array.from(values))),
        );

        const rows = yield* query("identifier.getByValueMany", (db) =>
          db
            .select()
            .from(identifiers)
            .where(clauses.length === 1 ? clauses[0] : or(...clauses))
            .execute(),
        );

        const byPair = new Map(
          rows.map((row) => [
            pairKey(row.type, row.value),
            {
              id: row.id,
              userId: row.userId,
              type: row.type,
              value: row.value,
              verified: row.verified,
              ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
              createdAt: row.createdAt,
            } satisfies Auth.Identifier,
          ]),
        );
        for (const entry of entries) {
          entry.completeUnsafe(
            Exit.succeed(byPair.get(pairKey(entry.request.type, entry.request.value)) ?? null),
          );
        }
      }),
    );
  });

/**
 * A resolver that collapses every {@link ListIdentifiersByUser} in a batch into
 * a single `WHERE user_id IN (...)` query, then splits the rows back out per
 * user.
 *
 * The single `ORDER BY created_at` carries through to each user's slice, so the
 * batched result is ordered exactly like `IdentifierStore.listByUser`, and a
 * user with no identifiers gets `[]` rather than a missing entry.
 *
 * The returned resolver must be **shared** for batching to happen — requests
 * are grouped per resolver instance. Build it once behind
 * `Requests.AuthRequests`/`Requests.layer` rather than per call site.
 */
export const makeByUserResolver = (
  tables: Tables = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<ListIdentifiersByUser>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const identifiers = tables.identifiers;
    return RequestResolver.make<ListIdentifiersByUser>((entries) =>
      Effect.gen(function* () {
        const userIds = Array.from(new Set(entries.map((entry) => entry.request.userId)));
        const rows = yield* query("identifier.listByUserMany", (db) =>
          db
            .select()
            .from(identifiers)
            .where(inArray(identifiers.userId, userIds))
            .orderBy(asc(identifiers.createdAt))
            .execute(),
        );

        const byUser = new Map<string, Array<Auth.Identifier>>();
        for (const row of rows) {
          const identifier: Auth.Identifier = {
            id: row.id,
            userId: row.userId,
            type: row.type,
            value: row.value,
            verified: row.verified,
            ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
            createdAt: row.createdAt,
          };
          const existing = byUser.get(row.userId);
          if (existing === undefined) {
            byUser.set(row.userId, [identifier]);
          } else {
            existing.push(identifier);
          }
        }

        for (const entry of entries) {
          entry.completeUnsafe(Exit.succeed(byUser.get(entry.request.userId) ?? []));
        }
      }),
    );
  });
