/**
 * Drizzle-backed implementation of effect-auth's `IdentifierStore`, plus the
 * `Request`/`RequestResolver` pairs that batch identifier reads.
 *
 * {@link make} is an `Effect` that reads {@link DrizzleDatabase} out of context
 * and returns a plain store object; {@link layer} lifts it into a `Layer` keyed
 * by `Auth.IdentifierStore`. Both take an optional schema — any dialect's
 * {@link Tables} under any names, or an {@link AuthSchema} mapped onto the
 * application's own table — so switching database, table names or table shape
 * is a one-argument change.
 *
 * ### Contract notes
 *
 * - `getByValue` and `setVerified` return `null` on a miss; they never fail
 *   with a "not found" error.
 * - Deletes are silent no-ops when the row does not exist.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`, including the unique-index violation raised when two
 *   users race for the same `(type, value)` identifier. `Auth.claimIdentifier`
 *   and `Auth.replaceIdentifier` in core re-read the pair on failure and turn
 *   that race into an `IdentifierTakenError`.
 * - `replace` inserts the new identifier and then deletes the old one. The
 *   store opens no transaction of its own: run on a handle inside the
 *   application's transaction, the two statements commit or roll back together;
 *   otherwise each autocommits, and a failure between them leaves the user
 *   holding both identifiers, never neither. A value another user holds is
 *   refused by the unique index before anything is deleted.
 */

import { and, asc, eq, inArray, or } from "drizzle-orm";
import { Effect, Exit, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type IdentifierColumns,
  type IdentifierSchema,
  resolveSchema,
  type SchemaInput,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/** What an identifier read projects, under the store's own field names. */
type IdentifierRow = DrizzleSelected<IdentifierColumns>;

const toIdentifier = (row: IdentifierRow): Auth.Identifier => ({
  id: row.id,
  userId: row.userId,
  type: row.type,
  value: row.value,
  verified: row.verified,
  ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
  createdAt: row.createdAt,
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Build an `IdentifierStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof Auth.IdentifierStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const identifiers: IdentifierSchema = resolveSchema(schema).identifiers;
    const column = identifiers.columns;
    const table = identifiers.table;

    const insert = (identifier: Auth.Identifier, label: string) =>
      query(label, (db) =>
        db
          .insert(table)
          .values(
            writeValues(identifiers, {
              id: identifier.id,
              userId: identifier.userId,
              type: identifier.type,
              value: identifier.value,
              verified: identifier.verified,
              verifiedAt: identifier.verifiedAt ?? null,
              createdAt: identifier.createdAt,
            }),
          )
          .execute(),
      ).pipe(Effect.as(identifier));

    return {
      getByValue: (type, value) =>
        query("identifier.getByValue", (db) =>
          db
            .select(column)
            .from(table)
            .where(and(eq(column.type, type), eq(column.value, value)))
            .limit(1)
            .execute(),
        ).pipe(
          Effect.map((rows) => {
            const row = rows[0];
            return row === undefined ? null : toIdentifier(row);
          }),
        ),

      listByUser: (userId) =>
        query("identifier.listByUser", (db) =>
          db
            .select(column)
            .from(table)
            .where(eq(column.userId, userId))
            .orderBy(asc(column.createdAt))
            .execute(),
        ).pipe(Effect.map((rows) => rows.map(toIdentifier))),

      // The `(type, value)` unique index is the claim mechanism: a losing
      // racer's INSERT is rejected by the database and surfaces here as an
      // `AuthError`, which `Auth.claimIdentifier` re-reads into an
      // `IdentifierTakenError`.
      create: (identifier) => insert(identifier, "identifier.create"),

      // Claim, then release: the INSERT goes first so the unique index refuses a
      // taken value while `from` is still in place.
      replace: (from, to) => {
        const invalid = Auth.replaceInputError(from, to);
        if (invalid !== null) return Effect.fail(invalid);
        return Effect.gen(function* () {
          const held = yield* query("identifier.replace.read", (db) =>
            db
              .select({ id: column.id })
              .from(table)
              .where(
                and(
                  eq(column.id, from.id),
                  eq(column.userId, from.userId),
                  eq(column.type, from.type),
                  eq(column.value, from.value),
                ),
              )
              .limit(1)
              .execute(),
          );
          if (held.length === 0) return null;
          yield* insert(to, "identifier.replace");
          yield* query("identifier.replace.release", (db) =>
            db.delete(table).where(eq(column.id, from.id)).execute(),
          );
          return to;
        });
      },

      // `UPDATE ... RETURNING` would be one statement, but MySQL has no
      // `RETURNING` clause, so the updated row is read back instead — the same
      // two statements on all three dialects rather than a per-dialect branch.
      setVerified: (id, verifiedAt) =>
        Effect.gen(function* () {
          yield* query("identifier.setVerified", (db) =>
            db
              .update(table)
              .set(writeValues(identifiers, { verified: true, verifiedAt }))
              .where(eq(column.id, id))
              .execute(),
          );

          const rows = yield* query("identifier.setVerified.read", (db) =>
            db.select(column).from(table).where(eq(column.id, id)).limit(1).execute(),
          );

          const row = rows[0];
          return row === undefined ? null : toIdentifier(row);
        }),

      delete: (id) =>
        query("identifier.delete", (db) =>
          db.delete(table).where(eq(column.id, id)).execute(),
        ).pipe(Effect.asVoid),

      deleteByUser: (userId) =>
        query("identifier.deleteByUser", (db) =>
          db.delete(table).where(eq(column.userId, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.IdentifierStore.Service;
  });

/** `IdentifierStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.IdentifierStore, make(schema));

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
  schema: SchemaInput = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<GetIdentifierByValue>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const identifiers: IdentifierSchema = resolveSchema(schema).identifiers;
    const column = identifiers.columns;
    const table = identifiers.table;

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
          and(eq(column.type, type), inArray(column.value, Array.from(values))),
        );

        const rows = yield* query("identifier.getByValueMany", (db) =>
          db
            .select(column)
            .from(table)
            .where(clauses.length === 1 ? clauses[0] : or(...clauses))
            .execute(),
        );

        const byPair = new Map(
          rows.map((row) => [pairKey(row.type, row.value), toIdentifier(row)]),
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
  schema: SchemaInput = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<ListIdentifiersByUser>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const identifiers: IdentifierSchema = resolveSchema(schema).identifiers;
    const column = identifiers.columns;
    const table = identifiers.table;

    return RequestResolver.make<ListIdentifiersByUser>((entries) =>
      Effect.gen(function* () {
        const userIds = Array.from(new Set(entries.map((entry) => entry.request.userId)));
        const rows = yield* query("identifier.listByUserMany", (db) =>
          db
            .select(column)
            .from(table)
            .where(inArray(column.userId, userIds))
            .orderBy(asc(column.createdAt))
            .execute(),
        );

        const byUser = new Map<string, Array<Auth.Identifier>>();
        for (const row of rows) {
          const identifier = toIdentifier(row);
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
