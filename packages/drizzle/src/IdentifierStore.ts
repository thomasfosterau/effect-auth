/**
 * Drizzle `IdentifierStore` and the batched identifier reads, over a dialect's
 * {@link Tables} or a `defineSchema` mapping. A unique-index violation is an
 * `AuthError`, which core turns into `IdentifierTakenError`. `replace` inserts,
 * then deletes, in no transaction of its own: outside the application's, a
 * failure leaves both identifiers.
 */

import { and, asc, eq, inArray, or } from "drizzle-orm";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as HashMap from "effect/HashMap";
import * as Layer from "effect/Layer";
import * as Request from "effect/Request";
import * as RequestResolver from "effect/RequestResolver";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type IdentifierColumns,
  type IdentifierSchema,
  resolveSchema,
  type SchemaInput,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { makeQuery, type Query } from "./internal.ts";
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
        ).pipe(Effect.map((rows) => Option.map(Arr.head(rows), toIdentifier))),

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
        if (Option.isSome(invalid)) return Effect.fail(invalid.value);
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
          if (Arr.isReadonlyArrayEmpty(held)) return Option.none();
          yield* insert(to, "identifier.replace");
          yield* query("identifier.replace.release", (db) =>
            db.delete(table).where(eq(column.id, from.id)).execute(),
          );
          return Option.some(to);
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

          return Option.map(Arr.head(rows), toIdentifier);
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
 * Resolves to `None` on a miss, exactly like `IdentifierStore.getByValue`.
 * Issue it with `Requests.getIdentifierByValue(type, value)`.
 */
export class GetIdentifierByValue extends Request.TaggedClass("GetIdentifierByValue")<
  { readonly type: Auth.IdentifierType; readonly value: string },
  Option.Option<Auth.Identifier>,
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

/**
 * Build a resolver over the schema's identifiers table, with the per-query
 * runner bound to the `DrizzleDatabase` in scope.
 */
const withIdentifierTable = <A>(
  schema: SchemaInput,
  build: (query: Query, identifiers: IdentifierSchema) => A,
): Effect.Effect<A, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) =>
    build(makeQuery(handle), resolveSchema(schema).identifiers),
  );

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
  withIdentifierTable(schema, (query, { columns: column, table }) =>
    RequestResolver.make<GetIdentifierByValue>((entries) =>
      Effect.gen(function* () {
        const byType = Arr.groupBy(entries, (entry): string => entry.request.type);

        const clauses = R.collect(byType, (_type, group) =>
          and(
            eq(column.type, group[0].request.type),
            inArray(column.value, Arr.dedupe(group.map((entry) => entry.request.value))),
          ),
        );

        const rows = yield* query("identifier.getByValueMany", (db) =>
          db
            .select(column)
            .from(table)
            .where(clauses.length === 1 ? clauses[0] : or(...clauses))
            .execute(),
        );

        const byPair = HashMap.fromIterable(
          rows.map((row) => [pairKey(row.type, row.value), toIdentifier(row)] as const),
        );
        Arr.forEach(entries, (entry) =>
          entry.completeUnsafe(
            Exit.succeed(HashMap.get(byPair, pairKey(entry.request.type, entry.request.value))),
          ),
        );
      }),
    ),
  );

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
  withIdentifierTable(schema, (query, { columns: column, table }) =>
    RequestResolver.make<ListIdentifiersByUser>((entries) =>
      Effect.gen(function* () {
        const userIds = Arr.dedupe(entries.map((entry) => entry.request.userId));
        const rows = yield* query("identifier.listByUserMany", (db) =>
          db
            .select(column)
            .from(table)
            .where(inArray(column.userId, userIds))
            .orderBy(asc(column.createdAt))
            .execute(),
        );

        const byUser = R.map(
          Arr.groupBy(rows, (row) => row.userId),
          (userRows) => userRows.map(toIdentifier),
        );

        Arr.forEach(entries, (entry) =>
          entry.completeUnsafe(
            Exit.succeed(Option.getOrElse(R.get(byUser, entry.request.userId), () => [])),
          ),
        );
      }),
    ),
  );
