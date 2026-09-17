/**
 * Drizzle-backed implementation of effect-auth's `UserStore`, plus the
 * `Request`/`RequestResolver` pair that batches user reads.
 *
 * {@link make} is an `Effect` that reads {@link DrizzleDatabase} out of context
 * and returns a plain store object; {@link layer} lifts it into a `Layer` keyed
 * by `Auth.UserStore`. Both take an optional schema — any dialect's
 * {@link Tables} under any names, or an {@link AuthSchema} mapped onto the
 * application's own table — so switching database, table names or table shape
 * is a one-argument change.
 *
 * ### Contract notes
 *
 * - `get` returns `null` on a miss; it never fails with a "not found" error.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { eq, inArray } from "drizzle-orm";
import { Effect, Exit, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { resolveSchema, type SchemaInput, type UserColumns, type UserSchema } from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/** What a user read projects, under the store's own field names. */
type UserRow = DrizzleSelected<UserColumns>;

const toUser = (row: UserRow): Auth.User => ({
  id: row.id,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
  attributes: row.attributes ?? {},
  ...(row.name !== null ? { name: row.name } : {}),
  ...(row.image !== null ? { image: row.image } : {}),
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Build a `UserStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof Auth.UserStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const users: UserSchema = resolveSchema(schema).users;
    const column = users.columns;
    const table = users.table;

    const byId = (userId: string, label: string): Effect.Effect<UserRow | null, Auth.AuthError> =>
      query(label, (db) =>
        db.select(column).from(table).where(eq(column.id, userId)).limit(1).execute(),
      ).pipe(Effect.map((rows) => rows[0] ?? null));

    return {
      get: (userId) =>
        byId(userId, "user.get").pipe(Effect.map((row) => (row === null ? null : toUser(row)))),
    } satisfies typeof Auth.UserStore.Service;
  });

/** `UserStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.UserStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.UserStore, make(schema));

// ---------------------------------------------------------------------------
// Requests / Resolver
// ---------------------------------------------------------------------------

/**
 * Read one user by id. Resolves to `null` on a miss, exactly like
 * `UserStore.get`. Issue it with `Requests.getUser(id)`.
 */
export class GetUser extends Request.TaggedClass("GetUser")<
  { readonly id: string },
  Auth.User | null,
  Auth.AuthError
> {}

/** Every request served by {@link makeResolver}. */
export type UserRequest = GetUser;

/**
 * A resolver that collapses every {@link GetUser} in a batch into a single
 * `WHERE id IN (...)` query.
 *
 * Duplicate ids inside the batch are de-duplicated before the query is built.
 *
 * The returned resolver must be **shared** for batching to happen — requests
 * are grouped per resolver instance. Build it once behind
 * `Requests.AuthRequests`/`Requests.layer` rather than per call site.
 */
export const makeResolver = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<UserRequest>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const users: UserSchema = resolveSchema(schema).users;
    const column = users.columns;
    const table = users.table;

    return RequestResolver.make<UserRequest>((entries) =>
      Effect.gen(function* () {
        const ids = Array.from(new Set(entries.map((entry) => entry.request.id)));
        const rows = yield* query("user.getMany", (db) =>
          db.select(column).from(table).where(inArray(column.id, ids)).execute(),
        );

        const byId = new Map(rows.map((row) => [row.id, row]));
        for (const entry of entries) {
          const row = byId.get(entry.request.id);
          entry.completeUnsafe(Exit.succeed(row === undefined ? null : toUser(row)));
        }
      }),
    );
  });
