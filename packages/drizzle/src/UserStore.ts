/**
 * Drizzle-backed implementation of effect-auth's `UserStore`, plus the
 * `Request`/`RequestResolver` pair that batches user reads.
 *
 * {@link makeUserStore} is an `Effect` that reads {@link DrizzleDatabase} out of
 * context and returns a plain store object; {@link userStoreLayer} lifts it
 * into a `Layer` keyed by `Auth.UserStore`. Both take an optional
 * {@link Tables} set, so custom table names are a one-argument change.
 *
 * ### Contract notes
 *
 * - `get` and `getCredentials` return `null` on a miss; they never fail with a
 *   "not found" error.
 * - `getCredentials` reads `password_hash`; writing it belongs to a store this
 *   package does not implement yet.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { eq, inArray } from "drizzle-orm";
import { Effect, Exit, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import { run } from "./internal.ts";
import type { Tables, UserRow } from "./Schema.ts";
import { tables as defaultTables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Row -> domain mapping
// ---------------------------------------------------------------------------

const rowToUser = (row: UserRow): Auth.User => ({
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
export const makeUserStore = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.UserStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const db = yield* DrizzleDatabase;
    const users = tables.users;

    const byId = (userId: string, label: string) =>
      run(label, () => db.select().from(users).where(eq(users.id, userId)).limit(1).execute()).pipe(
        Effect.map((rows) => rows[0] ?? null),
      );

    return {
      get: (userId) =>
        byId(userId, "user.get").pipe(Effect.map((row) => (row === null ? null : rowToUser(row)))),

      getCredentials: (userId) =>
        byId(userId, "user.getCredentials").pipe(Effect.map((row) => row?.passwordHash ?? null)),
    } satisfies typeof Auth.UserStore.Service;
  });

/** `UserStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const userStoreLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.UserStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.UserStore, makeUserStore(tables));

// ---------------------------------------------------------------------------
// Requests / Resolver
// ---------------------------------------------------------------------------

/**
 * Read one user by id. Resolves to `null` on a miss, exactly like
 * `UserStore.get`. Issue it with `Drizzle.getUser(id)`.
 */
export class GetUser extends Request.TaggedClass("GetUser")<
  { readonly id: string },
  Auth.User | null,
  Auth.AuthError
> {}

/**
 * Read one user's password hash. Resolves to `null` when the user does not
 * exist *or* has no password set — the same conflation `UserStore.getCredentials`
 * makes. Issue it with `Drizzle.getUserCredentials(id)`.
 */
export class GetUserCredentials extends Request.TaggedClass("GetUserCredentials")<
  { readonly id: string },
  string | null,
  Auth.AuthError
> {}

/** Every request served by {@link makeUserResolver}. */
export type UserRequest = GetUser | GetUserCredentials;

/**
 * A resolver that collapses every {@link GetUser} and {@link GetUserCredentials}
 * in a batch into a single `WHERE id IN (...)` query.
 *
 * Both requests read the same row, so they share one resolver — and therefore
 * one batch and one query. A page that renders a user and checks whether that
 * user has a password costs one round trip, not two, and duplicate ids inside
 * the batch are de-duplicated before the query is built.
 *
 * The returned resolver must be **shared** for batching to happen — requests
 * are grouped per resolver instance. Build it once behind
 * `AuthRequests`/`requestsLayer` rather than per call site.
 */
export const makeUserResolver = (
  tables: Tables = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<UserRequest>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (db) => {
    const users = tables.users;
    return RequestResolver.make<UserRequest>((entries) =>
      Effect.gen(function* () {
        const ids = Array.from(new Set(entries.map((entry) => entry.request.id)));
        const rows = yield* run("user.getMany", () =>
          db.select().from(users).where(inArray(users.id, ids)).execute(),
        );

        const byId = new Map(rows.map((row) => [row.id, row]));
        for (const entry of entries) {
          const row = byId.get(entry.request.id);
          entry.completeUnsafe(
            Exit.succeed(
              entry.request._tag === "GetUser"
                ? row === undefined
                  ? null
                  : rowToUser(row)
                : (row?.passwordHash ?? null),
            ),
          );
        }
      }),
    );
  });
