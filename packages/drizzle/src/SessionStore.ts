/**
 * Drizzle-backed implementation of effect-auth's `SessionStore`, plus the
 * `Request`/`RequestResolver` pair that batches session reads.
 *
 * {@link makeSessionStore} is an `Effect` that reads {@link DrizzleDatabase} out
 * of context and returns a plain store object; {@link sessionStoreLayer} lifts
 * it into a `Layer` keyed by `Auth.SessionStore`. Both take an optional
 * {@link Tables} set, so custom table names are a one-argument change.
 *
 * ### Contract notes
 *
 * - `get` returns `null` on a miss; it never fails with a "not found" error.
 * - Deletes are silent no-ops when the row does not exist.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 * - Session ids are SHA-256 hex digests of the bearer token, computed by the
 *   service layer — the database never sees a raw token.
 */

import { asc, eq, inArray } from "drizzle-orm";
import { Effect, Exit, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import { run } from "./internal.ts";
import type { SessionRow, Tables } from "./Schema.ts";
import { tables as defaultTables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Row -> domain mapping
// ---------------------------------------------------------------------------

const rowToSession = (row: SessionRow): Auth.Session => ({
  id: row.id,
  userId: row.userId,
  expiresAt: row.expiresAt,
  createdAt: row.createdAt,
  lastActivityAt: row.lastActivityAt,
  attributes: row.attributes ?? {},
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Build a `SessionStore` over the ambient {@link DrizzleDatabase}. */
export const makeSessionStore = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.SessionStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const db = yield* DrizzleDatabase;
    const sessions = tables.sessions;

    return {
      create: (session) =>
        run("session.create", () =>
          db
            .insert(sessions)
            .values({
              id: session.id,
              userId: session.userId,
              expiresAt: session.expiresAt,
              createdAt: session.createdAt,
              lastActivityAt: session.lastActivityAt,
              attributes: session.attributes,
            })
            .execute(),
        ).pipe(Effect.as(session)),

      get: (sessionId) =>
        run("session.get", () =>
          db.select().from(sessions).where(eq(sessions.id, sessionId)).limit(1).execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : rowToSession(rows[0])))),

      update: (session) =>
        run("session.update", () =>
          db
            .update(sessions)
            .set({
              expiresAt: session.expiresAt,
              lastActivityAt: session.lastActivityAt,
              attributes: session.attributes,
            })
            .where(eq(sessions.id, session.id))
            .execute(),
        ).pipe(Effect.as(session)),

      delete: (sessionId) =>
        run("session.delete", () =>
          db.delete(sessions).where(eq(sessions.id, sessionId)).execute(),
        ).pipe(Effect.asVoid),

      deleteByUserId: (userId) =>
        run("session.deleteByUserId", () =>
          db.delete(sessions).where(eq(sessions.userId, userId)).execute(),
        ).pipe(Effect.asVoid),

      listByUserId: (userId) =>
        run("session.listByUserId", () =>
          db
            .select()
            .from(sessions)
            .where(eq(sessions.userId, userId))
            .orderBy(asc(sessions.createdAt))
            .execute(),
        ).pipe(Effect.map((rows) => rows.map(rowToSession))),
    } satisfies typeof Auth.SessionStore.Service;
  });

/** `SessionStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const sessionStoreLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.SessionStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.SessionStore, makeSessionStore(tables));

// ---------------------------------------------------------------------------
// Request / Resolver
// ---------------------------------------------------------------------------

/**
 * Read one session by its id (the SHA-256 hash of the bearer token).
 *
 * Resolves to `null` on a miss, exactly like `SessionStore.get`. Issue it with
 * `Drizzle.getSession(id)` rather than constructing it by hand.
 */
export class GetSession extends Request.TaggedClass("GetSession")<
  { readonly id: string },
  Auth.Session | null,
  Auth.AuthError
> {}

/**
 * A resolver that collapses every {@link GetSession} in a batch into a single
 * `WHERE id IN (...)` query.
 *
 * Duplicate ids in the same batch are de-duplicated before the query is built,
 * so N concurrent lookups of the same session cost one row read.
 *
 * The returned resolver must be **shared** for batching to happen — requests
 * are grouped per resolver instance. Build it once behind
 * `AuthRequests`/`requestsLayer` rather than per call site.
 */
export const makeSessionResolver = (
  tables: Tables = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<GetSession>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (db) => {
    const sessions = tables.sessions;
    return RequestResolver.make<GetSession>((entries) =>
      Effect.gen(function* () {
        const ids = Array.from(new Set(entries.map((entry) => entry.request.id)));
        const rows = yield* run("session.getMany", () =>
          db.select().from(sessions).where(inArray(sessions.id, ids)).execute(),
        );

        const byId = new Map(rows.map((row) => [row.id, rowToSession(row)]));
        for (const entry of entries) {
          entry.completeUnsafe(Exit.succeed(byId.get(entry.request.id) ?? null));
        }
      }),
    );
  });
