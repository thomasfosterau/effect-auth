/**
 * Drizzle-backed implementation of effect-auth's `SessionStore`, plus the
 * `Request`/`RequestResolver` pair that batches session reads.
 *
 * {@link make} is an `Effect` that reads {@link DrizzleDatabase} out of context
 * and returns a plain store object; {@link layer} lifts it into a `Layer` keyed
 * by `Auth.SessionStore`. Both take an optional schema — any dialect's
 * {@link Tables} under any names, or an {@link AuthSchema} mapped onto the
 * application's own table — so switching database, table names or table shape
 * is a one-argument change.
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
import { Effect, Layer, Request, RequestResolver } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  resolveSchema,
  type SchemaInput,
  type SessionColumns,
  type SessionSchema,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { completeById, makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/**
 * What a session read projects, whatever the underlying columns are called: the
 * mapping names them, so the row comes back under the store's own field names.
 */
type SessionRow = DrizzleSelected<SessionColumns>;

const toSession = (row: SessionRow): Auth.Session => ({
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
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof Auth.SessionStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const sessions: SessionSchema = resolveSchema(schema).sessions;
    const column = sessions.columns;
    const table = sessions.table;

    return {
      create: (session) =>
        query("session.create", (db) =>
          db
            .insert(table)
            .values(
              writeValues(sessions, {
                id: session.id,
                userId: session.userId,
                expiresAt: session.expiresAt,
                createdAt: session.createdAt,
                lastActivityAt: session.lastActivityAt,
                attributes: session.attributes,
              }),
            )
            .execute(),
        ).pipe(Effect.as(session)),

      get: (sessionId) =>
        query("session.get", (db) =>
          db.select(column).from(table).where(eq(column.id, sessionId)).limit(1).execute(),
        ).pipe(
          Effect.map((rows) => {
            const row = rows[0];
            return row === undefined ? null : toSession(row);
          }),
        ),

      update: (session) =>
        query("session.update", (db) =>
          db
            .update(table)
            .set(
              writeValues(sessions, {
                expiresAt: session.expiresAt,
                lastActivityAt: session.lastActivityAt,
                attributes: session.attributes,
              }),
            )
            .where(eq(column.id, session.id))
            .execute(),
        ).pipe(Effect.as(session)),

      delete: (sessionId) =>
        query("session.delete", (db) =>
          db.delete(table).where(eq(column.id, sessionId)).execute(),
        ).pipe(Effect.asVoid),

      deleteByUserId: (userId) =>
        query("session.deleteByUserId", (db) =>
          db.delete(table).where(eq(column.userId, userId)).execute(),
        ).pipe(Effect.asVoid),

      listByUserId: (userId) =>
        query("session.listByUserId", (db) =>
          db
            .select(column)
            .from(table)
            .where(eq(column.userId, userId))
            .orderBy(asc(column.createdAt))
            .execute(),
        ).pipe(Effect.map((rows) => rows.map(toSession))),
    } satisfies typeof Auth.SessionStore.Service;
  });

/** `SessionStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.SessionStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.SessionStore, make(schema));

// ---------------------------------------------------------------------------
// Request / Resolver
// ---------------------------------------------------------------------------

/**
 * Read one session by its id (the SHA-256 hash of the bearer token).
 *
 * Resolves to `null` on a miss, exactly like `SessionStore.get`. Issue it with
 * `Requests.getSession(id)` rather than constructing it by hand.
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
 * `Requests.AuthRequests`/`Requests.layer` rather than per call site.
 */
export const makeResolver = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<RequestResolver.RequestResolver<GetSession>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const sessions: SessionSchema = resolveSchema(schema).sessions;
    const column = sessions.columns;
    const table = sessions.table;

    return RequestResolver.make<GetSession>((entries) =>
      completeById(
        entries,
        (ids) =>
          query("session.getMany", (db) =>
            db.select(column).from(table).where(inArray(column.id, ids)).execute(),
          ),
        toSession,
      ),
    );
  });
