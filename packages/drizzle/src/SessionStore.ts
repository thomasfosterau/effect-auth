/**
 * Drizzle `SessionStore` and the batched session reads, over a dialect's {@link
 * Tables} or a `defineSchema` mapping. Session ids are the token digests the
 * service computes. `touch` moves only the expiry columns, guarded so it never
 * recreates a deleted session.
 */

import { and, asc, eq, gte, inArray } from "drizzle-orm";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Request from "effect/Request";
import * as RequestResolver from "effect/RequestResolver";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  resolveSchema,
  type SchemaInput,
  type SessionColumns,
  type SessionSchema,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { affectedRows, completeById, makeQuery } from "./internal.ts";
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

    const get = (label: string, sessionId: string) =>
      query(label, (db) =>
        db.select(column).from(table).where(eq(column.id, sessionId)).limit(1).execute(),
      ).pipe(Effect.map((rows) => Option.map(Arr.head(rows), toSession)));

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

      get: (sessionId) => get("session.get", sessionId),

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

      touch: (sessionId, touch) =>
        Effect.gen(function* () {
          const matched = yield* affectedRows(
            "session.touch",
            query("session.touch", (db) =>
              db
                .update(table)
                .set(
                  writeValues(sessions, {
                    expiresAt: touch.expiresAt,
                    lastActivityAt: touch.lastActivityAt,
                  }),
                )
                .where(and(eq(column.id, sessionId), gte(column.expiresAt, touch.lastActivityAt)))
                .execute(),
            ),
          );
          return matched > 0 ? yield* get("session.touch.read", sessionId) : Option.none();
        }),

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
 * Resolves to `None` on a miss, exactly like `SessionStore.get`. Issue it with
 * `Requests.getSession(id)` rather than constructing it by hand.
 */
export class GetSession extends Request.TaggedClass("GetSession")<
  { readonly id: string },
  Option.Option<Auth.Session>,
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
