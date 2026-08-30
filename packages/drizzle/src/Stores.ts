/**
 * Drizzle-backed implementations of effect-auth's `SessionStore`, `UserStore`
 * and `IdentifierStore`.
 *
 * Each `make*Store` is an `Effect` that reads {@link DrizzleDatabase} out of
 * context and returns a plain store object; each `*StoreLayer` lifts it into a
 * `Layer` keyed by the matching effect-auth tag, and {@link layer} bundles all
 * three. Every factory takes an optional {@link Tables} set, so custom table
 * names are a one-argument change:
 *
 * ```ts
 * const stores = layer(defineTables({ sessions: "app_sessions" }));
 * ```
 *
 * ### Contract notes
 *
 * - Lookups return `null` on a miss; they never fail with a "not found" error.
 * - Deletes are silent no-ops when the row does not exist.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`, including the unique-index violation raised when two
 *   users race for the same `(type, value)` identifier. `Auth.claimIdentifier`
 *   in core re-reads the pair on failure and turns that race into an
 *   `IdentifierTakenError`.
 * - Session ids are SHA-256 hex digests of the bearer token, computed by the
 *   service layer — the database never sees a raw token.
 *
 * This package stands alone: it does **not** wrap
 * `@thomasfosterau/effect-auth-sql`. It speaks drizzle's PostgreSQL query
 * builder directly, so `jsonb` attribute bags and `timestamptz` columns are
 * round-tripped natively by the driver rather than encoded into `TEXT`.
 */

import { and, asc, eq } from "drizzle-orm";
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import type { IdentifierRow, SessionRow, Tables, UserRow } from "./Schema.ts";
import { tables as defaultTables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Driver plumbing
// ---------------------------------------------------------------------------

/**
 * Run a drizzle query, mapping any driver rejection to the `AuthError` the
 * store interfaces expose while preserving the underlying cause.
 */
const run = <A>(label: string, query: () => Promise<A>): Effect.Effect<A, Auth.AuthError> =>
  Effect.tryPromise({
    try: query,
    catch: (cause) => new Auth.AuthError({ message: `drizzle ${label} failed`, cause }),
  });

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

const rowToUser = (row: UserRow): Auth.User => ({
  id: row.id,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
  attributes: row.attributes ?? {},
  ...(row.name !== null ? { name: row.name } : {}),
  ...(row.image !== null ? { image: row.image } : {}),
});

const rowToIdentifier = (row: IdentifierRow): Auth.Identifier => ({
  id: row.id,
  userId: row.userId,
  type: row.type,
  value: row.value,
  verified: row.verified,
  ...(row.verifiedAt !== null ? { verifiedAt: row.verifiedAt } : {}),
  createdAt: row.createdAt,
});

// ---------------------------------------------------------------------------
// SessionStore
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

// ---------------------------------------------------------------------------
// UserStore
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

// ---------------------------------------------------------------------------
// IdentifierStore
// ---------------------------------------------------------------------------

/** Build an `IdentifierStore` over the ambient {@link DrizzleDatabase}. */
export const makeIdentifierStore = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.IdentifierStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const db = yield* DrizzleDatabase;
    const identifiers = tables.identifiers;

    return {
      getByValue: (type, value) =>
        run("identifier.getByValue", () =>
          db
            .select()
            .from(identifiers)
            .where(and(eq(identifiers.type, type), eq(identifiers.value, value)))
            .limit(1)
            .execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : rowToIdentifier(rows[0])))),

      listByUser: (userId) =>
        run("identifier.listByUser", () =>
          db
            .select()
            .from(identifiers)
            .where(eq(identifiers.userId, userId))
            .orderBy(asc(identifiers.createdAt))
            .execute(),
        ).pipe(Effect.map((rows) => rows.map(rowToIdentifier))),

      // The `(type, value)` unique index is the claim mechanism: a losing
      // racer's INSERT is rejected by PostgreSQL and surfaces here as an
      // `AuthError`, which `Auth.claimIdentifier` re-reads into an
      // `IdentifierTakenError`.
      create: (identifier) =>
        run("identifier.create", () =>
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

      setVerified: (id, verifiedAt) =>
        run("identifier.setVerified", () =>
          db
            .update(identifiers)
            .set({ verified: true, verifiedAt })
            .where(eq(identifiers.id, id))
            .returning()
            .execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : rowToIdentifier(rows[0])))),

      delete: (id) =>
        run("identifier.delete", () =>
          db.delete(identifiers).where(eq(identifiers.id, id)).execute(),
        ).pipe(Effect.asVoid),

      deleteByUser: (userId) =>
        run("identifier.deleteByUser", () =>
          db.delete(identifiers).where(eq(identifiers.userId, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.IdentifierStore.Service;
  });

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/** `SessionStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const sessionStoreLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.SessionStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.SessionStore, makeSessionStore(tables));

/** `UserStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const userStoreLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.UserStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.UserStore, makeUserStore(tables));

/** `IdentifierStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const identifierStoreLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.IdentifierStore, makeIdentifierStore(tables));

/**
 * Every drizzle-backed store in one layer. Provide it together with a
 * {@link DrizzleDatabase} layer and the session/sign-in path (session
 * validation, credential lookup, identifier resolution) has persistence.
 *
 * Stores beyond these three — OAuth accounts, WebAuthn credentials, rate
 * limits, and the rest — are not covered here yet; use
 * `@thomasfosterau/effect-auth-sql` or a `KeyValueStore`-backed layer from
 * core for those.
 */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.mergeAll(sessionStoreLayer(tables), userStoreLayer(tables), identifierStoreLayer(tables));
