import { Effect, Layer } from "effect"
import { eq } from "drizzle-orm"
import { SessionStore, AuthError, SessionNotFoundError } from "effect-auth"
import type { Session } from "effect-auth"
import { DrizzleDatabase } from "./database.js"
import { sessionsTable } from "./schema.js"
import type { SessionsTable } from "./schema.js"

/**
 * Convert a sessions table row to a Session domain object.
 */
const rowToSession = (row: SessionsTable["$inferSelect"]): Session => ({
  id: row.id,
  userId: row.userId,
  expiresAt: row.expiresAt,
  createdAt: row.createdAt,
  lastActivityAt: row.lastActivityAt,
  attributes: row.attributes,
})

/**
 * Create a SessionStore Layer backed by a Drizzle PostgreSQL database.
 *
 * By default the built-in `sessionsTable` schema is used. Pass a custom table
 * if you have defined your own schema.
 *
 * @example
 * ```ts
 * const SessionStoreLive = makeDrizzleSessionStoreLive()
 * // or with a custom table:
 * const SessionStoreLive = makeDrizzleSessionStoreLive(mySessionsTable)
 * ```
 */
export const makeDrizzleSessionStoreLive = (
  table: SessionsTable = sessionsTable
): Layer.Layer<SessionStore, never, DrizzleDatabase> =>
  Layer.effect(
    SessionStore,
    Effect.gen(function* () {
      const db = yield* DrizzleDatabase

      return {
        create: (session: Session) =>
          Effect.tryPromise({
            try: async () => {
              const rows = await db
                .insert(table)
                .values({
                  id: session.id,
                  userId: session.userId,
                  expiresAt: session.expiresAt,
                  createdAt: session.createdAt,
                  lastActivityAt: session.lastActivityAt,
                  attributes: session.attributes,
                })
                .returning()
              const row = rows[0]
              if (row === undefined) {
                throw new Error("Insert returned no rows")
              }
              return rowToSession(row)
            },
            catch: (err) =>
              new AuthError({ message: `Failed to create session: ${String(err)}` }),
          }),

        get: (sessionId: string) =>
          Effect.gen(function* () {
            const rows = yield* Effect.tryPromise({
              try: () =>
                db.select().from(table).where(eq(table.id, sessionId)),
              catch: (err) =>
                new SessionNotFoundError({
                  message: `Failed to get session: ${String(err)}`,
                  sessionId,
                }),
            })
            const row = rows[0]
            if (row === undefined) {
              return yield* Effect.fail(
                new SessionNotFoundError({ message: "Session not found", sessionId })
              )
            }
            return rowToSession(row)
          }),

        update: (session: Session) =>
          Effect.tryPromise({
            try: async () => {
              const rows = await db
                .update(table)
                .set({
                  expiresAt: session.expiresAt,
                  lastActivityAt: session.lastActivityAt,
                  attributes: session.attributes,
                })
                .where(eq(table.id, session.id))
                .returning()
              const row = rows[0]
              if (row === undefined) {
                throw new Error("Update returned no rows")
              }
              return rowToSession(row)
            },
            catch: (err) =>
              new AuthError({ message: `Failed to update session: ${String(err)}` }),
          }),

        delete: (sessionId: string) =>
          Effect.tryPromise({
            try: () => db.delete(table).where(eq(table.id, sessionId)).then(() => undefined),
            catch: (err) =>
              new AuthError({ message: `Failed to delete session: ${String(err)}` }),
          }),

        deleteByUserId: (userId: string) =>
          Effect.tryPromise({
            try: () =>
              db.delete(table).where(eq(table.userId, userId)).then(() => undefined),
            catch: (err) =>
              new AuthError({
                message: `Failed to delete sessions for user: ${String(err)}`,
              }),
          }),
      }
    })
  )

/**
 * Default DrizzleSessionStoreLive using the built-in sessions table schema.
 */
export const DrizzleSessionStoreLive = makeDrizzleSessionStoreLive()
