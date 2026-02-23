import { Effect, Layer } from "effect"
import { eq } from "drizzle-orm"
import { UserStore, UserNotFoundError } from "effect-auth"
import type { User } from "effect-auth"
import { DrizzleDatabase } from "./database.js"
import { usersTable } from "./schema.js"
import type { UsersTable } from "./schema.js"

/**
 * Convert a users table row to a User domain object.
 */
const rowToUser = (row: Pick<UsersTable["$inferSelect"], "id" | "attributes">): User => ({
  id: row.id,
  attributes: row.attributes,
})

/**
 * Create a UserStore Layer backed by a Drizzle PostgreSQL database.
 *
 * By default the built-in `usersTable` schema is used. Pass a custom table
 * if you have defined your own schema.
 *
 * @example
 * ```ts
 * const UserStoreLive = makeDrizzleUserStoreLive()
 * // or with a custom table:
 * const UserStoreLive = makeDrizzleUserStoreLive(myUsersTable)
 * ```
 */
export const makeDrizzleUserStoreLive = (
  table: UsersTable = usersTable
): Layer.Layer<UserStore, never, DrizzleDatabase> =>
  Layer.effect(
    UserStore,
    Effect.gen(function* () {
      const db = yield* DrizzleDatabase

      return {
        get: (userId: string) =>
          Effect.gen(function* () {
            const rows = yield* Effect.tryPromise({
              try: () =>
                db
                  .select({ id: table.id, attributes: table.attributes })
                  .from(table)
                  .where(eq(table.id, userId)),
              catch: (err) =>
                new UserNotFoundError({
                  message: `Failed to get user: ${String(err)}`,
                  userId,
                }),
            })
            const row = rows[0]
            if (row === undefined) {
              return yield* Effect.fail(
                new UserNotFoundError({ message: "User not found", userId })
              )
            }
            return rowToUser(row)
          }),

        getCredentials: (userId: string) =>
          Effect.gen(function* () {
            const rows = yield* Effect.tryPromise({
              try: () =>
                db
                  .select({ hashedPassword: table.hashedPassword })
                  .from(table)
                  .where(eq(table.id, userId)),
              catch: (err) =>
                new UserNotFoundError({
                  message: `Failed to get credentials: ${String(err)}`,
                  userId,
                }),
            })
            const row = rows[0]
            if (row === undefined || row.hashedPassword === null) {
              return yield* Effect.fail(
                new UserNotFoundError({ message: "User credentials not found", userId })
              )
            }
            return row.hashedPassword
          }),
      }
    })
  )

/**
 * Default DrizzleUserStoreLive using the built-in users table schema.
 */
export const DrizzleUserStoreLive = makeDrizzleUserStoreLive()
