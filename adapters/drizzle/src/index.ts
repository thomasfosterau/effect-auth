/**
 * @effect-auth/adapter-drizzle
 *
 * Drizzle ORM adapter for effect-auth.
 * Implements SessionStore and UserStore using a PostgreSQL Drizzle database.
 *
 * @example
 * ```ts
 * import { drizzle } from "drizzle-orm/node-postgres"
 * import { Layer } from "effect"
 * import {
 *   DrizzleDatabase,
 *   DrizzleSessionStoreLive,
 *   DrizzleUserStoreLive,
 * } from "@effect-auth/adapter-drizzle"
 *
 * const pool = new Pool({ connectionString: process.env.DATABASE_URL })
 * const DatabaseLive = Layer.succeed(DrizzleDatabase, drizzle(pool))
 *
 * const StoreLive = Layer.mergeAll(
 *   DrizzleSessionStoreLive,
 *   DrizzleUserStoreLive,
 * ).pipe(Layer.provide(DatabaseLive))
 * ```
 */

// Database service tag
export { DrizzleDatabase } from "./database.js"
export type { DrizzleDatabase as DrizzleDatabaseType } from "./database.js"

// Default schema tables
export { sessionsTable, usersTable } from "./schema.js"
export type { SessionsTable, UsersTable } from "./schema.js"

// Session store
export { DrizzleSessionStoreLive, makeDrizzleSessionStoreLive } from "./session-store.js"

// User store
export { DrizzleUserStoreLive, makeDrizzleUserStoreLive } from "./user-store.js"
