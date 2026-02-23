import { Context } from "effect"
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core"

/**
 * A Drizzle PostgreSQL database instance.
 * Compatible with any PostgreSQL driver (node-postgres, postgres.js, etc.).
 */
export type DrizzleDatabase = PgDatabase<PgQueryResultHKT, Record<string, never>>

/**
 * Service tag for the Drizzle database instance.
 *
 * Provide your configured drizzle db when building the Layer:
 * @example
 * ```ts
 * import { drizzle } from "drizzle-orm/node-postgres"
 * import { Layer } from "effect"
 * import { DrizzleDatabase } from "@effect-auth/adapter-drizzle"
 *
 * const DatabaseLive = Layer.succeed(DrizzleDatabase, drizzle(pool))
 * ```
 */
export const DrizzleDatabase = Context.GenericTag<DrizzleDatabase>(
  "@effect-auth/DrizzleDatabase"
)
