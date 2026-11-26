/**
 * A role column's `CHECK`, derived from the application's `Ladder`, so the rung
 * set is declared once. Growing the ladder changes the DDL, so a
 * migration-drift gate catches the missing migration.
 *
 * @example
 * ```ts
 * import { check, pgTable, text } from "drizzle-orm/pg-core"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle"
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"])
 *
 * export const users = pgTable(
 *   "users",
 *   { id: text("id").primaryKey(), role: text("role").notNull().default("user") },
 *   (table) => [check("users_role_valid", Drizzle.ladderCheck(table.role, Roles))],
 * )
 * ```
 *
 * @module ladder-check
 */
import { sql, type SQL, type SQLWrapper } from "drizzle-orm";
import type * as Auth from "@thomasfosterau/effect-auth";

/**
 * `<column> IN (<every rung>)` — the body of a `CHECK` constraint, with the
 * rungs inlined as quoted literals (`inlineParams`), since DDL has no bind
 * parameters: the migration carries the literal `IN` list whichever tool
 * renders it.
 *
 * @since 0.1.0
 * @category schema
 */
export const ladderCheck = <Rung extends string>(
  column: SQLWrapper,
  ladder: Auth.Ladder.Ladder<Rung>,
): SQL =>
  sql`${column} IN (${sql.join(
    ladder.rungs.map((rung) => sql`${rung}`),
    sql`, `,
  )})`.inlineParams();
