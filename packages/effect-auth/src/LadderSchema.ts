/**
 * The ladder's rungs as a `Schema` — so the allowed role values are declared
 * once (`Ladder.make([...])`) and drive the type, the runtime check, and (via
 * `@thomasfosterau/effect-auth-drizzle`'s `ladderCheck`) the database `CHECK`.
 *
 * Kept out of `Ladder.ts`, which is import-free for browser bundles.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Schema } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"])
 * const AppUser = Schema.Struct({ id: Schema.String, role: Auth.LadderSchema.rung(Roles) })
 *
 * // A rung on the ladder decodes.
 * assert.equal(Schema.decodeUnknownSync(AppUser)({ id: "u1", role: "moderator" }).role, "moderator")
 * // A value that is not a rung is refused.
 * assert.throws(() => Schema.decodeUnknownSync(AppUser)({ id: "u1", role: "superadmin" }))
 * ```
 *
 * @module ladder-schema
 */
import { Schema } from "effect";
import type * as Ladder from "./Ladder.ts";

/**
 * A `Schema` accepting exactly the rungs of `ladder`.
 *
 * @since 1.0.0
 * @category schemas
 */
export const rung = <Rung extends string>(ladder: Ladder.Ladder<Rung>): Schema.Codec<Rung> =>
  Schema.Literals(ladder.rungs);
