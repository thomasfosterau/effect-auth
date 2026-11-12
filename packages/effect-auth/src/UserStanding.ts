/**
 * Whether a user may still authenticate: the ban and SCIM-deactivation reads,
 * in a module that imports nothing else of the core, so a credential service
 * (`ApiKeyService`) can gate on them without a cycle through `Admin.ts` or
 * `Scim.ts`, which re-export them.
 *
 * @module user-standing
 */
import { Clock, Effect } from "effect";
import * as P from "effect/Predicate";
import type * as Types from "./Types.ts";

/** `User.attributes` key set to `true` while a user is SCIM-deactivated. */
export const SCIM_DEACTIVATED_ATTRIBUTE = "scimDeactivated";

/**
 * Whether a user is currently deactivated by SCIM — the inverse of the SCIM
 * `active` attribute.
 *
 * Deactivation is deliberately a plain attribute rather than a column: it is
 * readable by any store, survives a round trip through JSON, and lets apps
 * gate on it without importing the SCIM module.
 */
export const isScimDeactivated = (user: Types.User): boolean =>
  user.attributes[SCIM_DEACTIVATED_ATTRIBUTE] === true;

/**
 * Whether a user is currently banned. A ban with `attributes.banExpires` in
 * the past has lapsed and no longer counts.
 *
 * An Effect because "the past" is read from the `Clock`, so `TestClock`
 * decides whether a ban has lapsed.
 */
export const isBanned = (user: Types.User): Effect.Effect<boolean> => {
  if (user.attributes["banned"] !== true) {
    return Effect.succeed(false);
  }
  const banExpires = user.attributes["banExpires"];
  if (!P.isNumber(banExpires)) {
    return Effect.succeed(true);
  }
  return Effect.map(Clock.currentTimeMillis, (now) => banExpires > now);
};

/** Whether a user is in good standing: neither currently banned nor SCIM-deactivated. */
export const isInGoodStanding = (user: Types.User): Effect.Effect<boolean> =>
  isScimDeactivated(user) ? Effect.succeed(false) : Effect.map(isBanned(user), (b) => !b);
