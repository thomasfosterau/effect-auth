/**
 * Whether a user may still authenticate: the ban and SCIM-deactivation reads,
 * in a module that imports only `Errors.ts` of the core, so `SessionService`
 * and the credential services gate on them without a cycle through `Admin.ts`
 * or `Scim.ts`, which re-export them.
 *
 * @module user-standing
 */
import * as Clock from "effect/Clock";
import * as Effect from "effect/Effect";
import * as P from "effect/Predicate";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";

/** `User.attributes` key set to `true` while a user is SCIM-deactivated. */
export const SCIM_DEACTIVATED_ATTRIBUTE = "scimDeactivated";

/**
 * The `User.attributes` keys that decide a user's standing: the ban flag and
 * its expiry, and the SCIM deactivation flag. The session cookie cache never
 * snapshots a user holding one, so standing is always read from the store.
 */
export const STANDING_ATTRIBUTES: ReadonlyArray<string> = [
  "banned",
  "banExpires",
  SCIM_DEACTIVATED_ATTRIBUTE,
];

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

/**
 * Succeed when `user` is in good standing; otherwise fail with
 * `UserBannedError`, worded for a deactivation or a ban. `SessionService`
 * runs it before it creates or answers a session.
 */
export const requireGoodStanding = (
  user: Types.User,
): Effect.Effect<void, Errors.UserBannedError> =>
  isScimDeactivated(user)
    ? Effect.fail(new Errors.UserBannedError({ message: "Your account has been deactivated" }))
    : Effect.flatMap(isBanned(user), (banned) =>
        banned
          ? Effect.fail(new Errors.UserBannedError({ message: "Your account has been suspended" }))
          : Effect.void,
      );
