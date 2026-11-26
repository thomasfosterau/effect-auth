/**
 * Guards for administrator impersonation (ADR-0014). An impersonation session
 * (one `AdminService.impersonateUser` issued, carrying
 * `attributes.impersonatedBy`) may act as the user but may not change the
 * account's credentials or identity: its password, email, multi-factor
 * enrolment, passkeys, API keys, linked accounts, login handles, or the
 * account's existence. Without the guard, impersonation would turn into a
 * permanent takeover of the account.
 *
 * The services that make those changes call {@link guardCurrentSession}
 * first, so the guard holds wherever the session context is provided (the
 * HTTP tier, `SessionContext.authenticatedLayer` at an app's own edge). The
 * HTTP tier also checks the session it resolved with
 * {@link assertNotImpersonating}. Wrap an application's own sensitive
 * operations with the same helpers.
 *
 * @since 0.1.0
 * @module impersonation
 */
import { Effect } from "effect";
import * as Option from "effect/Option";
import * as Errors from "./Errors.ts";
import { CurrentSession, MaybeCurrentSession } from "./SessionContext.ts";
import { isImpersonationSession } from "./Types.ts";
import type * as Types from "./Types.ts";

export { isImpersonationSession };

/**
 * Fail with `ImpersonationForbiddenError` when `session` is an impersonation.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Exit } from "effect"
 * import { Impersonation } from "@thomasfosterau/effect-auth"
 *
 * const now = new Date()
 * const session = {
 *   id: "digest",
 *   userId: "u-1",
 *   expiresAt: now,
 *   createdAt: now,
 *   lastActivityAt: now,
 *   attributes: { impersonatedBy: "admin-1" },
 * }
 * const exit = await Effect.runPromiseExit(Impersonation.assertNotImpersonating(session))
 * assert.equal(Exit.isFailure(exit), true)
 * ```
 *
 * @since 0.1.0
 */
export const assertNotImpersonating = (
  session: Types.Session,
): Effect.Effect<void, Errors.ImpersonationForbiddenError> =>
  isImpersonationSession(session)
    ? Effect.fail(
        new Errors.ImpersonationForbiddenError({
          message: "This change is not allowed while impersonating a user",
        }),
      )
    : Effect.void;

/**
 * {@link assertNotImpersonating} on the session in context: `CurrentSession`,
 * else the one in `MaybeCurrentSession`. With neither (a background job, a
 * signed-out caller, a server-side call outside any request) there is no
 * impersonation, and it succeeds.
 *
 * @since 0.1.0
 */
export const guardCurrentSession: Effect.Effect<void, Errors.ImpersonationForbiddenError> =
  Effect.flatMap(
    Effect.all([Effect.serviceOption(CurrentSession), Effect.serviceOption(MaybeCurrentSession)], {
      concurrency: 1,
    }),
    ([current, maybe]) =>
      Option.match(
        Option.orElse(current, () =>
          Option.map(Option.flatten(maybe), (resolved) => resolved.session),
        ),
        { onNone: () => Effect.void, onSome: assertNotImpersonating },
      ),
  );
