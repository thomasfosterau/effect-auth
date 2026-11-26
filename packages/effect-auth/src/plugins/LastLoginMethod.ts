/**
 * Last-login-method plugin: records the sign-in method in the session's
 * `attributes.method` on `afterSignIn` and `afterSignUp`. The browser hint
 * cookie is the HTTP tier's (`cookie.lastLoginMethod`), which covers every
 * sign-in endpoint.
 *
 * @module plugins/last-login-method
 */
import * as Effect from "effect/Effect";
import type { AuthResult } from "../email/EmailPassword.ts";
import { SessionService } from "../SessionService.ts";
import { Hooks, makePlugin } from "../Hooks.ts";

/**
 * Records the sign-in method into the issued session's `attributes.method` on
 * `afterSignIn` and `afterSignUp`.
 *
 * `Layer<Hooks, never, Hooks | SessionService>` — provide your
 * `SessionService` layer; it is acquired when the layer is built. Configured
 * with `isolateTaps: true`, so recording the method never breaks the sign-in
 * itself.
 */
export const LastLoginMethodPlugin = makePlugin(
  Effect.gen(function* () {
    const sessionManager = yield* SessionService;
    const record = (result: AuthResult) =>
      result.session !== undefined && result.method !== undefined
        ? sessionManager
            .setSessionAttributes(result.session.id, { method: result.method })
            .pipe(Effect.ignore)
        : Effect.void;
    return {
      afterSignIn: Hooks.tap(record),
      afterSignUp: Hooks.tap(record),
    };
  }),
  { isolateTaps: true },
);
