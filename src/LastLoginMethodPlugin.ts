/**
 * Last-login-method plugin (tap hooks).
 *
 * Records the sign-in method (the {@link AuthResult.method} discriminator —
 * `"email-password"`, `"username"`, ...) into the issued session's
 * `attributes.method` on `afterSignIn`/`afterSignUp`, so apps can answer
 * "how did this user last authenticate?" server-side.
 *
 * The companion browser hint — a non-httpOnly `${cookie}_last_method` cookie
 * login pages read to highlight the user's previous method — is set by the
 * HTTP layer: enable it with `cookie.lastLoginMethod` on
 * `makeAuthWebHandler` (it covers every sign-in endpoint, including the
 * flows that don't fire these hooks).
 *
 * @module plugins/last-login-method
 */
import { Effect } from "effect";
import type { AuthResult } from "./EmailPassword.ts";
import { SessionManager } from "./Session.ts";
import { Hooks, makePlugin } from "./Hooks.ts";

/**
 * Build the plugin. `Layer<Hooks, never, Hooks | SessionManagerTag>` —
 * provide your `SessionManager` layer. Tap failures are isolated: recording
 * the method never breaks the sign-in itself.
 */
export const makeLastLoginMethodPlugin = () =>
  makePlugin(
    Effect.gen(function* () {
      const sessionManager = yield* SessionManager;
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
