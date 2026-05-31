/**
 * Audit logging plugin (tap hooks).
 *
 * Observes successful sign-up, sign-in and sign-out and emits structured logs.
 * Demonstrates tap-only hooks authored with {@link Hooks.tap}, and the
 * `isolateTaps` option: a logging failure is caught and logged rather than
 * aborting the auth operation.
 *
 * @module plugins/audit
 */
import { Effect } from "effect";
import type { AuthResult } from "../EmailPassword.js";
import { Hooks, makePlugin, type SessionRef } from "../Hooks.js";

/**
 * Logs `afterSignUp`, `afterSignIn` and `afterSignOut`.
 *
 * `Layer<Hooks, never, Hooks>` - no dependencies (uses Effect's built-in
 * logger). Configured with `isolateTaps: true` so audit failures never break
 * authentication.
 */
export const AuditPlugin = makePlugin(
  {
    afterSignUp: Hooks.tap((result: AuthResult) =>
      Effect.logInfo("auth.signUp", {
        userId: result.user.id,
        hasSession: result.session !== undefined,
      }),
    ),
    afterSignIn: Hooks.tap((result: AuthResult) =>
      Effect.logInfo("auth.signIn", { userId: result.user.id }),
    ),
    afterSignOut: Hooks.tap((ref: SessionRef) =>
      Effect.logInfo("auth.signOut", { sessionId: ref.sessionId }),
    ),
  },
  { isolateTaps: true },
);
