/**
 * Audit logging plugin (tap hooks).
 *
 * Observes successful sign-up, sign-in and sign-out, and the writes the
 * application reports with `recordWrite`, and emits structured logs. A write
 * is logged with its acting principal, user or system, so unattended writes
 * by a background job are audited alongside a person's.
 * Demonstrates tap-only hooks authored with {@link Hooks.tap}, and the
 * `isolateTaps` option: a logging failure is caught and logged rather than
 * aborting the auth operation.
 *
 * @module plugins/audit
 */
import { Effect } from "effect";
import type { AuthResult } from "../email/EmailPassword.ts";
import * as Entity from "../Entity.ts";
import {
  type DeliveryFailure,
  Hooks,
  makePlugin,
  type SessionRef,
  type WriteEvent,
} from "../Hooks.ts";

/**
 * Logs `afterSignUp`, `afterSignIn` and `afterSignOut`, and `afterWrite` as
 * `auth.write` with the acting principal (`User::"<id>"` or
 * `System::"<name>"`), the action and the resource. A send run off the response
 * path that failed (`afterDeliveryFailure`) is logged as `auth.deliveryFailure`
 * at warning level, with its purpose and the sender's error.
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
    afterWrite: Hooks.tap((event: WriteEvent) =>
      Effect.logInfo("auth.write", {
        principal: Entity.formatRef(event.principal),
        system: event.principal.type === Entity.systemType,
        action: event.action,
        resource: Entity.formatRef(event.resource),
      }),
    ),
    afterDeliveryFailure: Hooks.tap((failure: DeliveryFailure) =>
      Effect.logWarning("auth.deliveryFailure", {
        purpose: failure.purpose,
        cause: failure.cause,
      }),
    ),
  },
  { isolateTaps: true },
);
