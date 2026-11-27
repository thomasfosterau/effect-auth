/**
 * Audit logging plugin: logs successful sign-up, sign-in and sign-out, and
 * every write reported with `recordWrite` under its acting principal, user or
 * system. Its taps are isolated, so a logging failure never aborts the
 * operation.
 *
 * @module plugins/audit
 */
import * as Effect from "effect/Effect";
import type { AuthResult } from "../email/EmailPassword.ts";
import * as Entity from "../Entity.ts";
import * as Hooks from "../Hooks.ts";

const impersonationFields = (event: Hooks.ImpersonationEvent) => ({
  impersonatorId: event.impersonatorId,
  userId: event.userId,
  sessionId: event.sessionId,
  expiresAt: event.expiresAt.toISOString(),
});

/**
 * Logs `afterSignUp`, `afterSignIn` and `afterSignOut`, and `afterWrite` as
 * `auth.write` with the acting principal (`User::"<id>"` or
 * `System::"<name>"`), the action and the resource. A send run off the response
 * path that failed (`afterDeliveryFailure`) is logged as `auth.deliveryFailure`
 * at warning level, with its purpose and the sender's error. An administrator
 * starting or stopping an impersonation is logged as `auth.impersonationStart`
 * / `auth.impersonationStop`, with both user ids and the session's stored id.
 *
 * `Layer<Hooks, never, Hooks>` - no dependencies (uses Effect's built-in
 * logger). Configured with `isolateTaps: true` so audit failures never break
 * authentication.
 */
export const AuditPlugin = Hooks.makePlugin(
  {
    afterSignUp: Hooks.Hooks.tap((result: AuthResult) =>
      Effect.logInfo("auth.signUp", {
        userId: result.user.id,
        hasSession: result.session !== undefined,
      }),
    ),
    afterSignIn: Hooks.Hooks.tap((result: AuthResult) =>
      Effect.logInfo("auth.signIn", { userId: result.user.id }),
    ),
    afterSignOut: Hooks.Hooks.tap((ref: Hooks.SessionRef) =>
      Effect.logInfo("auth.signOut", { sessionId: ref.sessionId }),
    ),
    afterWrite: Hooks.Hooks.tap((event: Hooks.WriteEvent) =>
      Effect.logInfo("auth.write", {
        principal: Entity.formatRef(event.principal),
        system: event.principal.type === Entity.systemType,
        action: event.action,
        resource: Entity.formatRef(event.resource),
      }),
    ),
    afterDeliveryFailure: Hooks.Hooks.tap((failure: Hooks.DeliveryFailure) =>
      Effect.logWarning("auth.deliveryFailure", {
        purpose: failure.purpose,
        cause: failure.cause,
      }),
    ),
    afterImpersonationStart: Hooks.Hooks.tap((event: Hooks.ImpersonationEvent) =>
      Effect.logInfo("auth.impersonationStart", impersonationFields(event)),
    ),
    afterImpersonationStop: Hooks.Hooks.tap((event: Hooks.ImpersonationEvent) =>
      Effect.logInfo("auth.impersonationStop", impersonationFields(event)),
    ),
  },
  { isolateTaps: true },
);
