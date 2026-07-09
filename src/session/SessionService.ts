import { Context, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type * as Types from "../Types.ts";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { hashToken } from "../TokenHash.ts";
import * as Obs from "../Observability.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";

const generateSessionId = (): string => crypto.randomBytes(20).toString("hex");

/**
 * Create a SessionService implementation
 */
export const make = (
  config: Types.SessionConfig,
): Effect.Effect<typeof SessionService.Service, never, SessionStore | UserStore> =>
  Effect.gen(function* () {
    const sessionStore = yield* SessionStore;
    const userStore = yield* UserStore;

    return {
      createSession: (rawUserId: string, rawAttributes: Record<string, unknown> = {}) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const args = yield* hooks.beforeCreateSession({
            userId: rawUserId,
            attributes: rawAttributes,
          });

          const rawToken = generateSessionId();
          const now = new Date();
          const expiresAt = new Date(now.getTime() + config.sessionExpiresIn.activePeriod);

          const session: Types.Session = {
            id: hashToken(rawToken), // store only the hash; raw token goes to the cookie
            userId: args.userId,
            expiresAt,
            createdAt: now,
            lastActivityAt: now,
            attributes: args.attributes ?? {},
          };

          yield* sessionStore.create(session);
          // Return the raw token as session.id so the HTTP layer can set it as the cookie value.
          return yield* hooks.afterCreateSession({ ...session, id: rawToken });
        }).pipe(
          Effect.withSpan("effect-auth.create-session"),
          Effect.tap(() => Obs.recordSessionCreated()),
        ),

      validateSession: (rawSessionId) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const { sessionId: rawToken } = yield* hooks.beforeValidateSession({
            sessionId: rawSessionId,
          });

          // Look up the session by its token hash; never expose the raw token to the store.
          const tokenHash = hashToken(rawToken);
          const session = yield* sessionStore.get(tokenHash);
          if (session === null) {
            return yield* new Errors.SessionNotFoundError({
              message: "Session not found",
              sessionId: tokenHash,
            });
          }

          // Check if session is expired
          const now = new Date();
          if (session.expiresAt.getTime() < now.getTime()) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session has expired",
                sessionId: tokenHash,
              }),
            );
          }

          // Check if session has been idle for too long
          const timeSinceLastActivity = now.getTime() - session.lastActivityAt.getTime();
          if (timeSinceLastActivity > config.sessionExpiresIn.idlePeriod) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session expired due to inactivity",
                sessionId: tokenHash,
              }),
            );
          }

          // Check if session has exceeded its absolute maximum lifetime
          const sessionLifetime = now.getTime() - session.createdAt.getTime();
          if (sessionLifetime > config.sessionExpiresIn.activePeriod) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session exceeded maximum lifetime",
                sessionId: tokenHash,
              }),
            );
          }

          // Extend expiration (capped at absolute max lifetime).
          const newExpiresAt = new Date(
            Math.min(
              now.getTime() + config.sessionExpiresIn.idlePeriod,
              session.createdAt.getTime() + config.sessionExpiresIn.activePeriod,
            ),
          );

          const updatedSession: Types.Session = {
            ...session,
            lastActivityAt: now,
            expiresAt: newExpiresAt,
          };

          // Throttle store writes: skip the update when the session was
          // refreshed within the last `updateAge` ms (default: always write).
          const updateAge = config.sessionExpiresIn.updateAge ?? 0;
          const timeSinceUpdate = now.getTime() - session.lastActivityAt.getTime();
          if (timeSinceUpdate >= updateAge) {
            yield* Effect.ignore(sessionStore.update(updatedSession));
          }

          // Get user
          const user = yield* userStore.get(session.userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({
              message: "User not found",
              userId: session.userId,
            });
          }

          // Return the raw token as session.id so the HTTP layer can bind the session
          // cookie and cache correctly — the stored hash stays in the database only.
          return yield* hooks.afterValidateSession({
            session: { ...updatedSession, id: rawToken },
            user,
          });
        }).pipe(
          Effect.withSpan("effect-auth.validate-session"),
          Effect.tap(() => Obs.recordSessionValidated("success")),
          Effect.tapError((e) =>
            "_tag" in e && e._tag === "SessionNotFoundError"
              ? Obs.recordSessionValidated("not_found")
              : "_tag" in e && e._tag === "SessionExpiredError"
                ? Obs.recordSessionValidated("expired")
                : Effect.void,
          ),
        ),

      invalidateSession: (rawSessionId) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const { sessionId: rawToken } = yield* hooks.beforeSignOut({ sessionId: rawSessionId });
          yield* sessionStore.delete(hashToken(rawToken));
          yield* hooks.afterSignOut({ sessionId: rawToken });
        }).pipe(
          Effect.withSpan("effect-auth.sign-out"),
          Effect.tap(() => Obs.recordSessionInvalidated()),
        ),

      invalidateUserSessions: (userId) => sessionStore.deleteByUserId(userId),

      listSessions: (userId) =>
        Effect.gen(function* () {
          const sessions = yield* sessionStore.listByUserId(userId);
          const now = Date.now();
          return sessions.filter((session) => session.expiresAt.getTime() >= now);
        }),

      revokeOtherSessions: (userId, currentSessionId) =>
        Effect.gen(function* () {
          const currentHash = hashToken(currentSessionId);
          const sessions = yield* sessionStore.listByUserId(userId);
          yield* Effect.forEach(
            // session.id values from the store are hashes; compare against hashed current token
            sessions.filter((session) => session.id !== currentHash),
            (session) => sessionStore.delete(session.id),
            { discard: true },
          );
        }),

      setSessionAttributes: (rawSessionId, attributes) =>
        Effect.gen(function* () {
          const tokenHash = hashToken(rawSessionId);
          const session = yield* sessionStore.get(tokenHash);
          if (session === null) {
            return yield* new Errors.SessionNotFoundError({
              message: "Session not found",
              sessionId: tokenHash,
            });
          }
          const updated: Types.Session = {
            ...session,
            attributes: { ...session.attributes, ...attributes },
          };
          const result = yield* sessionStore.update(updated);
          // Return raw token as id, matching the pattern from createSession/validateSession.
          return { ...result, id: rawSessionId };
        }),
    };
  });

/**
 * Tag for SessionService service
 *
 * Session manager service
 */
export class SessionService extends Context.Service<
  SessionService,
  {
    /**
     * Create a new session for a user
     */
    readonly createSession: (
      userId: string,
      attributes?: Record<string, unknown>,
    ) => Effect.Effect<Types.Session, Errors.AuthError | HookError, Hooks>;

    /**
     * Validate a session and return it with the user
     */
    readonly validateSession: (
      sessionId: string,
    ) => Effect.Effect<
      Types.SessionWithUser,
      | Errors.SessionNotFoundError
      | Errors.SessionExpiredError
      | Errors.UserNotFoundError
      | HookError,
      Hooks
    >;

    /**
     * Invalidate a session
     */
    readonly invalidateSession: (
      sessionId: string,
    ) => Effect.Effect<void, Errors.AuthError | HookError, Hooks>;

    /**
     * Invalidate all sessions for a user
     */
    readonly invalidateUserSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * List a user's sessions that have not yet expired.
     */
    readonly listSessions: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Types.Session>, Errors.AuthError>;

    /**
     * Invalidate every session for a user except the given one (e.g. keep the
     * current device signed in while revoking all others).
     */
    readonly revokeOtherSessions: (
      userId: string,
      currentSessionId: string,
    ) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Merge `attributes` into a session's stored attributes (e.g. record the
     * `activeOrganizationId`). Existing keys are overwritten; others are kept.
     * Returns the updated session.
     */
    readonly setSessionAttributes: (
      sessionId: string,
      attributes: Record<string, unknown>,
    ) => Effect.Effect<Types.Session, Errors.SessionNotFoundError | Errors.AuthError>;
  }
>()("@effect-auth/SessionService") {
  static readonly make = make;
  static readonly layer = (config: Types.SessionConfig) =>
    Layer.effect(SessionService, make(config));
}
