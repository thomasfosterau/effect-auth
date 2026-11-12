import { Clock, Context, DateTime, Effect, Layer } from "effect";
import * as P from "effect/Predicate";
import { Hex } from "effect/encoding";
import { SecureRandom } from "effect/crypto";
import type * as Types from "./Types.ts";
import * as Errors from "./Errors.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { hashToken } from "./TokenHash.ts";
import * as Obs from "./Observability.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";

/**
 * Create a SessionService implementation
 */
export const make = (
  config: Types.SessionConfig,
): Effect.Effect<
  typeof SessionService.Service,
  never,
  SessionStore | UserStore | Hooks | SecureRandom.SecureRandom
> =>
  Effect.gen(function* () {
    const sessionStore = yield* SessionStore;
    const userStore = yield* UserStore;
    const hooks = yield* Hooks;
    const crypto = yield* SecureRandom.SecureRandom;

    const generateSessionId = (): Effect.Effect<string> =>
      crypto.randomBytes(20).pipe(Effect.map(Hex.encode));

    return {
      createSession: Effect.fn("SessionService.createSession")(
        (rawUserId: string, rawAttributes: Types.Attributes = {}) =>
          Effect.gen(function* () {
            const args = yield* hooks.beforeCreateSession({
              userId: rawUserId,
              attributes: rawAttributes,
            });

            const rawToken = yield* generateSessionId();
            const nowUtc = yield* DateTime.now;
            const now = DateTime.toDateUtc(nowUtc);
            const expiresAt = DateTime.toDateUtc(
              DateTime.mapEpochMillis(
                nowUtc,
                (millis) => millis + config.sessionExpiresIn.activePeriod,
              ),
            );

            const session: Types.Session = {
              id: hashToken(rawToken), // the store, and every reader, sees only the digest
              userId: args.userId,
              expiresAt,
              createdAt: now,
              lastActivityAt: now,
              attributes: args.attributes ?? {},
            };

            yield* sessionStore.create(session);
            // The raw token travels beside the record, never as its id (#581).
            const created = yield* hooks.afterCreateSession(session);
            return { session: created, token: rawToken } satisfies Types.IssuedSession;
          }).pipe(
            Effect.withSpan(Obs.spanNames.createSession),
            Effect.tap(() => Obs.recordSessionCreated()),
          ),
      ),

      validateSession: Effect.fn("SessionService.validateSession")((rawSessionId: string) =>
        Effect.gen(function* () {
          // Look up the session by its token hash; never expose the raw token
          // to the store or to a hook (#669). The hook observes or denies:
          // what it returns is not read back, so it cannot redirect the lookup.
          const tokenHash = hashToken(rawSessionId);
          yield* hooks.beforeValidateSession({ sessionId: tokenHash });
          const session = yield* sessionStore.get(tokenHash);
          if (session === null) {
            return yield* new Errors.SessionNotFoundError({
              message: "Session not found",
              sessionId: tokenHash,
            });
          }

          // Check if session is expired
          const nowUtc = yield* DateTime.now;
          const now = DateTime.toDateUtc(nowUtc);
          if (session.expiresAt.getTime() < now.getTime()) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* new Errors.SessionExpiredError({
              message: "Session has expired",
              sessionId: tokenHash,
            });
          }

          // Check if session has been idle for too long
          const timeSinceLastActivity = now.getTime() - session.lastActivityAt.getTime();
          if (timeSinceLastActivity > config.sessionExpiresIn.idlePeriod) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* new Errors.SessionExpiredError({
              message: "Session expired due to inactivity",
              sessionId: tokenHash,
            });
          }

          // Check if session has exceeded its absolute maximum lifetime
          const sessionLifetime = now.getTime() - session.createdAt.getTime();
          if (sessionLifetime > config.sessionExpiresIn.activePeriod) {
            yield* Effect.ignore(sessionStore.delete(tokenHash));
            return yield* new Errors.SessionExpiredError({
              message: "Session exceeded maximum lifetime",
              sessionId: tokenHash,
            });
          }

          // Extend expiration (capped at absolute max lifetime).
          const newExpiresAt = DateTime.toDateUtc(
            DateTime.mapEpochMillis(nowUtc, (millis) =>
              Math.min(
                millis + config.sessionExpiresIn.idlePeriod,
                session.createdAt.getTime() + config.sessionExpiresIn.activePeriod,
              ),
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

          // The session answers under its stored id: the caller already holds
          // the token it presented (#581).
          return yield* hooks.afterValidateSession({ session: updatedSession, user });
        }).pipe(
          Effect.withSpan(Obs.spanNames.validateSession),
          Effect.tap(() => Obs.recordSessionValidated("success")),
          Effect.tapError((e) =>
            P.isTagged(e, "SessionNotFoundError")
              ? Obs.recordSessionValidated("not_found")
              : P.isTagged(e, "SessionExpiredError")
                ? Obs.recordSessionValidated("expired")
                : Effect.void,
          ),
        ),
      ),

      invalidateSession: Effect.fn("SessionService.invalidateSession")((rawSessionId: string) =>
        Effect.gen(function* () {
          // Every hook gets the stored id, so none can record the credential
          // (#669); `beforeSignOut` observes or denies, and is not read back.
          const storedId = hashToken(rawSessionId);
          yield* hooks.beforeSignOut({ sessionId: storedId });
          yield* sessionStore.delete(storedId);
          yield* hooks.afterSignOut({ sessionId: storedId });
        }).pipe(
          Effect.withSpan(Obs.spanNames.signOut),
          Effect.tap(() => Obs.recordSessionInvalidated()),
        ),
      ),

      invalidateUserSessions: Effect.fn("SessionService.invalidateUserSessions")((userId: string) =>
        sessionStore.deleteByUserId(userId),
      ),

      listSessions: Effect.fn("SessionService.listSessions")(function* (userId: string) {
        const sessions = yield* sessionStore.listByUserId(userId);
        const now = yield* Clock.currentTimeMillis;
        return sessions.filter((session) => session.expiresAt.getTime() >= now);
      }),

      revokeSessionById: Effect.fn("SessionService.revokeSessionById")(function* (
        userId: string,
        storedSessionId: string,
      ) {
        const sessions = yield* sessionStore.listByUserId(userId);
        const held = sessions.some((session) => session.id === storedSessionId);
        if (held) yield* sessionStore.delete(storedSessionId);
        return held;
      }),

      revokeOtherSessions: Effect.fn("SessionService.revokeOtherSessions")(function* (
        userId: string,
        keepSessionId: string,
      ) {
        const sessions = yield* sessionStore.listByUserId(userId);
        yield* Effect.forEach(
          sessions.filter((session) => session.id !== keepSessionId),
          (session) => sessionStore.delete(session.id),
          { concurrency: 1, discard: true },
        );
      }),

      setSessionAttributes: Effect.fn("SessionService.setSessionAttributes")(function* (
        storedSessionId: string,
        attributes: Types.Attributes,
      ) {
        const session = yield* sessionStore.get(storedSessionId);
        if (session === null) {
          return yield* new Errors.SessionNotFoundError({
            message: "Session not found",
            sessionId: storedSessionId,
          });
        }
        const updated: Types.Session = {
          ...session,
          attributes: { ...session.attributes, ...attributes },
        };
        return yield* sessionStore.update(updated);
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
     * Create a new session for a user. Answers the stored record (its `id`
     * the digest of the token) and the raw `token`, the credential to hand
     * the client in the session cookie (or, in bearer mode, the
     * `set-auth-token` header). The token is never the record's id (#581).
     */
    readonly createSession: (
      userId: string,
      attributes?: Types.Attributes,
    ) => Effect.Effect<Types.IssuedSession, Errors.AuthError | HookError>;

    /**
     * Validate the session a raw token names and return it with the user. The
     * session answers under its stored id (the token's digest), never the
     * token. `beforeValidateSession` observes the stored id, never the token,
     * and can only deny: its return value is not read back (#669).
     */
    readonly validateSession: (
      token: string,
    ) => Effect.Effect<
      Types.SessionWithUser,
      | Errors.SessionNotFoundError
      | Errors.SessionExpiredError
      | Errors.UserNotFoundError
      | HookError
    >;

    /**
     * Invalidate the session a raw token names. The sign-out hooks run and
     * observe the stored id, never the token (#581, #669); `beforeSignOut`
     * can deny the sign-out but not redirect it, since its return value is
     * not read back.
     */
    readonly invalidateSession: (
      token: string,
    ) => Effect.Effect<void, Errors.AuthError | HookError>;

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
     * Revoke one of a user's sessions by its stored id (the hash of its token,
     * as `listSessions` reports it), so a client can revoke a session it can
     * see but whose token it never held. Returns `false`, deleting nothing,
     * when the user holds no session with that id. Like
     * `revokeOtherSessions`, it runs no sign-out hook.
     */
    readonly revokeSessionById: (
      userId: string,
      storedSessionId: string,
    ) => Effect.Effect<boolean, Errors.AuthError>;

    /**
     * Invalidate every session for a user except the one with the given
     * stored id (e.g. keep the current device signed in while revoking all
     * others). Pass `session.id` as `validateSession` or `createSession`
     * answers it, the digest, not the token.
     */
    readonly revokeOtherSessions: (
      userId: string,
      keepSessionId: string,
    ) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Merge `attributes` into the stored attributes of the session with the
     * given stored id (e.g. record the `activeOrganizationId`). Existing keys
     * are overwritten; others are kept. Returns the updated session.
     */
    readonly setSessionAttributes: (
      storedSessionId: string,
      attributes: Types.Attributes,
    ) => Effect.Effect<Types.Session, Errors.SessionNotFoundError | Errors.AuthError>;
  }
>()("@effect-auth/SessionService") {
  static readonly make = make;
  static readonly layer = (config: Types.SessionConfig) =>
    Layer.effect(SessionService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}
