import { Context, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type * as Types from "./Types.js";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";

/**
 * Session store interface for managing session persistence
 * Users should implement this interface with their preferred storage backend
 * (e.g., Redis, PostgreSQL, MongoDB, etc.)
 */
export interface SessionStore {
  /**
   * Create a new session
   */
  readonly create: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Get a session by ID
   */
  readonly get: (sessionId: string) => Effect.Effect<Types.Session, Errors.SessionNotFoundError>;

  /**
   * Update a session
   */
  readonly update: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Delete a session
   */
  readonly delete: (sessionId: string) => Effect.Effect<void, Errors.AuthError>;

  /**
   * Delete all sessions for a user
   */
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Tag for SessionStore service
 */
export class SessionStoreTag extends Context.Tag("@effect-auth/SessionStore")<
  SessionStoreTag,
  SessionStore
>() {}

// Public ergonomic alias
export const SessionStore = SessionStoreTag;

/**
 * User store interface for managing user persistence
 * Users should implement this interface with their preferred storage backend
 */
export interface UserStore {
  /**
   * Get a user by ID
   */
  readonly get: (userId: string) => Effect.Effect<Types.User, Errors.UserNotFoundError>;

  /**
   * Get user credentials (hashed password)
   */
  readonly getCredentials: (userId: string) => Effect.Effect<string, Errors.UserNotFoundError>;
}

/**
 * Tag for UserStore service
 */
export class UserStoreTag extends Context.Tag("@effect-auth/UserStore")<
  UserStoreTag,
  UserStore
>() {}

// Public ergonomic alias
export const UserStore = UserStoreTag;

/**
 * Session manager service
 */
export interface SessionManager {
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
    Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError | HookError,
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
}

/**
 * Tag for SessionManager service
 */
export class SessionManagerTag extends Context.Tag("@effect-auth/SessionManager")<
  SessionManagerTag,
  SessionManager
>() {}

// Public ergonomic alias
export const SessionManager = SessionManagerTag;

/**
 * Generate a secure random session ID
 * Following Copenhagen guidelines for session tokens
 */
const generateSessionId = (): string => {
  // Generate 20 random bytes (160 bits) for session ID
  // This provides sufficient entropy to prevent brute force attacks
  return crypto.randomBytes(20).toString("hex");
};

/**
 * Create a SessionManager implementation
 */
export const makeSessionManager = (
  config: Types.SessionConfig,
): Effect.Effect<SessionManager, never, SessionStoreTag | UserStoreTag> =>
  Effect.gen(function* () {
    const sessionStore = yield* SessionStoreTag;
    const userStore = yield* UserStoreTag;

    return {
      createSession: (rawUserId, rawAttributes = {}) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const args = yield* hooks.beforeCreateSession({
            userId: rawUserId,
            attributes: rawAttributes,
          });

          const sessionId = generateSessionId();
          const now = new Date();
          const expiresAt = new Date(now.getTime() + config.sessionExpiresIn.activePeriod);

          const session: Types.Session = {
            id: sessionId,
            userId: args.userId,
            expiresAt,
            createdAt: now,
            lastActivityAt: now,
            attributes: args.attributes ?? {},
          };

          const created = yield* sessionStore.create(session);
          return yield* hooks.afterCreateSession(created);
        }),

      validateSession: (rawSessionId) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const { sessionId } = yield* hooks.beforeValidateSession({ sessionId: rawSessionId });

          const session = yield* sessionStore.get(sessionId);

          // Check if session is expired
          const now = new Date();
          if (session.expiresAt.getTime() < now.getTime()) {
            // Delete expired session (ignore errors)
            yield* Effect.ignore(sessionStore.delete(sessionId));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session has expired",
                sessionId,
              }),
            );
          }

          // Check if session has been idle for too long
          const timeSinceLastActivity = now.getTime() - session.lastActivityAt.getTime();
          if (timeSinceLastActivity > config.sessionExpiresIn.idlePeriod) {
            // Session has been idle for too long
            yield* Effect.ignore(sessionStore.delete(sessionId));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session expired due to inactivity",
                sessionId,
              }),
            );
          }

          // Check if session has exceeded its absolute maximum lifetime
          const sessionLifetime = now.getTime() - session.createdAt.getTime();
          if (sessionLifetime > config.sessionExpiresIn.activePeriod) {
            // Session has exceeded maximum lifetime
            yield* Effect.ignore(sessionStore.delete(sessionId));
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session exceeded maximum lifetime",
                sessionId,
              }),
            );
          }

          // Update session activity and potentially extend expiration
          const newExpiresAt = new Date(
            Math.min(
              now.getTime() + config.sessionExpiresIn.idlePeriod, // Extend by idle period
              session.createdAt.getTime() + config.sessionExpiresIn.activePeriod, // But not beyond max lifetime
            ),
          );

          const updatedSession: Types.Session = {
            ...session,
            lastActivityAt: now,
            expiresAt: newExpiresAt,
          };

          // Update session (ignore errors as it's not critical)
          yield* Effect.ignore(sessionStore.update(updatedSession));

          // Get user
          const user = yield* userStore.get(session.userId);

          return yield* hooks.afterValidateSession({
            session: updatedSession,
            user,
          });
        }),

      invalidateSession: (rawSessionId) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const { sessionId } = yield* hooks.beforeSignOut({ sessionId: rawSessionId });
          yield* sessionStore.delete(sessionId);
          yield* hooks.afterSignOut({ sessionId });
        }),

      invalidateUserSessions: (userId) => sessionStore.deleteByUserId(userId),
    };
  });

export const SessionManagerLayer = (config: Types.SessionConfig) =>
  Layer.effect(SessionManagerTag, makeSessionManager(config));
