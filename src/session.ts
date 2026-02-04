import { Effect, Context } from "effect"
import * as crypto from "node:crypto"
import type * as Types from "./types.js"
import * as Errors from "./errors.js"

/**
 * Session store interface for managing session persistence
 * Users should implement this interface with their preferred storage backend
 * (e.g., Redis, PostgreSQL, MongoDB, etc.)
 */
export interface SessionStore {
  /**
   * Create a new session
   */
  readonly create: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>
  
  /**
   * Get a session by ID
   */
  readonly get: (sessionId: string) => Effect.Effect<Types.Session, Errors.SessionNotFoundError>
  
  /**
   * Update a session
   */
  readonly update: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>
  
  /**
   * Delete a session
   */
  readonly delete: (sessionId: string) => Effect.Effect<void, Errors.AuthError>
  
  /**
   * Delete all sessions for a user
   */
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>
}

/**
 * Tag for SessionStore service
 */
export const SessionStore = Context.GenericTag<SessionStore>("@effect-auth/SessionStore")

/**
 * User store interface for managing user persistence
 * Users should implement this interface with their preferred storage backend
 */
export interface UserStore {
  /**
   * Get a user by ID
   */
  readonly get: (userId: string) => Effect.Effect<Types.User, Errors.UserNotFoundError>
  
  /**
   * Get user credentials (hashed password)
   */
  readonly getCredentials: (userId: string) => Effect.Effect<string, Errors.UserNotFoundError>
}

/**
 * Tag for UserStore service
 */
export const UserStore = Context.GenericTag<UserStore>("@effect-auth/UserStore")

/**
 * Session manager service
 */
export interface SessionManager {
  /**
   * Create a new session for a user
   */
  readonly createSession: (
    userId: string,
    attributes?: Record<string, unknown>
  ) => Effect.Effect<Types.Session, Errors.AuthError>
  
  /**
   * Validate a session and return it with the user
   */
  readonly validateSession: (
    sessionId: string
  ) => Effect.Effect<
    Types.SessionWithUser,
    Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError
  >
  
  /**
   * Invalidate a session
   */
  readonly invalidateSession: (sessionId: string) => Effect.Effect<void, Errors.AuthError>
  
  /**
   * Invalidate all sessions for a user
   */
  readonly invalidateUserSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>
}

/**
 * Tag for SessionManager service
 */
export const SessionManager = Context.GenericTag<SessionManager>("@effect-auth/SessionManager")

/**
 * Generate a secure random session ID
 * Following Copenhagen guidelines for session tokens
 */
const generateSessionId = (): string => {
  // Generate 20 random bytes (160 bits) for session ID
  // This provides sufficient entropy to prevent brute force attacks
  return crypto.randomBytes(20).toString("hex")
}

/**
 * Create a SessionManager implementation
 */
export const makeSessionManager = (config: Types.SessionConfig): Effect.Effect<
  SessionManager,
  never,
  SessionStore | UserStore
> =>
  Effect.gen(function* () {
    const sessionStore = yield* SessionStore
    const userStore = yield* UserStore

    return {
      createSession: (userId, attributes = {}) =>
        Effect.gen(function* () {
          const sessionId = generateSessionId()
          const now = Date.now()
          const expiresAt = new Date(now + config.sessionExpiresIn.activePeriod)

          const session: Types.Session = {
            id: sessionId,
            userId,
            expiresAt,
            attributes
          }

          return yield* sessionStore.create(session)
        }),

      validateSession: (sessionId) =>
        Effect.gen(function* () {
          const session = yield* sessionStore.get(sessionId)

          // Check if session is expired
          const now = Date.now()
          if (session.expiresAt.getTime() < now) {
            // Delete expired session (ignore errors)
            yield* Effect.ignore(sessionStore.delete(sessionId))
            return yield* Effect.fail(
              new Errors.SessionExpiredError({
                message: "Session has expired",
                sessionId
              })
            )
          }

          // Check if session should be extended (idle timeout)
          const idleExpiry = now + config.sessionExpiresIn.idlePeriod
          const activeExpiry = now + config.sessionExpiresIn.activePeriod
          
          // Extend session if it's past the idle period
          const sessionAge = now - (session.expiresAt.getTime() - config.sessionExpiresIn.activePeriod)
          if (sessionAge > config.sessionExpiresIn.idlePeriod) {
            const updatedSession = {
              ...session,
              expiresAt: new Date(Math.min(idleExpiry, activeExpiry))
            }
            // Update session (ignore errors as it's not critical)
            yield* Effect.ignore(sessionStore.update(updatedSession))
          }

          // Get user
          const user = yield* userStore.get(session.userId)

          return {
            session,
            user
          }
        }),

      invalidateSession: (sessionId) => sessionStore.delete(sessionId),

      invalidateUserSessions: (userId) => sessionStore.deleteByUserId(userId)
    }
  })
