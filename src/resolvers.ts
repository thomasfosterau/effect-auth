import { Effect, RequestResolver } from "effect"
import * as Requests from "./requests.js"
import * as Errors from "./errors.js"
import { SessionManager } from "./session.js"
import { PasswordHasherContext } from "./password.js"
import { UserStore } from "./session.js"

/**
 * Create a resolver for session creation
 */
export const makeCreateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.CreateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManager
      return yield* sessionManager.createSession(request.userId, request.attributes)
    })
)

/**
 * Create a resolver for session validation
 */
export const makeValidateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.ValidateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManager
      return yield* sessionManager.validateSession(request.sessionId)
    })
)

/**
 * Create a resolver for session invalidation
 */
export const makeInvalidateSessionResolver = RequestResolver.fromEffect(
  (request: Requests.InvalidateSessionRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManager
      return yield* sessionManager.invalidateSession(request.sessionId)
    })
)

/**
 * Create a resolver for invalidating all user sessions
 */
export const makeInvalidateUserSessionsResolver = RequestResolver.fromEffect(
  (request: Requests.InvalidateUserSessionsRequest) =>
    Effect.gen(function* () {
      const sessionManager = yield* SessionManager
      return yield* sessionManager.invalidateUserSessions(request.userId)
    })
)

/**
 * Create a resolver for credential verification
 */
export const makeVerifyCredentialsResolver = RequestResolver.fromEffect(
  (request: Requests.VerifyCredentialsRequest) =>
    Effect.gen(function* () {
      const userStore = yield* UserStore
      const passwordHasher = yield* PasswordHasherContext

      // Get user and their hashed password
      const user = yield* userStore.get(request.userId)
      const hashedPassword = yield* userStore.getCredentials(request.userId)

      // Verify password
      const isValid = yield* passwordHasher.verify(request.password, hashedPassword)

      if (!isValid) {
        return yield* Effect.fail(
          new Errors.InvalidCredentialsError({
            message: "Invalid credentials"
          })
        )
      }

      return user
    })
)

/**
 * Create a resolver for password hashing
 */
export const makeHashPasswordResolver = RequestResolver.fromEffect(
  (request: Requests.HashPasswordRequest) =>
    Effect.gen(function* () {
      const passwordHasher = yield* PasswordHasherContext
      return yield* passwordHasher.hash(request.password)
    })
)

/**
 * Create a resolver for password verification
 */
export const makeVerifyPasswordResolver = RequestResolver.fromEffect(
  (request: Requests.VerifyPasswordRequest) =>
    Effect.gen(function* () {
      const passwordHasher = yield* PasswordHasherContext
      return yield* passwordHasher.verify(request.password, request.hash)
    })
)
