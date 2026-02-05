import { Data } from "effect"

/**
 * Base authentication error
 */
export class AuthError extends Data.TaggedError("AuthError")<{
  readonly message: string
}> {}

/**
 * Invalid credentials error
 */
export class InvalidCredentialsError extends Data.TaggedError("InvalidCredentialsError")<{
  readonly message: string
}> {}

/**
 * Session not found error
 */
export class SessionNotFoundError extends Data.TaggedError("SessionNotFoundError")<{
  readonly message: string
  readonly sessionId: string
}> {}

/**
 * Session expired error
 */
export class SessionExpiredError extends Data.TaggedError("SessionExpiredError")<{
  readonly message: string
  readonly sessionId: string
}> {}

/**
 * User not found error
 */
export class UserNotFoundError extends Data.TaggedError("UserNotFoundError")<{
  readonly message: string
  readonly userId: string
}> {}

/**
 * Permission denied error
 */
export class PermissionDeniedError extends Data.TaggedError("PermissionDeniedError")<{
  readonly message: string
  readonly resource: string
  readonly action: string
}> {}

/**
 * Hashing error
 */
export class HashingError extends Data.TaggedError("HashingError")<{
  readonly message: string
  readonly cause?: unknown
}> {}
