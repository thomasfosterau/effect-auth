import * as Request from "effect/Request"
import type * as Types from "./types.js"
import type * as Errors from "./errors.js"

/**
 * Request to create a new session for a user
 */
export interface CreateSessionRequest
  extends Request.Request<Types.Session, Errors.AuthError> {
  readonly _tag: "CreateSessionRequest"
  readonly userId: string
  readonly attributes?: Record<string, unknown>
}

export const CreateSessionRequest = Request.tagged<CreateSessionRequest>("CreateSessionRequest")

/**
 * Request to validate and retrieve a session
 */
export interface ValidateSessionRequest
  extends Request.Request<
    Types.SessionWithUser,
    Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError
  > {
  readonly _tag: "ValidateSessionRequest"
  readonly sessionId: string
}

export const ValidateSessionRequest = Request.tagged<ValidateSessionRequest>("ValidateSessionRequest")

/**
 * Request to invalidate/delete a session
 */
export interface InvalidateSessionRequest
  extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "InvalidateSessionRequest"
  readonly sessionId: string
}

export const InvalidateSessionRequest = Request.tagged<InvalidateSessionRequest>("InvalidateSessionRequest")

/**
 * Request to invalidate all sessions for a user
 */
export interface InvalidateUserSessionsRequest
  extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "InvalidateUserSessionsRequest"
  readonly userId: string
}

export const InvalidateUserSessionsRequest = Request.tagged<InvalidateUserSessionsRequest>("InvalidateUserSessionsRequest")

/**
 * Request to verify credentials and authenticate a user
 */
export interface VerifyCredentialsRequest
  extends Request.Request<
    Types.User,
    Errors.InvalidCredentialsError | Errors.UserNotFoundError | Errors.HashingError
  > {
  readonly _tag: "VerifyCredentialsRequest"
  readonly userId: string
  readonly password: string
}

export const VerifyCredentialsRequest = Request.tagged<VerifyCredentialsRequest>("VerifyCredentialsRequest")

/**
 * Request to hash a password
 */
export interface HashPasswordRequest
  extends Request.Request<Types.HashedPassword, Errors.HashingError> {
  readonly _tag: "HashPasswordRequest"
  readonly password: string
}

export const HashPasswordRequest = Request.tagged<HashPasswordRequest>("HashPasswordRequest")

/**
 * Request to verify a password against a hash
 */
export interface VerifyPasswordRequest
  extends Request.Request<boolean, Errors.HashingError> {
  readonly _tag: "VerifyPasswordRequest"
  readonly password: string
  readonly hash: string
}

export const VerifyPasswordRequest = Request.tagged<VerifyPasswordRequest>("VerifyPasswordRequest")

/**
 * Request to check if a user has permission for an action
 */
export interface CheckPermissionRequest
  extends Request.Request<boolean, Errors.PermissionDeniedError> {
  readonly _tag: "CheckPermissionRequest"
  readonly userId: string
  readonly resource: string
  readonly action: string
}

export const CheckPermissionRequest = Request.tagged<CheckPermissionRequest>("CheckPermissionRequest")
