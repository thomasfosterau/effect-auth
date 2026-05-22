import * as Request from "effect/Request";
import type * as Types from "./Types.js";
import type * as Errors from "./Errors.js";
import type * as AuthLifecycle from "./AuthLifecycle.js";
import type * as PasswordReset from "./PasswordReset.js";

/**
 * Request to create a new session for a user
 */
export interface CreateSessionRequest extends Request.Request<Types.Session, Errors.AuthError> {
  readonly _tag: "CreateSessionRequest";
  readonly userId: string;
  readonly attributes?: Record<string, unknown>;
}

export const CreateSessionRequest = Request.tagged<CreateSessionRequest>("CreateSessionRequest");

/**
 * Request to validate and retrieve a session
 */
export interface ValidateSessionRequest extends Request.Request<
  Types.SessionWithUser,
  Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError
> {
  readonly _tag: "ValidateSessionRequest";
  readonly sessionId: string;
}

export const ValidateSessionRequest =
  Request.tagged<ValidateSessionRequest>("ValidateSessionRequest");

/**
 * Request to invalidate/delete a session
 */
export interface InvalidateSessionRequest extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "InvalidateSessionRequest";
  readonly sessionId: string;
}

export const InvalidateSessionRequest = Request.tagged<InvalidateSessionRequest>(
  "InvalidateSessionRequest",
);

/**
 * Request to invalidate all sessions for a user
 */
export interface InvalidateUserSessionsRequest extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "InvalidateUserSessionsRequest";
  readonly userId: string;
}

export const InvalidateUserSessionsRequest = Request.tagged<InvalidateUserSessionsRequest>(
  "InvalidateUserSessionsRequest",
);

/**
 * Request to verify credentials and authenticate a user
 */
export interface VerifyCredentialsRequest extends Request.Request<
  Types.User,
  Errors.InvalidCredentialsError | Errors.UserNotFoundError | Errors.HashingError
> {
  readonly _tag: "VerifyCredentialsRequest";
  readonly userId: string;
  readonly password: string;
}

export const VerifyCredentialsRequest = Request.tagged<VerifyCredentialsRequest>(
  "VerifyCredentialsRequest",
);

/**
 * Request to hash a password
 */
export interface HashPasswordRequest extends Request.Request<
  Types.HashedPassword,
  Errors.HashingError
> {
  readonly _tag: "HashPasswordRequest";
  readonly password: string;
}

export const HashPasswordRequest = Request.tagged<HashPasswordRequest>("HashPasswordRequest");

/**
 * Request to verify a password against a hash
 */
export interface VerifyPasswordRequest extends Request.Request<boolean, Errors.HashingError> {
  readonly _tag: "VerifyPasswordRequest";
  readonly password: string;
  readonly hash: string;
}

export const VerifyPasswordRequest = Request.tagged<VerifyPasswordRequest>("VerifyPasswordRequest");

/**
 * Request to check if a user has permission for an action
 */
export interface CheckPermissionRequest extends Request.Request<
  boolean,
  Errors.PermissionDeniedError
> {
  readonly _tag: "CheckPermissionRequest";
  readonly userId: string;
  readonly resource: string;
  readonly action: string;
}

export const CheckPermissionRequest =
  Request.tagged<CheckPermissionRequest>("CheckPermissionRequest");

/**
 * Request to sign up with email and password through lifecycle service
 */
export interface SignUpEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  Errors.AuthError | Errors.HashingError | Errors.EmailVerificationError
> {
  readonly _tag: "SignUpEmailRequest";
  readonly input: {
    readonly email: string;
    readonly password: string;
    readonly name?: string;
    readonly attributes?: Record<string, unknown>;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}

export const SignUpEmailRequest = Request.tagged<SignUpEmailRequest>("SignUpEmailRequest");

/**
 * Request to sign in with email and password through lifecycle service
 */
export interface SignInEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  | Errors.AuthError
  | Errors.HashingError
  | Errors.InvalidCredentialsError
  | Errors.EmailVerificationError
> {
  readonly _tag: "SignInEmailRequest";
  readonly input: {
    readonly email: string;
    readonly password: string;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}

export const SignInEmailRequest = Request.tagged<SignInEmailRequest>("SignInEmailRequest");

/**
 * Request to verify email token through lifecycle service
 */
export interface VerifyEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  Errors.AuthError | Errors.EmailVerificationError
> {
  readonly _tag: "VerifyEmailRequest";
  readonly input: {
    readonly token: string;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}

export const VerifyEmailRequest = Request.tagged<VerifyEmailRequest>("VerifyEmailRequest");

/**
 * Request to initiate password reset for an email
 */
export interface RequestPasswordResetRequest extends Request.Request<
  void,
  Errors.AuthError | Errors.PasswordResetError
> {
  readonly _tag: "RequestPasswordResetRequest";
  readonly email: string;
}

export const RequestPasswordResetRequest = Request.tagged<RequestPasswordResetRequest>(
  "RequestPasswordResetRequest",
);

/**
 * Request to reset password with a token
 */
export interface ResetPasswordRequest extends Request.Request<
  PasswordReset.PasswordResetResult,
  Errors.AuthError | Errors.PasswordResetError | Errors.HashingError
> {
  readonly _tag: "ResetPasswordRequest";
  readonly token: string;
  readonly newPassword: string;
}

export const ResetPasswordRequest = Request.tagged<ResetPasswordRequest>("ResetPasswordRequest");

/**
 * Request to fetch a user by ID
 */
export interface GetUserRequest extends Request.Request<Types.User, Errors.UserNotFoundError> {
  readonly _tag: "GetUserRequest";
  readonly userId: string;
}

export const GetUserRequest = Request.tagged<GetUserRequest>("GetUserRequest");

/**
 * Request to fetch a user by email
 */
export interface GetUserByEmailRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "GetUserByEmailRequest";
  readonly email: string;
}

export const GetUserByEmailRequest = Request.tagged<GetUserByEmailRequest>("GetUserByEmailRequest");

/**
 * Request to merge attributes onto a user
 */
export interface UpdateUserAttributesRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "UpdateUserAttributesRequest";
  readonly userId: string;
  readonly attributes: Record<string, unknown>;
}

export const UpdateUserAttributesRequest = Request.tagged<UpdateUserAttributesRequest>(
  "UpdateUserAttributesRequest",
);

/**
 * Request to mark a user's email as verified
 */
export interface MarkEmailVerifiedRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "MarkEmailVerifiedRequest";
  readonly userId: string;
}

export const MarkEmailVerifiedRequest = Request.tagged<MarkEmailVerifiedRequest>(
  "MarkEmailVerifiedRequest",
);

/**
 * Request to delete a user
 */
export interface DeleteUserRequest extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "DeleteUserRequest";
  readonly userId: string;
}

export const DeleteUserRequest = Request.tagged<DeleteUserRequest>("DeleteUserRequest");
