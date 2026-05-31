import { Data } from "effect";

/**
 * Base authentication error
 */
export class AuthError extends Data.TaggedError("AuthError")<{
  readonly message: string;
}> {}

/**
 * Invalid credentials error
 */
export class InvalidCredentialsError extends Data.TaggedError("InvalidCredentialsError")<{
  readonly message: string;
}> {}

/**
 * Email not verified error
 */
export class EmailNotVerifiedError extends Data.TaggedError("EmailNotVerifiedError")<{
  readonly message: string;
  readonly email: string;
}> {}

/**
 * Session not found error
 */
export class SessionNotFoundError extends Data.TaggedError("SessionNotFoundError")<{
  readonly message: string;
  readonly sessionId: string;
}> {}

/**
 * Session expired error
 */
export class SessionExpiredError extends Data.TaggedError("SessionExpiredError")<{
  readonly message: string;
  readonly sessionId: string;
}> {}

/**
 * User not found error
 */
export class UserNotFoundError extends Data.TaggedError("UserNotFoundError")<{
  readonly message: string;
  readonly userId: string;
}> {}

/**
 * Permission denied error
 */
export class PermissionDeniedError extends Data.TaggedError("PermissionDeniedError")<{
  readonly message: string;
  readonly resource: string;
  readonly action: string;
}> {}

/**
 * Hashing error
 */
export class HashingError extends Data.TaggedError("HashingError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Insufficient scope error (OAuth-style scope authorization)
 */
export class InsufficientScopeError extends Data.TaggedError("InsufficientScopeError")<{
  readonly message: string;
  readonly requiredScope: string;
  readonly grantedScopes: readonly string[];
}> {}

/**
 * WebAuthn challenge not found error
 */
export class ChallengeNotFoundError extends Data.TaggedError("ChallengeNotFoundError")<{
  readonly message: string;
}> {}

/**
 * WebAuthn challenge expired error
 */
export class ChallengeExpiredError extends Data.TaggedError("ChallengeExpiredError")<{
  readonly message: string;
}> {}

/**
 * WebAuthn credential not found error
 */
export class CredentialNotFoundError extends Data.TaggedError("CredentialNotFoundError")<{
  readonly message: string;
  readonly credentialId: string;
}> {}

/**
 * WebAuthn verification error
 */
export class WebAuthnVerificationError extends Data.TaggedError("WebAuthnVerificationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * OAuth state not found error
 */
export class OAuthStateNotFoundError extends Data.TaggedError("OAuthStateNotFoundError")<{
  readonly message: string;
  readonly state: string;
}> {}

/**
 * OAuth state expired error
 */
export class OAuthStateExpiredError extends Data.TaggedError("OAuthStateExpiredError")<{
  readonly message: string;
  readonly state: string;
}> {}

/**
 * OAuth provider error
 */
export class OAuthProviderError extends Data.TaggedError("OAuthProviderError")<{
  readonly message: string;
  readonly provider: string;
  readonly cause?: unknown;
}> {}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends Data.TaggedError("RateLimitError")<{
  readonly message: string;
  readonly key: string;
  readonly retryAfter?: number;
}> {}

/**
 * Email verification error
 */
export class EmailVerificationError extends Data.TaggedError("EmailVerificationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Magic link error
 */
export class MagicLinkError extends Data.TaggedError("MagicLinkError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Password reset error
 */
export class PasswordResetError extends Data.TaggedError("PasswordResetError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}
