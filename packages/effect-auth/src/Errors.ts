import { Data } from "effect";

// ---------------------------------------------------------------------------
// Stable error codes – append-only; never rename or remove.
// ---------------------------------------------------------------------------

/**
 * The stable `code` every domain error carries. Append-only: a code is never renamed or removed, so clients and the `Messages` catalogue can rely on it.
 */
export const ErrorCode = {
  // Infrastructure
  AUTH_ERROR: "AUTH_ERROR",
  HASHING_ERROR: "HASHING_ERROR",

  // Credentials / session
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  SESSION_NOT_FOUND: "SESSION_NOT_FOUND",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  USER_NOT_FOUND: "USER_NOT_FOUND",

  // Email / account state
  EMAIL_NOT_VERIFIED: "EMAIL_NOT_VERIFIED",
  EMAIL_IN_USE: "EMAIL_IN_USE",
  EMAIL_VERIFICATION_ERROR: "EMAIL_VERIFICATION_ERROR",

  // Password policy
  PASSWORD_TOO_SHORT: "PASSWORD_TOO_SHORT",
  PASSWORD_TOO_LONG: "PASSWORD_TOO_LONG",
  PASSWORD_ALREADY_SET: "PASSWORD_ALREADY_SET",
  PWNED_PASSWORD: "PWNED_PASSWORD",

  // Sign-up / input
  SIGN_UP_DISABLED: "SIGN_UP_DISABLED",
  INVALID_INPUT: "INVALID_INPUT",
  CAPTCHA_FAILED: "CAPTCHA_FAILED",

  // Account access
  ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  USER_BANNED: "USER_BANNED",

  // Permissions / scopes
  NOT_AUTHENTICATED: "NOT_AUTHENTICATED",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  INSUFFICIENT_SCOPE: "INSUFFICIENT_SCOPE",

  // WebAuthn
  CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
  CHALLENGE_EXPIRED: "CHALLENGE_EXPIRED",
  CREDENTIAL_NOT_FOUND: "CREDENTIAL_NOT_FOUND",
  WEBAUTHN_VERIFICATION_ERROR: "WEBAUTHN_VERIFICATION_ERROR",

  // OAuth
  OAUTH_STATE_NOT_FOUND: "OAUTH_STATE_NOT_FOUND",
  OAUTH_STATE_EXPIRED: "OAUTH_STATE_EXPIRED",
  OAUTH_PROVIDER_ERROR: "OAUTH_PROVIDER_ERROR",
  OAUTH_ACCOUNT_NOT_LINKED: "OAUTH_ACCOUNT_NOT_LINKED",
  OAUTH_MISSING_EMAIL: "OAUTH_MISSING_EMAIL",
  OAUTH_ACCOUNT_CONFLICT: "OAUTH_ACCOUNT_CONFLICT",
  OAUTH_ACCOUNT_NOT_FOUND: "OAUTH_ACCOUNT_NOT_FOUND",
  OAUTH_NO_REFRESH_TOKEN: "OAUTH_NO_REFRESH_TOKEN",
  OAUTH_LAST_CREDENTIAL: "OAUTH_LAST_CREDENTIAL",
  OAUTH_EMAIL_MISMATCH: "OAUTH_EMAIL_MISMATCH",

  // Misc
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  RESEND_TOO_SOON: "RESEND_TOO_SOON",
  MAGIC_LINK_ERROR: "MAGIC_LINK_ERROR",
  PASSWORD_RESET_ERROR: "PASSWORD_RESET_ERROR",
  ONE_TIME_TOKEN_ERROR: "ONE_TIME_TOKEN_ERROR",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

// ---------------------------------------------------------------------------
// Infrastructure / unexpected errors
// ---------------------------------------------------------------------------

/**
 * Generic infrastructure/unexpected error. Use only for failures that are NOT
 * user-input or flow outcomes (e.g. store unavailability, crypto failure). For
 * flow outcomes use a specific tagged error.
 */
export class AuthError extends Data.TaggedError("AuthError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.AUTH_ERROR {
    return ErrorCode.AUTH_ERROR;
  }
}

/**
 * Password hashing/verification failed (infrastructure).
 */
export class HashingError extends Data.TaggedError("HashingError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.HASHING_ERROR {
    return ErrorCode.HASHING_ERROR;
  }
}

// ---------------------------------------------------------------------------
// Credentials / session
// ---------------------------------------------------------------------------

/**
 * Submitted credentials are invalid. Always uses the generic "Invalid email or
 * password" message to prevent user enumeration.
 */
export class InvalidCredentialsError extends Data.TaggedError("InvalidCredentialsError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.INVALID_CREDENTIALS {
    return ErrorCode.INVALID_CREDENTIALS;
  }
}

/**
 * Session ID not found in the store.
 */
export class SessionNotFoundError extends Data.TaggedError("SessionNotFoundError")<{
  readonly message: string;
  readonly sessionId: string;
}> {
  get code(): typeof ErrorCode.SESSION_NOT_FOUND {
    return ErrorCode.SESSION_NOT_FOUND;
  }
}

/**
 * Session exists but has expired (absolute lifetime or idle timeout).
 */
export class SessionExpiredError extends Data.TaggedError("SessionExpiredError")<{
  readonly message: string;
  readonly sessionId: string;
}> {
  get code(): typeof ErrorCode.SESSION_EXPIRED {
    return ErrorCode.SESSION_EXPIRED;
  }
}

/**
 * User record not found in the store.
 */
export class UserNotFoundError extends Data.TaggedError("UserNotFoundError")<{
  readonly message: string;
  readonly userId: string;
}> {
  get code(): typeof ErrorCode.USER_NOT_FOUND {
    return ErrorCode.USER_NOT_FOUND;
  }
}

// ---------------------------------------------------------------------------
// Email / account state
// ---------------------------------------------------------------------------

/**
 * User has not yet verified their email address.
 */
export class EmailNotVerifiedError extends Data.TaggedError("EmailNotVerifiedError")<{
  readonly message: string;
  readonly email: string;
}> {
  get code(): typeof ErrorCode.EMAIL_NOT_VERIFIED {
    return ErrorCode.EMAIL_NOT_VERIFIED;
  }
}

/**
 * The email address is already associated with another account (sign-up or
 * change-email targeting a taken address).
 */
export class EmailInUseError extends Data.TaggedError("EmailInUseError")<{
  readonly message: string;
  /**
   * The normalized address found taken: for a sign-up, the one the
   * `beforeSignUp` hooks returned, which can differ from the submitted one.
   * Never sent over HTTP.
   */
  readonly email?: string | undefined;
}> {
  get code(): typeof ErrorCode.EMAIL_IN_USE {
    return ErrorCode.EMAIL_IN_USE;
  }
}

/**
 * Email verification operation failed (e.g. token invalid, already used).
 */
export class EmailVerificationError extends Data.TaggedError("EmailVerificationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.EMAIL_VERIFICATION_ERROR {
    return ErrorCode.EMAIL_VERIFICATION_ERROR;
  }
}

// ---------------------------------------------------------------------------
// Password policy (flow outcomes – NOT infrastructure)
// ---------------------------------------------------------------------------

/**
 * Password does not meet length policy requirements.
 *
 * `code` is `"PASSWORD_TOO_SHORT"` or `"PASSWORD_TOO_LONG"`.
 * `params` carries the policy bounds for message interpolation.
 */
export class PasswordPolicyError extends Data.TaggedError("PasswordPolicyError")<{
  readonly code: typeof ErrorCode.PASSWORD_TOO_SHORT | typeof ErrorCode.PASSWORD_TOO_LONG;
  readonly message: string;
  readonly params: { readonly minLength?: number; readonly maxLength?: number };
}> {}

/**
 * Attempting to set a password for a user that already has one. Callers should
 * use `changePassword` instead.
 */
export class PasswordAlreadySetError extends Data.TaggedError("PasswordAlreadySetError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.PASSWORD_ALREADY_SET {
    return ErrorCode.PASSWORD_ALREADY_SET;
  }
}

/**
 * The supplied password appears in a known data-breach corpus (HIBP).
 */
export class PwnedPasswordError extends Data.TaggedError("PwnedPasswordError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.PWNED_PASSWORD {
    return ErrorCode.PWNED_PASSWORD;
  }
}

// ---------------------------------------------------------------------------
// Sign-up / input validation (flow outcomes)
// ---------------------------------------------------------------------------

/**
 * Email/password sign-up has been administratively disabled via config.
 */
export class SignUpDisabledError extends Data.TaggedError("SignUpDisabledError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.SIGN_UP_DISABLED {
    return ErrorCode.SIGN_UP_DISABLED;
  }
}

/**
 * A required input field is missing or empty (e.g. blank email after normalization).
 * `field` names the offending field for the HTTP response.
 */
export class InvalidInputError extends Data.TaggedError("InvalidInputError")<{
  readonly message: string;
  readonly field: string;
}> {
  get code(): typeof ErrorCode.INVALID_INPUT {
    return ErrorCode.INVALID_INPUT;
  }
}

/**
 * Bot/captcha verification failed. Raised by the `CaptchaPlugin`.
 */
export class CaptchaError extends Data.TaggedError("CaptchaError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.CAPTCHA_FAILED {
    return ErrorCode.CAPTCHA_FAILED;
  }
}

// ---------------------------------------------------------------------------
// Account access (flow outcomes)
// ---------------------------------------------------------------------------

/**
 * Account is temporarily locked due to too many failed sign-in attempts.
 * Raised by the `AccountLockoutPlugin`.
 */
export class AccountLockedError extends Data.TaggedError("AccountLockedError")<{
  readonly message: string;
  readonly retryAfter?: number;
}> {
  get code(): typeof ErrorCode.ACCOUNT_LOCKED {
    return ErrorCode.ACCOUNT_LOCKED;
  }
}

/**
 * User account has been permanently banned by an administrator.
 * Raised by the `BannedUserPlugin`.
 */
export class UserBannedError extends Data.TaggedError("UserBannedError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.USER_BANNED {
    return ErrorCode.USER_BANNED;
  }
}

// ---------------------------------------------------------------------------
// Permissions / scopes
// ---------------------------------------------------------------------------

/**
 * No principal is present: the effect required an authenticated user and the
 * current execution is anonymous.
 *
 * The authentication counterpart to {@link PermissionDeniedError}: that one
 * means "we know who you are and you may not"; this one means "we do not know
 * who you are". Raised by the failing accessors in `SessionContext`
 * (`requireCurrentUser`, `requireCurrentSession`) so a guard can turn an
 * anonymous context into a typed failure without reaching for the HTTP layer's
 * `Unauthorized`.
 */
export class NotAuthenticatedError extends Data.TaggedError("NotAuthenticatedError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.NOT_AUTHENTICATED {
    return ErrorCode.NOT_AUTHENTICATED;
  }
}

/**
 * Caller lacks the required permission.
 */
export class PermissionDeniedError extends Data.TaggedError("PermissionDeniedError")<{
  readonly message: string;
  readonly resource: string;
  readonly action: string;
}> {
  get code(): typeof ErrorCode.PERMISSION_DENIED {
    return ErrorCode.PERMISSION_DENIED;
  }
}

/**
 * OAuth-style scope check: caller has been granted fewer scopes than required.
 */
export class InsufficientScopeError extends Data.TaggedError("InsufficientScopeError")<{
  readonly message: string;
  readonly requiredScope: string;
  readonly grantedScopes: readonly string[];
}> {
  get code(): typeof ErrorCode.INSUFFICIENT_SCOPE {
    return ErrorCode.INSUFFICIENT_SCOPE;
  }
}

// ---------------------------------------------------------------------------
// WebAuthn
// ---------------------------------------------------------------------------

/**
 * No pending WebAuthn challenge found for the session.
 */
export class ChallengeNotFoundError extends Data.TaggedError("ChallengeNotFoundError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.CHALLENGE_NOT_FOUND {
    return ErrorCode.CHALLENGE_NOT_FOUND;
  }
}

/**
 * WebAuthn challenge exists but has expired.
 */
export class ChallengeExpiredError extends Data.TaggedError("ChallengeExpiredError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.CHALLENGE_EXPIRED {
    return ErrorCode.CHALLENGE_EXPIRED;
  }
}

/**
 * WebAuthn credential not found.
 */
export class CredentialNotFoundError extends Data.TaggedError("CredentialNotFoundError")<{
  readonly message: string;
  readonly credentialId: string;
}> {
  get code(): typeof ErrorCode.CREDENTIAL_NOT_FOUND {
    return ErrorCode.CREDENTIAL_NOT_FOUND;
  }
}

/**
 * WebAuthn verification step failed (signature, origin, RP ID, ...).
 */
export class WebAuthnVerificationError extends Data.TaggedError("WebAuthnVerificationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.WEBAUTHN_VERIFICATION_ERROR {
    return ErrorCode.WEBAUTHN_VERIFICATION_ERROR;
  }
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

/**
 * OAuth CSRF state token not found (unknown or already consumed).
 */
export class OAuthStateNotFoundError extends Data.TaggedError("OAuthStateNotFoundError")<{
  readonly message: string;
  readonly state: string;
}> {
  get code(): typeof ErrorCode.OAUTH_STATE_NOT_FOUND {
    return ErrorCode.OAUTH_STATE_NOT_FOUND;
  }
}

/**
 * OAuth CSRF state token has expired.
 */
export class OAuthStateExpiredError extends Data.TaggedError("OAuthStateExpiredError")<{
  readonly message: string;
  readonly state: string;
}> {
  get code(): typeof ErrorCode.OAUTH_STATE_EXPIRED {
    return ErrorCode.OAUTH_STATE_EXPIRED;
  }
}

/**
 * External OAuth provider returned an error or unexpected response.
 */
export class OAuthProviderError extends Data.TaggedError("OAuthProviderError")<{
  readonly message: string;
  readonly provider: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.OAUTH_PROVIDER_ERROR {
    return ErrorCode.OAUTH_PROVIDER_ERROR;
  }
}

/**
 * OAuth account exists in the store but is not linked to any user. Use
 * `linkAccount` to associate it with a user before signing in.
 */
export class OAuthAccountNotLinkedError extends Data.TaggedError("OAuthAccountNotLinkedError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_NOT_LINKED {
    return ErrorCode.OAUTH_ACCOUNT_NOT_LINKED;
  }
}

/**
 * The OAuth provider did not return an email address for this account.
 */
export class OAuthMissingEmailError extends Data.TaggedError("OAuthMissingEmailError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_MISSING_EMAIL {
    return ErrorCode.OAUTH_MISSING_EMAIL;
  }
}

/**
 * The OAuth account is already linked to a different user.
 */
export class OAuthAccountConflictError extends Data.TaggedError("OAuthAccountConflictError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_CONFLICT {
    return ErrorCode.OAUTH_ACCOUNT_CONFLICT;
  }
}

/**
 * No OAuth account for the given provider is linked to the user.
 */
export class OAuthAccountNotFoundError extends Data.TaggedError("OAuthAccountNotFoundError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_NOT_FOUND {
    return ErrorCode.OAUTH_ACCOUNT_NOT_FOUND;
  }
}

/**
 * The OAuth account has no stored refresh token.
 */
export class OAuthNoRefreshTokenError extends Data.TaggedError("OAuthNoRefreshTokenError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_NO_REFRESH_TOKEN {
    return ErrorCode.OAUTH_NO_REFRESH_TOKEN;
  }
}

/**
 * Unlinking would remove the user's last sign-in credential: no other linked
 * OAuth account remains and the user has no password. Pass
 * `allowUnlinkingAll: true` to `unlinkAccount` to override.
 */
export class OAuthLastCredentialError extends Data.TaggedError("OAuthLastCredentialError")<{
  readonly message: string;
  readonly userId: string;
}> {
  get code(): typeof ErrorCode.OAUTH_LAST_CREDENTIAL {
    return ErrorCode.OAUTH_LAST_CREDENTIAL;
  }
}

/**
 * The OAuth account's provider email differs from the user's current account
 * email. Pass `allowDifferentEmails: true` in `OAuthServiceOptions` to override.
 */
export class OAuthEmailMismatchError extends Data.TaggedError("OAuthEmailMismatchError")<{
  readonly message: string;
  readonly provider: string;
}> {
  get code(): typeof ErrorCode.OAUTH_EMAIL_MISMATCH {
    return ErrorCode.OAUTH_EMAIL_MISMATCH;
  }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/**
 * Resend requested before the per-identifier cooldown window has elapsed.
 * `retryAfter` is the number of milliseconds the caller must wait before
 * sending again. Raised by the passwordless send paths when `resendCooldown`
 * is configured in the flow config.
 */
export class ResendTooSoonError extends Data.TaggedError("ResendTooSoonError")<{
  readonly message: string;
  readonly retryAfter: number;
}> {
  get code(): typeof ErrorCode.RESEND_TOO_SOON {
    return ErrorCode.RESEND_TOO_SOON;
  }
}

/**
 * Rate limit exceeded. `retryAfter` is the number of milliseconds before the
 * caller may retry.
 */
export class RateLimitError extends Data.TaggedError("RateLimitError")<{
  readonly message: string;
  readonly key: string;
  readonly retryAfter?: number;
}> {
  get code(): typeof ErrorCode.RATE_LIMIT_EXCEEDED {
    return ErrorCode.RATE_LIMIT_EXCEEDED;
  }
}

/**
 * A client-address-keyed rate limit is configured with no client-address
 * source: no `trustedProxy`, and no opt-out. A Web `Request` never carries a
 * socket address, so without a configured source the limiter could not key the
 * request. It would have to skip the request or share one bucket between
 * callers, and neither is allowed (#358, #388).
 *
 * Raised at build time, before any request:
 *
 * - `Http.make` throws it synchronously when `ipRateLimit` is configured with no
 *   `trustedProxy` and no `allowMissingClientIp: true` (#358), and when the
 *   `Hooks` in `services` include `IPRateLimitPlugin` with neither of them
 *   (#389), and when the `services` include an `OidcProviderService` with
 *   dynamic client registration enabled and there is neither of them (#388,
 *   #398).
 *
 * `Http.makeAsync` rejects with the same errors `Http.make` throws, so the app
 * fails to start either way.
 *
 * Exported from the package root as `ClientAddressConfigError` and as
 * `Http.ClientAddressConfigError`, and from the `./http` subpath. Every name is
 * the same class.
 */
export class ClientAddressConfigError extends Data.TaggedError("ClientAddressConfigError")<{
  readonly message: string;
}> {}

/**
 * A rate limit is configured with no `RateLimiter` in `services`, so it could not
 * run (#389). The limits are `Http.make`'s `ipRateLimit`, the dynamic client
 * registration limit (`POST /register`) and the device user-code limit on
 * approve/deny, which counts as configured whenever a
 * `DeviceAuthorizationService` is in `services` unless it was built with
 * `allowMissingRateLimiter: true`.
 *
 * `Http.make` throws it synchronously when `services` builds synchronously, so
 * the app fails to start. When `services` does asynchronous work while building
 * (a database connection, for example), `make` returns before the build can be
 * checked: the handler's build fails with this error instead, and every request
 * rejects with it. `Http.makeAsync` rejects with it at startup, so the app fails
 * to start, however `services` is composed.
 */
export class RateLimiterConfigError extends Data.TaggedError("RateLimiterConfigError")<{
  readonly message: string;
}> {}

/**
 * `Http.make` was called with `strict: true`, and the `services` build had not
 * finished when `make` had run it as far as it runs synchronously (#416). The
 * build waits on asynchronous work (a database connection, `Effect.promise`),
 * on a merged layer that yields, on a forked fiber that yields before it
 * completes a `Deferred` the build awaits, or, when the build fails, on a
 * finalizer that does asynchronous work. The message names `Http.makeAsync`,
 * which waits for such a build.
 *
 * `make` throws it synchronously, so the app fails to start. Before it throws,
 * `make` interrupts the build and releases what the build acquired, as far as
 * that runs synchronously. Two parts finish after `make` has thrown: a
 * finalizer that does asynchronous work, and, when the build is in an
 * uninterruptible step that waits on asynchronous work (an
 * `Effect.acquireRelease` acquire that awaits), the whole release, since the
 * interrupt waits for that step to end.
 *
 * It cannot carry a failure the build ends with only after `make` throws: when
 * the build is failing (a step that failed while a finalizer it runs awaits),
 * `make` logs that failure with `Effect.logError` when the build ends.
 *
 * Without `strict`, `make` never raises it: it returns, and the startup checks
 * run when the build finishes.
 *
 * Exported from the package root as `ServicesBuildPendingError` and as
 * `Http.ServicesBuildPendingError`, and from the `./http` subpath. Every name
 * is the same class.
 */
export class ServicesBuildPendingError extends Data.TaggedError("ServicesBuildPendingError")<{
  readonly message: string;
}> {}

/**
 * Magic link send/verify failure (infrastructure or token mismatch).
 */
export class MagicLinkError extends Data.TaggedError("MagicLinkError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.MAGIC_LINK_ERROR {
    return ErrorCode.MAGIC_LINK_ERROR;
  }
}

/**
 * Password reset send/verify failure (infrastructure or token mismatch).
 */
export class PasswordResetError extends Data.TaggedError("PasswordResetError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {
  get code(): typeof ErrorCode.PASSWORD_RESET_ERROR {
    return ErrorCode.PASSWORD_RESET_ERROR;
  }
}

/**
 * One-time token verification failure (invalid, expired, or already used).
 *
 * Anti-enumeration: all failure cases surface the same generic message so
 * callers cannot distinguish between a token that never existed and one that
 * has already been consumed.
 */
export class OneTimeTokenError extends Data.TaggedError("OneTimeTokenError")<{
  readonly message: string;
}> {
  get code(): typeof ErrorCode.ONE_TIME_TOKEN_ERROR {
    return ErrorCode.ONE_TIME_TOKEN_ERROR;
  }
}
