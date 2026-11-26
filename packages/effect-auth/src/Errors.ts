import * as Schema from "effect/Schema";

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
  REAUTHENTICATION_REQUIRED: "REAUTHENTICATION_REQUIRED",

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
  LAST_ORGANIZATION_OWNER: "LAST_ORGANIZATION_OWNER",
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
export class AuthError extends Schema.TaggedError<AuthError, { readonly brand: unique symbol }>()(
  "AuthError",
  {
    message: Schema.String,
    cause: Schema.optionalKey(Schema.Unknown),
  },
) {
  get code(): typeof ErrorCode.AUTH_ERROR {
    return ErrorCode.AUTH_ERROR;
  }
}

/**
 * Password hashing/verification failed (infrastructure).
 */
export class HashingError extends Schema.TaggedError<
  HashingError,
  { readonly brand: unique symbol }
>()("HashingError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
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
export class InvalidCredentialsError extends Schema.TaggedError<
  InvalidCredentialsError,
  { readonly brand: unique symbol }
>()("InvalidCredentialsError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.INVALID_CREDENTIALS {
    return ErrorCode.INVALID_CREDENTIALS;
  }
}

/**
 * Session ID not found in the store.
 */
export class SessionNotFoundError extends Schema.TaggedError<
  SessionNotFoundError,
  { readonly brand: unique symbol }
>()("SessionNotFoundError", {
  message: Schema.String,
  sessionId: Schema.String,
}) {
  get code(): typeof ErrorCode.SESSION_NOT_FOUND {
    return ErrorCode.SESSION_NOT_FOUND;
  }
}

/**
 * Session exists but has expired (absolute lifetime or idle timeout).
 */
export class SessionExpiredError extends Schema.TaggedError<
  SessionExpiredError,
  { readonly brand: unique symbol }
>()("SessionExpiredError", {
  message: Schema.String,
  sessionId: Schema.String,
}) {
  get code(): typeof ErrorCode.SESSION_EXPIRED {
    return ErrorCode.SESSION_EXPIRED;
  }
}

/**
 * User record not found in the store.
 */
export class UserNotFoundError extends Schema.TaggedError<
  UserNotFoundError,
  { readonly brand: unique symbol }
>()("UserNotFoundError", {
  message: Schema.String,
  userId: Schema.String,
}) {
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
export class EmailNotVerifiedError extends Schema.TaggedError<
  EmailNotVerifiedError,
  { readonly brand: unique symbol }
>()("EmailNotVerifiedError", {
  message: Schema.String,
  email: Schema.String,
}) {
  get code(): typeof ErrorCode.EMAIL_NOT_VERIFIED {
    return ErrorCode.EMAIL_NOT_VERIFIED;
  }
}

/**
 * The email address is already associated with another account (sign-up or
 * change-email targeting a taken address).
 */
export class EmailInUseError extends Schema.TaggedError<
  EmailInUseError,
  { readonly brand: unique symbol }
>()("EmailInUseError", {
  message: Schema.String,
  /**
   * The normalized address found taken: for a sign-up, the one the
   * `beforeSignUp` hooks returned, which can differ from the submitted one.
   * Never sent over HTTP.
   */
  email: Schema.optionalKey(Schema.String),
}) {
  get code(): typeof ErrorCode.EMAIL_IN_USE {
    return ErrorCode.EMAIL_IN_USE;
  }
}

/**
 * Email verification operation failed (e.g. token invalid, already used).
 */
export class EmailVerificationError extends Schema.TaggedError<
  EmailVerificationError,
  { readonly brand: unique symbol }
>()("EmailVerificationError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
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
export class PasswordPolicyError extends Schema.TaggedError<
  PasswordPolicyError,
  { readonly brand: unique symbol }
>()("PasswordPolicyError", {
  code: Schema.Literals([ErrorCode.PASSWORD_TOO_SHORT, ErrorCode.PASSWORD_TOO_LONG]),
  message: Schema.String,
  params: Schema.Struct({
    minLength: Schema.optionalKey(Schema.Finite),
    maxLength: Schema.optionalKey(Schema.Finite),
  }),
}) {}

/**
 * A sensitive change (starting an email change) needs fresh proof that the
 * caller is the account holder: the current password, or for an account
 * without one, a recent sign-in.
 */
export class ReauthenticationRequiredError extends Schema.TaggedError<
  ReauthenticationRequiredError,
  { readonly brand: unique symbol }
>()("ReauthenticationRequiredError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.REAUTHENTICATION_REQUIRED {
    return ErrorCode.REAUTHENTICATION_REQUIRED;
  }
}

/**
 * Attempting to set a password for a user that already has one. Callers should
 * use `changePassword` instead.
 */
export class PasswordAlreadySetError extends Schema.TaggedError<
  PasswordAlreadySetError,
  { readonly brand: unique symbol }
>()("PasswordAlreadySetError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.PASSWORD_ALREADY_SET {
    return ErrorCode.PASSWORD_ALREADY_SET;
  }
}

/**
 * The supplied password appears in a known data-breach corpus (HIBP).
 */
export class PwnedPasswordError extends Schema.TaggedError<
  PwnedPasswordError,
  { readonly brand: unique symbol }
>()("PwnedPasswordError", {
  message: Schema.String,
}) {
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
export class SignUpDisabledError extends Schema.TaggedError<
  SignUpDisabledError,
  { readonly brand: unique symbol }
>()("SignUpDisabledError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.SIGN_UP_DISABLED {
    return ErrorCode.SIGN_UP_DISABLED;
  }
}

/**
 * A required input field is missing or empty (e.g. blank email after normalization).
 * `field` names the offending field for the HTTP response.
 */
export class InvalidInputError extends Schema.TaggedError<
  InvalidInputError,
  { readonly brand: unique symbol }
>()("InvalidInputError", {
  message: Schema.String,
  field: Schema.String,
}) {
  get code(): typeof ErrorCode.INVALID_INPUT {
    return ErrorCode.INVALID_INPUT;
  }
}

/**
 * Bot/captcha verification failed. Raised by the `CaptchaPlugin`.
 */
export class CaptchaError extends Schema.TaggedError<
  CaptchaError,
  { readonly brand: unique symbol }
>()("CaptchaError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.CAPTCHA_FAILED {
    return ErrorCode.CAPTCHA_FAILED;
  }
}

// ---------------------------------------------------------------------------
// Account access (flow outcomes)
// ---------------------------------------------------------------------------

/**
 * Account is temporarily locked due to too many failed sign-in attempts.
 * Raised by the `AccountLockoutPlugin`. `retryAfter`, when present, is how
 * long the lock has left to run; an HTTP layer that sends it as a
 * `Retry-After` header rounds it up to whole seconds.
 */
export class AccountLockedError extends Schema.TaggedError<
  AccountLockedError,
  { readonly brand: unique symbol }
>()("AccountLockedError", {
  message: Schema.String,
  retryAfter: Schema.optionalKey(Schema.Duration),
}) {
  get code(): typeof ErrorCode.ACCOUNT_LOCKED {
    return ErrorCode.ACCOUNT_LOCKED;
  }
}

/**
 * The user is banned or SCIM-deactivated. `SessionService` raises it when it
 * would create or answer a session for such a user.
 */
export class UserBannedError extends Schema.TaggedError<
  UserBannedError,
  { readonly brand: unique symbol }
>()("UserBannedError", {
  message: Schema.String,
}) {
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
export class NotAuthenticatedError extends Schema.TaggedError<
  NotAuthenticatedError,
  { readonly brand: unique symbol }
>()("NotAuthenticatedError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.NOT_AUTHENTICATED {
    return ErrorCode.NOT_AUTHENTICATED;
  }
}

/**
 * Caller lacks the required permission.
 */
export class PermissionDeniedError extends Schema.TaggedError<
  PermissionDeniedError,
  { readonly brand: unique symbol }
>()("PermissionDeniedError", {
  message: Schema.String,
  resource: Schema.String,
  action: Schema.String,
}) {
  get code(): typeof ErrorCode.PERMISSION_DENIED {
    return ErrorCode.PERMISSION_DENIED;
  }
}

/**
 * OAuth-style scope check: caller has been granted fewer scopes than required.
 */
export class InsufficientScopeError extends Schema.TaggedError<
  InsufficientScopeError,
  { readonly brand: unique symbol }
>()("InsufficientScopeError", {
  message: Schema.String,
  requiredScope: Schema.String,
  grantedScopes: Schema.Array(Schema.String),
}) {
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
export class ChallengeNotFoundError extends Schema.TaggedError<
  ChallengeNotFoundError,
  { readonly brand: unique symbol }
>()("ChallengeNotFoundError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.CHALLENGE_NOT_FOUND {
    return ErrorCode.CHALLENGE_NOT_FOUND;
  }
}

/**
 * WebAuthn challenge exists but has expired.
 */
export class ChallengeExpiredError extends Schema.TaggedError<
  ChallengeExpiredError,
  { readonly brand: unique symbol }
>()("ChallengeExpiredError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.CHALLENGE_EXPIRED {
    return ErrorCode.CHALLENGE_EXPIRED;
  }
}

/**
 * WebAuthn credential not found.
 */
export class CredentialNotFoundError extends Schema.TaggedError<
  CredentialNotFoundError,
  { readonly brand: unique symbol }
>()("CredentialNotFoundError", {
  message: Schema.String,
  credentialId: Schema.String,
}) {
  get code(): typeof ErrorCode.CREDENTIAL_NOT_FOUND {
    return ErrorCode.CREDENTIAL_NOT_FOUND;
  }
}

/**
 * WebAuthn verification step failed (signature, origin, RP ID, ...).
 */
export class WebAuthnVerificationError extends Schema.TaggedError<
  WebAuthnVerificationError,
  { readonly brand: unique symbol }
>()("WebAuthnVerificationError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
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
export class OAuthStateNotFoundError extends Schema.TaggedError<
  OAuthStateNotFoundError,
  { readonly brand: unique symbol }
>()("OAuthStateNotFoundError", {
  message: Schema.String,
  state: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_STATE_NOT_FOUND {
    return ErrorCode.OAUTH_STATE_NOT_FOUND;
  }
}

/**
 * OAuth CSRF state token has expired.
 */
export class OAuthStateExpiredError extends Schema.TaggedError<
  OAuthStateExpiredError,
  { readonly brand: unique symbol }
>()("OAuthStateExpiredError", {
  message: Schema.String,
  state: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_STATE_EXPIRED {
    return ErrorCode.OAUTH_STATE_EXPIRED;
  }
}

/**
 * External OAuth provider returned an error or unexpected response.
 */
export class OAuthProviderError extends Schema.TaggedError<
  OAuthProviderError,
  { readonly brand: unique symbol }
>()("OAuthProviderError", {
  message: Schema.String,
  provider: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
  get code(): typeof ErrorCode.OAUTH_PROVIDER_ERROR {
    return ErrorCode.OAUTH_PROVIDER_ERROR;
  }
}

/**
 * OAuth account exists in the store but is not linked to any user. Use
 * `linkAccount` to associate it with a user before signing in.
 */
export class OAuthAccountNotLinkedError extends Schema.TaggedError<
  OAuthAccountNotLinkedError,
  { readonly brand: unique symbol }
>()("OAuthAccountNotLinkedError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_NOT_LINKED {
    return ErrorCode.OAUTH_ACCOUNT_NOT_LINKED;
  }
}

/**
 * The OAuth provider did not return an email address for this account.
 */
export class OAuthMissingEmailError extends Schema.TaggedError<
  OAuthMissingEmailError,
  { readonly brand: unique symbol }
>()("OAuthMissingEmailError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_MISSING_EMAIL {
    return ErrorCode.OAUTH_MISSING_EMAIL;
  }
}

/**
 * The OAuth account is already linked to a different user.
 */
export class OAuthAccountConflictError extends Schema.TaggedError<
  OAuthAccountConflictError,
  { readonly brand: unique symbol }
>()("OAuthAccountConflictError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_CONFLICT {
    return ErrorCode.OAUTH_ACCOUNT_CONFLICT;
  }
}

/**
 * No OAuth account for the given provider is linked to the user.
 */
export class OAuthAccountNotFoundError extends Schema.TaggedError<
  OAuthAccountNotFoundError,
  { readonly brand: unique symbol }
>()("OAuthAccountNotFoundError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_ACCOUNT_NOT_FOUND {
    return ErrorCode.OAUTH_ACCOUNT_NOT_FOUND;
  }
}

/**
 * The OAuth account has no stored refresh token.
 */
export class OAuthNoRefreshTokenError extends Schema.TaggedError<
  OAuthNoRefreshTokenError,
  { readonly brand: unique symbol }
>()("OAuthNoRefreshTokenError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_NO_REFRESH_TOKEN {
    return ErrorCode.OAUTH_NO_REFRESH_TOKEN;
  }
}

/**
 * Unlinking would remove the user's last sign-in credential: no other linked
 * OAuth account remains and the user has no password. Pass
 * `allowUnlinkingAll: true` to `unlinkAccount` to override.
 */
export class OAuthLastCredentialError extends Schema.TaggedError<
  OAuthLastCredentialError,
  { readonly brand: unique symbol }
>()("OAuthLastCredentialError", {
  message: Schema.String,
  userId: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_LAST_CREDENTIAL {
    return ErrorCode.OAUTH_LAST_CREDENTIAL;
  }
}

/**
 * The OAuth account's provider email differs from the user's current account
 * email. Pass `allowDifferentEmails: true` in `OAuthServiceOptions` to override.
 */
export class OAuthEmailMismatchError extends Schema.TaggedError<
  OAuthEmailMismatchError,
  { readonly brand: unique symbol }
>()("OAuthEmailMismatchError", {
  message: Schema.String,
  provider: Schema.String,
}) {
  get code(): typeof ErrorCode.OAUTH_EMAIL_MISMATCH {
    return ErrorCode.OAUTH_EMAIL_MISMATCH;
  }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/**
 * Resend requested before the per-identifier cooldown window has elapsed.
 * `retryAfter` is how long the caller must wait before sending again; an HTTP
 * layer that sends it as a `Retry-After` header rounds it up to whole seconds.
 * Raised by the passwordless send paths when `resendCooldown` is configured in
 * the flow config.
 */
export class ResendTooSoonError extends Schema.TaggedError<
  ResendTooSoonError,
  { readonly brand: unique symbol }
>()("ResendTooSoonError", {
  message: Schema.String,
  retryAfter: Schema.Duration,
}) {
  get code(): typeof ErrorCode.RESEND_TOO_SOON {
    return ErrorCode.RESEND_TOO_SOON;
  }
}

/**
 * Deleting a user who is the last active owner of an organization that still
 * has other members. Transfer ownership, or remove the other members, first;
 * nothing of the user was deleted.
 */
export class LastOrganizationOwnerError extends Data.TaggedError("LastOrganizationOwnerError")<{
  readonly message: string;
  readonly organizationId: string;
}> {
  get code(): typeof ErrorCode.LAST_ORGANIZATION_OWNER {
    return ErrorCode.LAST_ORGANIZATION_OWNER;
  }
}

/**
 * Rate limit exceeded. `retryAfter`, when present, is how long the caller
 * must wait before retrying; an HTTP layer that sends it as a `Retry-After`
 * header rounds it up to whole seconds.
 */
export class RateLimitError extends Schema.TaggedError<
  RateLimitError,
  { readonly brand: unique symbol }
>()("RateLimitError", {
  message: Schema.String,
  key: Schema.String,
  retryAfter: Schema.optionalKey(Schema.Duration),
}) {
  get code(): typeof ErrorCode.RATE_LIMIT_EXCEEDED {
    return ErrorCode.RATE_LIMIT_EXCEEDED;
  }
}

/**
 * A client-address-keyed rate limit is configured with no client-address
 * source: no `trustedProxy`. A Web `Request` never carries a socket address,
 * so without a configured source the limiter could not key the request. It
 * would have to skip the request, share one bucket between callers or refuse
 * every request, and none of these is allowed.
 *
 * Raised at build time, before any request:
 *
 * - `Http.make` throws it synchronously when `ipRateLimit` (on unless it is
 *   `false`) has no `trustedProxy`, when the `Hooks` in
 *   `services` include `IPRateLimitPlugin` with no `trustedProxy`, and
 *   when the `services` include an `OidcProviderService` with dynamic client
 *   registration enabled and there is no `trustedProxy`. With no proxy no
 *   request has an address, so every limited request would be refused with
 *   `429`, and the handler refuses to start instead.
 *
 * `Http.makeAsync` rejects with the same errors `Http.make` throws, so the app
 * fails to start either way.
 *
 * Exported from the package root and from the `./http` subpath as
 * `ClientAddressConfigError`. Both names are the same class.
 */
export class ClientAddressConfigError extends Schema.TaggedError<
  ClientAddressConfigError,
  { readonly brand: unique symbol }
>()("ClientAddressConfigError", {
  message: Schema.String,
}) {}

/**
 * `SessionService.layer` (or `SessionService.make`) was given a
 * `sessionExpiresIn` that cannot work: an `activePeriod` or
 * `idlePeriod` that is not a finite, positive number of milliseconds (`NaN`
 * from an unset `Number(env)`, for example), or an `updateAge` that is not a
 * finite number, 0 or more. The layer build dies with it, so the app fails to
 * start instead of issuing sessions that never expire.
 */
export class SessionConfigError extends Schema.TaggedError<
  SessionConfigError,
  { readonly brand: unique symbol }
>()("SessionConfigError", {
  message: Schema.String,
}) {}

/**
 * A rate limit is configured with no `RateLimiter` in `services`, so it could not
 * run. The limits are `Http.make`'s `ipRateLimit` (on unless it is
 * `false`), the dynamic client
 * registration limit (`POST /register`) and the device user-code limit on
 * lookups and decisions, which counts as configured whenever a
 * `DeviceAuthorizationService` is in `services` unless it was built with
 * `allowMissingRateLimiter: true`.
 *
 * `Http.make` throws it synchronously when `services` builds synchronously, so
 * the app fails to start. When `services` does asynchronous work while building
 * (a database connection, for example), `make` returns before the build can be
 * checked: the handler's build fails with this error instead, and every request
 * rejects with it. `Http.makeAsync` rejects with it at startup, so the app fails
 * to start, however `services` is composed.
 *
 * It is also the error for an `ipv6PrefixLength` that is not an integer from 1
 * to 128: `Http.make` throws it for `ipRateLimit.ipv6PrefixLength`, and the
 * `IPRateLimitPlugin` layer build dies with it.
 */
export class RateLimiterConfigError extends Schema.TaggedError<
  RateLimiterConfigError,
  { readonly brand: unique symbol }
>()("RateLimiterConfigError", {
  message: Schema.String,
}) {}

/**
 * `Http.make` was called with `strict: true`, and the `services` build had not
 * finished when `make` had run it as far as it runs synchronously. The
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
 * Exported from the package root and from the `./http` subpath as
 * `ServicesBuildPendingError`. Both names are the same class.
 */
export class ServicesBuildPendingError extends Schema.TaggedError<
  ServicesBuildPendingError,
  { readonly brand: unique symbol }
>()("ServicesBuildPendingError", {
  message: Schema.String,
}) {}

/**
 * `Http.make` (or `Http.makeAsync`) was given `strict: true` and a
 * `signUpAttributes` list naming a key of `SIGN_UP_PROTECTED_ATTRIBUTES`
 * (the ban, SCIM and anonymous-user keys). A sign-up never stores those
 * whatever the list says, so naming one does nothing; without `strict` the
 * handler logs a warning instead. `attributes` lists the protected keys named.
 *
 * Exported from the package root and from the `./http` subpath as
 * `SignUpAttributesConfigError`. Both names are the same class.
 *
 * @since 0.9.0
 * @category errors
 */
export class SignUpAttributesConfigError extends Schema.TaggedError<
  SignUpAttributesConfigError,
  { readonly brand: unique symbol }
>()("SignUpAttributesConfigError", {
  message: Schema.String,
  attributes: Schema.Array(Schema.String),
}) {}

/**
 * Magic link send/verify failure (infrastructure or token mismatch).
 */
export class MagicLinkError extends Schema.TaggedError<
  MagicLinkError,
  { readonly brand: unique symbol }
>()("MagicLinkError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
  get code(): typeof ErrorCode.MAGIC_LINK_ERROR {
    return ErrorCode.MAGIC_LINK_ERROR;
  }
}

/**
 * Password reset send/verify failure (infrastructure or token mismatch).
 */
export class PasswordResetError extends Schema.TaggedError<
  PasswordResetError,
  { readonly brand: unique symbol }
>()("PasswordResetError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Unknown),
}) {
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
export class OneTimeTokenError extends Schema.TaggedError<
  OneTimeTokenError,
  { readonly brand: unique symbol }
>()("OneTimeTokenError", {
  message: Schema.String,
}) {
  get code(): typeof ErrorCode.ONE_TIME_TOKEN_ERROR {
    return ErrorCode.ONE_TIME_TOKEN_ERROR;
  }
}
