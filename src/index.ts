/**
 * effect-auth — public API barrel.
 *
 * @module effect-auth
 */

// Core primitives
export * from "./Types.ts";
export * from "./Errors.ts";
export * from "./Hooks.ts";
export * from "./TokenHash.ts";
export * from "./email/EmailAddress.ts";
export * from "./Identifier.ts";
export * from "./Cipher.ts";
export * from "./Messages.ts";
export * from "./authz/Permission.ts";
export * from "./authz/RBAC.ts";

// Session management
export * from "./session/SessionService.ts";
export * from "./session/SessionStore.ts";
export * from "./session/UserStore.ts";

// Rate limiting
export * from "./RateLimit.ts";
export * from "./RateLimitPersistence.ts";

// Authorization
export * from "./authz/Authorization.ts";

// Password
export * from "./password/Password.ts";

// OTP primitives
export * from "./OTP.ts";

// Key-value store adapters
export * from "./KeyValueStores.ts";

// Services
export * from "./User.ts";
export * from "./email/EmailPassword.ts";
export * from "./email/EmailOTP.ts";
export * from "./email/EmailVerification.ts";
export * from "./password/PasswordReset.ts";
export * from "./PhoneOTP.ts";
export * from "./MagicLink.ts";
export * from "./Username.ts";
export * from "./TwoFactor.ts";
export * from "./WebAuthn.ts";
export * from "./APIKey.ts";
export * from "./JWT.ts";
export * from "./oauth/OAuth.ts";
export * from "./SSO.ts";
export * from "./GoogleOneTap.ts";
export * from "./Anonymous.ts";
export * from "./Admin.ts";
export * from "./Organization.ts";
export * from "./AccountManagement.ts";
export * from "./DeviceAuthorization.ts";
export * from "./AuthLifecycle.ts";
export * from "./OIDCProvider.ts";
export * from "./ClientIP.ts";
export * from "./SessionCookieCache.ts";
export {
  type OneTimeTokenRecord,
  OneTimeTokenStore,
  type OneTimeTokenStoreShape,
  type OneTimeTokenConfig,
  type OneTimeTokenGenerateOptions,
  type OneTimeTokenVerifyResult,
  type OneTimeTokenServiceShape,
  OneTimeTokenService,
  redeemOneTimeTokenForSession,
} from "./OneTimeToken.ts";

// Observability
/** Metrics counters and record helpers for tracing and observability. */
export * from "./Observability.ts";

// Plugins
/** Structured audit logging of sign-up/sign-in/sign-out (tap hooks). */
export * from "./plugins/Audit.ts";
/** Lowercases and trims emails before sign-up/sign-in. */
export * from "./plugins/NormalizeEmail.ts";
/** Rate-limits auth operations via the RateLimiter service. */
export * from "./plugins/RateLimit.ts";
/** OWASP-style account lockout after repeated failed sign-ins. */
export * from "./plugins/AccountLockout.ts";
/** Captcha verification (Turnstile / reCAPTCHA / hCaptcha) on sign-up/sign-in. */
export * from "./plugins/Captcha.ts";
/** Have-I-Been-Pwned compromised-password checks. */
export * from "./password/HaveIBeenPwned.ts";
/** Records the sign-in method into session attributes (last-login-method). */
export * from "./plugins/LastLoginMethod.ts";
/** IP-keyed rate limiting (sign-in, sign-up, password-reset) using the ClientIP service. */
export * from "./plugins/IPRateLimit.ts";
/** HTTP layer: makeAuthWebHandler, makeAuthClient, wire types. */
export * as Http from "./http/Http.ts";
