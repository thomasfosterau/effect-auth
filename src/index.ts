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
export * from "./EmailAddress.ts";
export * from "./Identifier.ts";
export * from "./Cipher.ts";
export * from "./Messages.ts";
export * from "./Permission.ts";
export * from "./Rbac.ts";

// Session management (SessionManager = legacy alias for SessionService)
export * from "./SessionService.ts";
export * from "./SessionStore.ts";
export * from "./UserStore.ts";
// Compat: re-export SessionManager alias and makeSessionManager
export { SessionService as SessionManager, make as makeSessionManager } from "./SessionService.ts";
export type { SessionServiceShape as SessionManagerShape } from "./SessionService.ts";

// Rate limiting
export * from "./RateLimit.ts";
export * from "./RateLimitPersistence.ts";

// Authorization
export * from "./Authorization.ts";

// Password
export * from "./Password.ts";

// OTP primitives
export * from "./Otp.ts";

// Key-value store adapters
export * from "./KeyValueStores.ts";

// Services
export * from "./User.ts";
export * from "./EmailPassword.ts";
export * from "./EmailOtp.ts";
export * from "./EmailVerification.ts";
export * from "./PasswordReset.ts";
export * from "./PhoneOtp.ts";
export * from "./MagicLink.ts";
export * from "./Username.ts";
export * from "./TwoFactor.ts";
export * from "./WebAuthn.ts";
export { WebAuthnService, type WebAuthnServiceShape } from "./WebAuthnService.ts";
export * from "./ApiKey.ts";
export * from "./Jwt.ts";
export * from "./OAuth/OAuth.ts";
export * from "./Sso.ts";
export * from "./GoogleOneTap.ts";
export * from "./Anonymous.ts";
export * from "./Admin.ts";
export * from "./Organization.ts";
export * from "./AccountManagement.ts";
export * from "./DeviceAuthorization.ts";
export * from "./AuthLifecycle.ts";
export * from "./OidcProvider.ts";
export * from "./ClientIp.ts";
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

// Plugins
/** Structured audit logging of sign-up/sign-in/sign-out (tap hooks). */
export * from "./AuditPlugin.ts";
/** Lowercases and trims emails before sign-up/sign-in. */
export * from "./NormalizeEmailPlugin.ts";
/** Rate-limits auth operations via the RateLimiter service. */
export * from "./RateLimitPlugin.ts";
/** OWASP-style account lockout after repeated failed sign-ins. */
export * from "./AccountLockoutPlugin.ts";
/** Captcha verification (Turnstile / reCAPTCHA / hCaptcha) on sign-up/sign-in. */
export * from "./CaptchaPlugin.ts";
/** Have-I-Been-Pwned compromised-password checks. */
export * from "./HaveIBeenPwned.ts";
/** Records the sign-in method into session attributes (last-login-method). */
export * from "./LastLoginMethodPlugin.ts";
/** IP-keyed rate limiting (sign-in, sign-up, password-reset) using the ClientIp service. */
export * from "./IpRateLimitPlugin.ts";
/** HTTP layer: makeAuthWebHandler, makeAuthClient, wire types. */
export * as Http from "./Http.ts";
