/**
 * Example plugins built on the {@link makePlugin} helper. They validate the
 * ergonomics of the hooks API and are usable as-is.
 *
 * @module plugins
 */

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
export * from "./HibpPlugin.ts";

/** Records the sign-in method into session attributes (last-login-method). */
export * from "./LastLoginMethodPlugin.ts";

/** IP-keyed rate limiting (sign-in, sign-up, password-reset) using the ClientIp service. */
export * from "./IpRateLimitPlugin.ts";
