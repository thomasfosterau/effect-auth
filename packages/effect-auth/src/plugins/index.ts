/**
 * Example plugins built on the {@link makePlugin} helper. They validate the
 * ergonomics of the hooks API and are usable as-is.
 *
 * @module plugins
 */

/** Structured audit logging of sign-up/sign-in/sign-out (tap hooks). */
export * from "./AuditPlugin.js";

/** Lowercases and trims emails before sign-up/sign-in. */
export * from "./NormalizeEmailPlugin.js";

/** Rate-limits auth operations via the RateLimiter service. */
export * from "./RateLimitPlugin.js";

/** OWASP-style account lockout after repeated failed sign-ins. */
export * from "./AccountLockoutPlugin.js";

/** Captcha verification (Turnstile / reCAPTCHA / hCaptcha) on sign-up/sign-in. */
export * from "./CaptchaPlugin.js";

/** Have-I-Been-Pwned compromised-password checks. */
export * from "./HibpPlugin.js";

/** Records the sign-in method into session attributes (last-login-method). */
export * from "./LastLoginMethodPlugin.js";
