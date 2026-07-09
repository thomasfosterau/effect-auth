/** Structured audit logging of sign-up/sign-in/sign-out (tap hooks). */
export * from "./Audit.ts";
/** Lowercases and trims emails before sign-up/sign-in. */
export * from "./NormalizeEmail.ts";
/** Rate-limits auth operations via the RateLimiter service. */
export * from "./RateLimit.ts";
/** OWASP-style account lockout after repeated failed sign-ins. */
export * from "./AccountLockout.ts";
/** Captcha verification (Turnstile / reCAPTCHA / hCaptcha) on sign-up/sign-in. */
export * from "./Captcha.ts";
/** Records the sign-in method into session attributes (last-login-method). */
export * from "./LastLoginMethod.ts";
/** IP-keyed rate limiting (sign-in, sign-up, password-reset) using the ClientIP service. */
export * from "./IPRateLimit.ts";
