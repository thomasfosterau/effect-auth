/**
 * Effect Auth - Authentication and Authorization library for Effect
 * 
 * A generic authentication and authorization library following guidelines from
 * Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
 * for flexible, composable authentication flows.
 */

// Core types
export * from "./types.js"
export * from "./errors.js"
export * from "./requests.js"

// Password hashing (following Oslo patterns)
export * from "./password.js"
export * from "./password-traits.js"

// Session management (following Lucia/Copenhagen guidelines)
export * from "./session.js"

// Request resolvers
export * from "./resolvers.js"

// Authorization
export * from "./authorization.js"

// OTP utilities (TOTP and HOTP, following Oslo patterns)
export * from "./otp.js"

// WebAuthn (passkey authentication)
export * from "./webauthn-types.js"
export * from "./webauthn.js"

// OAuth 2.0 / OIDC (inspired by BetterAuth)
export * from "./oauth-types.js"
export * from "./oauth.js"

// Email verification (inspired by BetterAuth)
export * from "./email-verification-types.js"
export * from "./email-verification.js"

// Rate limiting (inspired by BetterAuth)
export * from "./rate-limit-types.js"
export * from "./rate-limit.js"

// Re-export commonly used Effect types
export { Effect, Context, Layer, RequestResolver } from "effect"
