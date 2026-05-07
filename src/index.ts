/**
 * Effect Auth - Authentication and Authorization library for Effect
 * 
 * A generic authentication and authorization library following guidelines from
 * Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
 * for flexible, composable authentication flows.
 */

// Core types
export * from "./Types.js"
export * from "./Errors.js"
export * from "./Requests.js"

// Password hashing (following Oslo patterns)
export * from "./Password.js"

// Session management (following Lucia/Copenhagen guidelines)
export * from "./Session.js"

// Request resolvers
export * from "./Resolvers.js"

// Authorization
export * from "./Authorization.js"

// OTP utilities (TOTP and HOTP, following Oslo patterns)
export * from "./Otp.js"

// WebAuthn (passkey authentication)
export * from "./WebAuthn.js"

// OAuth 2.0 / OIDC (inspired by BetterAuth)
export * from "./OAuth.js"

// Email verification (inspired by BetterAuth)
export * from "./EmailVerification.js"

// Rate limiting (inspired by BetterAuth)
export * from "./RateLimit.js"

// Email and password authentication flows
export * from "./EmailPassword.js"

// Password reset flows
export * from "./PasswordReset.js"

// User service primitive
export * from "./User.js"

// High-level auth lifecycle orchestration
export * from "./AuthLifecycle.js"

// Re-export commonly used Effect types
export { Effect, Context, Layer, RequestResolver } from "effect"
