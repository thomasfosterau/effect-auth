/**
 * Effect Auth - Authentication and Authorization library for Effect
 *
 * A generic authentication and authorization library following guidelines from
 * Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
 * for flexible, composable authentication flows.
 */

/** Core domain types. */
export * from "./Types.js";

/** Tagged errors raised across the library. */
export * from "./Errors.js";

/** Effect `Request` definitions for auth operations. */
export * from "./Requests.js";

/** Password hashing (following Oslo patterns). */
export * from "./Password.js";

/** Session management (following Lucia/Copenhagen guidelines). */
export * from "./Session.js";

/** Request resolvers wiring stores to requests. */
export * from "./Resolvers.js";

/** Authorization primitives. */
export * from "./Authorization.js";

/** Permission value helpers (parse/format/wildcard matching). */
export * from "./Permission.js";

/** In-memory role store with hierarchy (RBAC). */
export * from "./Rbac.js";

/** OAuth-style scope helpers. */
export * from "./Scope.js";

/** OTP utilities (TOTP and HOTP, following Oslo patterns). */
export * from "./Otp.js";

/** WebAuthn (passkey authentication). */
export * from "./WebAuthn.js";

/** OAuth 2.0 / OIDC (inspired by BetterAuth). */
export * from "./OAuth.js";

/** Email verification (inspired by BetterAuth). */
export * from "./EmailVerification.js";

/** Rate limiting (inspired by BetterAuth). */
export * from "./RateLimit.js";

/** Email and password authentication flows. */
export * from "./EmailPassword.js";

/** Password reset flows. */
export * from "./PasswordReset.js";

/** User service primitive. */
export * from "./User.js";

/** High-level auth lifecycle orchestration. */
export * from "./AuthLifecycle.js";

/** Typed, composable hooks/plugin system. */
export * from "./Hooks.js";

/** Example plugins built on the hooks system. */
export * from "./plugins/index.js";

/**
 * HTTP protocol (optional; requires the `effect/unstable/httpapi` modules).
 * Exposed under the `Http` namespace, e.g. `Auth.Http.makeAuthWebHandler`.
 */
export * as Http from "./Http.js";

export {
  /** Re-export of `Effect` from `effect`. */
  Effect,
  /** Re-export of `Context` from `effect`. */
  Context,
  /** Re-export of `Layer` from `effect`. */
  Layer,
  /** Re-export of `RequestResolver` from `effect`. */
  RequestResolver,
} from "effect";
