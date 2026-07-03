/**
 * Effect Auth - Authentication and Authorization library for Effect
 *
 * A generic authentication and authorization library following guidelines from
 * Lucia, Copenhagen, and Oslo projects. Built on Effect's `Context.Service` +
 * `Layer` pattern: access a feature with `yield* Auth.X`, provide it with
 * `Auth.X.layer(config)`, and bring your own stores. See DESIGN.md for the
 * settled API conventions.
 */

/** Core domain types. */
export * from "./Types.js";

/** Tagged errors raised across the library. */
export * from "./Errors.js";

/** Effect `Request` definitions for auth operations. @deprecated Removal planned for 1.0 (DESIGN.md D6). */
export * from "./Requests.js";

/** Password hashing (following Oslo patterns). */
export * from "./Password.js";

/** Session management (following Lucia/Copenhagen guidelines). */
export * from "./Session.js";

/** Request resolvers wiring stores to requests. @deprecated Removal planned for 1.0 (DESIGN.md D6). */
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

/** Enterprise SSO: OIDC relying party with email-domain routing. */
export * from "./Sso.js";

/** Sign-In With Ethereum (EIP-4361); verifier implemented by @effect-auth/siwe. */
export * from "./Siwe.js";

/** Google One Tap sign-in (verifies the credential id_token against Google's JWKS). */
export * from "./GoogleOneTap.js";

/** Email verification (inspired by BetterAuth). */
export * from "./EmailVerification.js";

/** Rate limiting (inspired by BetterAuth). */
export * from "./RateLimit.js";

/** RateLimiter facade backed by `effect/unstable/persistence` (+ Redis path). */
export * from "./RateLimitPersistence.js";

/** Email and password authentication flows. */
export * from "./EmailPassword.js";

/** Magic link (passwordless email) sign-in. */
export * from "./MagicLink.js";

/** Email OTP sign-in and verification codes. */
export * from "./EmailOtp.js";

/** Anonymous (guest) sign-in with account linking. */
export * from "./Anonymous.js";

/** Phone number (SMS OTP) sign-in and phone verification. */
export * from "./PhoneOtp.js";

/** Username (username + password) sign-in. */
export * from "./Username.js";

/** Device authorization grant (RFC 8628) for input-constrained devices. */
export * from "./DeviceAuthorization.js";

/** Two-factor authentication (TOTP + backup codes). */
export * from "./TwoFactor.js";

/** Organizations: members, invitations, and role-based org permissions. */
export * from "./Organization.js";

/** Admin tooling: user management, bans, impersonation. */
export * from "./Admin.js";

/** API keys (hashed at rest, permissions, quotas, rate limits). */
export * from "./ApiKey.js";

/** JWT issuance and verification (ES256/EdDSA) with JWKS. */
export * from "./Jwt.js";

/** OIDC provider: act as an OpenID Connect identity provider. */
export * from "./OidcProvider.js";

/** Password reset flows. */
export * from "./PasswordReset.js";

/** User service primitive. */
export * from "./User.js";

/** Verification-gated email change and self-service account deletion. */
export * from "./AccountManagement.js";

/** High-level auth lifecycle orchestration. */
export * from "./AuthLifecycle.js";

/** Typed, composable hooks/plugin system. */
export * from "./Hooks.js";

/** Example plugins built on the hooks system. */
export * from "./plugins/index.js";

/**
 * KeyValueStore-backed layers for the ephemeral stores (OAuth state,
 * WebAuthn challenges, rate limits, tokens/OTPs, pending two-factor).
 * Back them with `effect/unstable/persistence` KeyValueStore layers
 * (in-memory, file system, Redis, ...).
 */
export * from "./KeyValueStores.js";

/**
 * HTTP protocol (optional; requires the `effect/unstable/httpapi` modules).
 * Exposed under the `Http` namespace, e.g. `Auth.Http.makeAuthWebHandler`.
 */
export * as Http from "./Http.js";

export {
  /** Re-export of `Effect` from `effect`. @deprecated Import from `effect` directly; removal planned for 1.0 (DESIGN.md D9). */
  Effect,
  /** Re-export of `Context` from `effect`. @deprecated Import from `effect` directly; removal planned for 1.0 (DESIGN.md D9). */
  Context,
  /** Re-export of `Layer` from `effect`. @deprecated Import from `effect` directly; removal planned for 1.0 (DESIGN.md D9). */
  Layer,
  /** Re-export of `RequestResolver` from `effect`. @deprecated Import from `effect` directly; removal planned for 1.0 (DESIGN.md D9). */
  RequestResolver,
} from "effect";
