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
export * from "./Types.ts";

/** Tagged errors raised across the library. */
export * from "./Errors.ts";

/** Token hashing primitives (SHA-256, constant-time compare) shared across all bearer-token flows. */
export * from "./TokenHash.ts";

/** Pluggable i18n / message resolution service. */
export * from "./Messages.ts";

/** Shared utilities (e.g. normalizeEmail). */
export * from "./utils.ts";

/** Password hashing (following Oslo patterns). */
export * from "./Password.ts";

/** Session management (following Lucia/Copenhagen guidelines). */
export * from "./Session.ts";

/** Authorization primitives. */
export * from "./Authorization.ts";

/** Permission value helpers (parse/format/wildcard matching). */
export * from "./Permission.ts";

/** In-memory role store with hierarchy (RBAC). */
export * from "./Rbac.ts";

/** OAuth-style scope helpers. */
export * from "./Scope.ts";

/** OTP utilities (TOTP and HOTP, following Oslo patterns). */
export * from "./Otp.ts";

/** WebAuthn (passkey authentication). */
export * from "./WebAuthn.ts";

/** OAuth 2.0 / OIDC (inspired by BetterAuth). */
export * from "./OAuth.ts";

/** Enterprise SSO: OIDC relying party with email-domain routing. */
export * from "./Sso.ts";

/** Google One Tap sign-in (verifies the credential id_token against Google's JWKS). */
export * from "./GoogleOneTap.ts";

/** Email verification (inspired by BetterAuth). */
export * from "./EmailVerification.ts";

/** Rate limiting (inspired by BetterAuth). */
export * from "./RateLimit.ts";

/** Trusted-proxy aware client IP extraction and per-request ClientIp service. */
export * from "./ClientIp.ts";

/** RateLimiter facade backed by `effect/unstable/persistence` (+ Redis path). */
export * from "./RateLimitPersistence.ts";

/** Email and password authentication flows. */
export * from "./EmailPassword.ts";

/** Magic link (passwordless email) sign-in. */
export * from "./MagicLink.ts";

/** Email OTP sign-in and verification codes. */
export * from "./EmailOtp.ts";

/** Anonymous (guest) sign-in with account linking. */
export * from "./Anonymous.ts";

/** Phone number (SMS OTP) sign-in and phone verification. */
export * from "./PhoneOtp.ts";

/** Username (username + password) sign-in. */
export * from "./Username.ts";

/** Device authorization grant (RFC 8628) for input-constrained devices. */
export * from "./DeviceAuthorization.ts";

/** Two-factor authentication (TOTP + backup codes). */
export * from "./TwoFactor.ts";

/** Trusted-device tokens for skipping second-factor challenges. */
export * from "./TrustedDevice.ts";

/** OTP-based second-factor gate (email / SMS OTP as a second factor). */
export * from "./OtpSecondFactor.ts";

/** Organizations: members, invitations, and role-based org permissions. */
export * from "./Organization.ts";

/** Admin tooling: user management, bans, impersonation. */
export * from "./Admin.ts";

/** API keys (hashed at rest, permissions, quotas, rate limits). */
export * from "./ApiKey.ts";

/** JWT issuance and verification (ES256/EdDSA) with JWKS. */
export * from "./Jwt.ts";

/** OIDC provider: act as an OpenID Connect identity provider. */
export * from "./OidcProvider.ts";

/** Password reset flows. */
export * from "./PasswordReset.ts";

/** User service primitive. */
export * from "./User.ts";

/** Identifier domain: surrogate-keyed email/username/phone credentials. */
export * from "./Identifier.ts";

/** Verification-gated email change and self-service account deletion. */
export * from "./AccountManagement.ts";

/** High-level auth lifecycle orchestration. */
export * from "./AuthLifecycle.ts";

/** Typed, composable hooks/plugin system. */
export * from "./Hooks.ts";

/** Example plugins built on the hooks system. */
export * from "./plugins/index.ts";

/**
 * KeyValueStore-backed layers for the ephemeral stores (OAuth state,
 * WebAuthn challenges, rate limits, tokens/OTPs, pending two-factor).
 * Back them with `effect/unstable/persistence` KeyValueStore layers
 * (in-memory, file system, Redis, ...).
 */
export * from "./KeyValueStores.ts";

/**
 * HTTP protocol (optional; requires the `effect/unstable/httpapi` modules).
 * Exposed under the `Http` namespace, e.g. `Auth.Http.makeAuthWebHandler`.
 */
export * as Http from "./Http.ts";
