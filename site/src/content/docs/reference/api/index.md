---
title: "index"
description: "API reference for the index module."
---

## index overview

Effect Auth - Authentication and Authorization library for Effect

A generic authentication and authorization library following guidelines from
Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
for flexible, composable authentication flows.

---

<h2 class="text-delta">Table of contents</h2>

- [exports](#exports)
  - [From "./AccountManagement.js"](#from-accountmanagementjs)
  - [From "./Admin.js"](#from-adminjs)
  - [From "./Anonymous.js"](#from-anonymousjs)
  - [From "./ApiKey.js"](#from-apikeyjs)
  - [From "./AuthLifecycle.js"](#from-authlifecyclejs)
  - [From "./Authorization.js"](#from-authorizationjs)
  - [From "./DeviceAuthorization.js"](#from-deviceauthorizationjs)
  - [From "./EmailOtp.js"](#from-emailotpjs)
  - [From "./EmailPassword.js"](#from-emailpasswordjs)
  - [From "./EmailVerification.js"](#from-emailverificationjs)
  - [From "./Errors.js"](#from-errorsjs)
  - [From "./GoogleOneTap.js"](#from-googleonetapjs)
  - [From "./Hooks.js"](#from-hooksjs)
  - [From "./Http.js"](#from-httpjs)
  - [From "./Jwt.js"](#from-jwtjs)
  - [From "./KeyValueStores.js"](#from-keyvaluestoresjs)
  - [From "./MagicLink.js"](#from-magiclinkjs)
  - [From "./OAuth.js"](#from-oauthjs)
  - [From "./OidcProvider.js"](#from-oidcproviderjs)
  - [From "./Organization.js"](#from-organizationjs)
  - [From "./Otp.js"](#from-otpjs)
  - [From "./Password.js"](#from-passwordjs)
  - [From "./PasswordReset.js"](#from-passwordresetjs)
  - [From "./Permission.js"](#from-permissionjs)
  - [From "./PhoneOtp.js"](#from-phoneotpjs)
  - [From "./RateLimit.js"](#from-ratelimitjs)
  - [From "./RateLimitPersistence.js"](#from-ratelimitpersistencejs)
  - [From "./Rbac.js"](#from-rbacjs)
  - [From "./Requests.js"](#from-requestsjs)
  - [From "./Resolvers.js"](#from-resolversjs)
  - [From "./Scope.js"](#from-scopejs)
  - [From "./Session.js"](#from-sessionjs)
  - [From "./Siwe.js"](#from-siwejs)
  - [From "./Sso.js"](#from-ssojs)
  - [From "./TwoFactor.js"](#from-twofactorjs)
  - [From "./Types.js"](#from-typesjs)
  - [From "./User.js"](#from-userjs)
  - [From "./Username.js"](#from-usernamejs)
  - [From "./WebAuthn.js"](#from-webauthnjs)
  - [From "./plugins/index.js"](#from-pluginsindexjs)
- [utils](#utils)
  - [Context](#context)
  - [Effect](#effect)
  - [Layer](#layer)
  - [RequestResolver](#requestresolver)

---

# exports

## From "./AccountManagement.js"

Verification-gated email change and self-service account deletion.

**Signature**

```ts
export * from "./AccountManagement.js";
```

## From "./Admin.js"

Admin tooling: user management, bans, impersonation.

**Signature**

```ts
export * from "./Admin.js";
```

## From "./Anonymous.js"

Anonymous (guest) sign-in with account linking.

**Signature**

```ts
export * from "./Anonymous.js";
```

## From "./ApiKey.js"

API keys (hashed at rest, permissions, quotas, rate limits).

**Signature**

```ts
export * from "./ApiKey.js";
```

## From "./AuthLifecycle.js"

High-level auth lifecycle orchestration.

**Signature**

```ts
export * from "./AuthLifecycle.js";
```

## From "./Authorization.js"

Authorization primitives.

**Signature**

```ts
export * from "./Authorization.js";
```

## From "./DeviceAuthorization.js"

Device authorization grant (RFC 8628) for input-constrained devices.

**Signature**

```ts
export * from "./DeviceAuthorization.js";
```

## From "./EmailOtp.js"

Email OTP sign-in and verification codes.

**Signature**

```ts
export * from "./EmailOtp.js";
```

## From "./EmailPassword.js"

Email and password authentication flows.

**Signature**

```ts
export * from "./EmailPassword.js";
```

## From "./EmailVerification.js"

Email verification (inspired by BetterAuth).

**Signature**

```ts
export * from "./EmailVerification.js";
```

## From "./Errors.js"

Tagged errors raised across the library.

**Signature**

```ts
export * from "./Errors.js";
```

## From "./GoogleOneTap.js"

Google One Tap sign-in (verifies the credential id_token against Google's JWKS).

**Signature**

```ts
export * from "./GoogleOneTap.js";
```

## From "./Hooks.js"

Typed, composable hooks/plugin system.

**Signature**

```ts
export * from "./Hooks.js";
```

## From "./Http.js"

HTTP protocol (optional; requires the `effect/unstable/httpapi` modules).
Exposed under the `Http` namespace, e.g. `Auth.Http.makeAuthWebHandler`.

**Signature**

```ts
export * as Http from "./Http.js";
```

## From "./Jwt.js"

JWT issuance and verification (ES256/EdDSA) with JWKS.

**Signature**

```ts
export * from "./Jwt.js";
```

## From "./KeyValueStores.js"

KeyValueStore-backed layers for the ephemeral stores (OAuth state,
WebAuthn challenges, rate limits, tokens/OTPs, pending two-factor).
Back them with `effect/unstable/persistence` KeyValueStore layers
(in-memory, file system, Redis, ...).

**Signature**

```ts
export * from "./KeyValueStores.js";
```

## From "./MagicLink.js"

Magic link (passwordless email) sign-in.

**Signature**

```ts
export * from "./MagicLink.js";
```

## From "./OAuth.js"

OAuth 2.0 / OIDC (inspired by BetterAuth).

**Signature**

```ts
export * from "./OAuth.js";
```

## From "./OidcProvider.js"

OIDC provider: act as an OpenID Connect identity provider.

**Signature**

```ts
export * from "./OidcProvider.js";
```

## From "./Organization.js"

Organizations: members, invitations, and role-based org permissions.

**Signature**

```ts
export * from "./Organization.js";
```

## From "./Otp.js"

OTP utilities (TOTP and HOTP, following Oslo patterns).

**Signature**

```ts
export * from "./Otp.js";
```

## From "./Password.js"

Password hashing (following Oslo patterns).

**Signature**

```ts
export * from "./Password.js";
```

## From "./PasswordReset.js"

Password reset flows.

**Signature**

```ts
export * from "./PasswordReset.js";
```

## From "./Permission.js"

Permission value helpers (parse/format/wildcard matching).

**Signature**

```ts
export * from "./Permission.js";
```

## From "./PhoneOtp.js"

Phone number (SMS OTP) sign-in and phone verification.

**Signature**

```ts
export * from "./PhoneOtp.js";
```

## From "./RateLimit.js"

Rate limiting (inspired by BetterAuth).

**Signature**

```ts
export * from "./RateLimit.js";
```

## From "./RateLimitPersistence.js"

RateLimiter facade backed by `effect/unstable/persistence` (+ Redis path).

**Signature**

```ts
export * from "./RateLimitPersistence.js";
```

## From "./Rbac.js"

In-memory role store with hierarchy (RBAC).

**Signature**

```ts
export * from "./Rbac.js";
```

## From "./Requests.js"

Effect `Request` definitions for auth operations.

**Signature**

```ts
export * from "./Requests.js";
```

## From "./Resolvers.js"

Request resolvers wiring stores to requests.

**Signature**

```ts
export * from "./Resolvers.js";
```

## From "./Scope.js"

OAuth-style scope helpers.

**Signature**

```ts
export * from "./Scope.js";
```

## From "./Session.js"

Session management (following Lucia/Copenhagen guidelines).

**Signature**

```ts
export * from "./Session.js";
```

## From "./Siwe.js"

Sign-In With Ethereum (EIP-4361); verifier implemented by @effect-auth/siwe.

**Signature**

```ts
export * from "./Siwe.js";
```

## From "./Sso.js"

Enterprise SSO: OIDC relying party with email-domain routing.

**Signature**

```ts
export * from "./Sso.js";
```

## From "./TwoFactor.js"

Two-factor authentication (TOTP + backup codes).

**Signature**

```ts
export * from "./TwoFactor.js";
```

## From "./Types.js"

Effect Auth - Authentication and Authorization library for Effect

A generic authentication and authorization library following guidelines from
Lucia, Copenhagen, and Oslo projects. Uses Effect's Request/Resolver pattern
for flexible, composable authentication flows.

**Signature**

```ts
export * from "./Types.js";
```

## From "./User.js"

User service primitive.

**Signature**

```ts
export * from "./User.js";
```

## From "./Username.js"

Username (username + password) sign-in.

**Signature**

```ts
export * from "./Username.js";
```

## From "./WebAuthn.js"

WebAuthn (passkey authentication).

**Signature**

```ts
export * from "./WebAuthn.js";
```

## From "./plugins/index.js"

Example plugins built on the hooks system.

**Signature**

```ts
export * from "./plugins/index.js";
```

# utils

## Context

Re-export of `Context` from `effect`.

**Signature**

```ts
export declare const Context: typeof import("effect/dist/Context");
```

## Effect

Re-export of `Effect` from `effect`.

**Signature**

```ts
export declare const Effect: typeof import("effect/dist/Effect");
```

## Layer

Re-export of `Layer` from `effect`.

**Signature**

```ts
export declare const Layer: typeof import("effect/dist/Layer");
```

## RequestResolver

Re-export of `RequestResolver` from `effect`.

**Signature**

```ts
export declare const RequestResolver: typeof import("effect/dist/RequestResolver");
```
