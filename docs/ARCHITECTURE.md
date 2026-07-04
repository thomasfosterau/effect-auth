# Effect Auth Architecture

## Overview

Effect Auth is a generic, type-safe authentication and authorization library for [Effect](https://effect.website/) v4, following best practices from Lucia, the Copenhagen Book, Oslo, and BetterAuth. It is a Bun-workspaces monorepo: the core library (`effect-auth`, ~44 modules) plus focused companion packages (`@effect-auth/sql`, `@effect-auth/alchemy`).

The settled API conventions — naming, export shapes, store contracts, error taxonomy — are recorded with rationale in [DESIGN.md](./DESIGN.md). This document describes how the pieces fit together.

## Core Principles

1. **Services & Layers**: every feature is an Effect `Context.Service` provided
   by a Layer — access with `yield* Auth.X`, provide with `Auth.X.layer(config)`.
2. **Type-Safe**: schema'd domain models and precise tagged-error unions.
3. **Composable**: features are independent layers; provide only what you use.
4. **Storage-Agnostic**: bring your own store implementations (or use
   `@effect-auth/sql`, `@effect-auth/alchemy`, or the built-in KeyValueStore
   layers).
5. **Secure by Default**: timing-safe comparisons, high-entropy tokens,
   HttpOnly/Secure cookies, trusted-origin CSRF checks, anti-enumeration
   responses.
6. **Minimal dependencies**: the core library depends on `effect` only and uses
   `node:crypto` exclusively for cryptography. Native or third-party
   dependencies live in companion packages.

## The service pattern

Each core module ships the same trio (see DESIGN.md D1):

```ts
// 1. The service shape — the interface store/service implementors reference
export interface SessionManagerShape { readonly createSession: (...) => Effect<...>; ... }

// 2. The service class — tag, name, and canonical layer in one
export class SessionManager extends Context.Service<SessionManager, SessionManagerShape>()(
  "@effect-auth/SessionManager",
) {
  static readonly layer = (config: SessionConfig) =>
    Layer.effect(SessionManager, makeSessionManager(config));
}

// 3. The low-level constructor, for embedding in custom layers
export const makeSessionManager = (config) => Effect.gen(...);
```

Canonical usage:

```ts
import { Effect, Layer } from "effect";
import * as Auth from "effect-auth";

const program = Effect.gen(function* () {
  const sessions = yield* Auth.SessionManager;
  const session = yield* sessions.createSession(userId);
  return yield* sessions.validateSession(session.id);
});

const layer = Auth.SessionManager.layer(sessionConfig).pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      Layer.succeed(Auth.SessionStore)(sessionStore),
      Layer.succeed(Auth.UserStore)(userStore),
      Auth.Hooks.Default,
    ),
  ),
);

await Effect.runPromise(Effect.provide(program, layer));
```

`X` is both the value you `yield*` and the tag you provide; `XShape` is the
structural interface you implement (`const store: Auth.SessionStoreShape =
{...}` / `satisfies Auth.SessionStoreShape`). The former `XServiceTag` names,
`XServiceLayer` constructors, and the `Requests.ts`/`Resolvers.ts`
Request/Resolver surface were removed in the 1.0 normalization (DESIGN.md
D1/D2/D6).

## Module map (`packages/effect-auth/src`)

- **Foundations**: `Types.ts` (schema'd `User`, `Session`, `SessionConfig`, …),
  `Errors.ts` (shared tagged errors), `Password.ts` (PBKDF2/scrypt hashers,
  multi-algorithm verifier), `Session.ts` (`SessionStore`, `UserStore`,
  `SessionManager`), `User.ts`, `Authorization.ts`/`Rbac.ts`/`Permission.ts`/
  `Scope.ts` (RBAC, permission values, OAuth-style scopes), `Otp.ts`
  (RFC 6238/4226 TOTP/HOTP primitives).
- **Sign-in methods**: `EmailPassword.ts`, `Username.ts`, `MagicLink.ts`,
  `EmailOtp.ts`, `PhoneOtp.ts`, `Anonymous.ts`, `WebAuthn.ts` (passkeys),
  `OAuth.ts` (social providers + PKCE), `Sso.ts` (OIDC relying party),
  `GoogleOneTap.ts`, `DeviceAuthorization.ts` (RFC 8628).
- **Account lifecycle**: `AuthLifecycle.ts` (sign-up/sign-in orchestration),
  `EmailVerification.ts`, `PasswordReset.ts`, `AccountManagement.ts`
  (email change / account deletion), `TwoFactor.ts` (TOTP + backup codes,
  integrating into password sign-in via the `SecondFactorGate` seam).
- **Platform features**: `Organization.ts`, `Admin.ts`, `ApiKey.ts`, `Jwt.ts`
  (ES256/EdDSA + JWKS), `OidcProvider.ts` (act as an OIDC identity provider),
  `RateLimit.ts`/`RateLimitPersistence.ts`.
- **Extension**: `Hooks.ts` (typed hooks/plugin system; see
  [HOOKS_DESIGN.md](./HOOKS_DESIGN.md) for the original design rationale) and
  `plugins/` (audit, email normalization, rate limiting, account lockout,
  captcha, Have-I-Been-Pwned, last-login-method).
- **Storage helpers**: `KeyValueStores.ts` — layers implementing the ephemeral
  stores (OAuth state, WebAuthn challenges, rate limits, tokens/OTPs, pending
  two-factor) over `effect/unstable/persistence` `KeyValueStore` (in-memory,
  file system, Redis, …).
- **HTTP** (exported as the `Auth.Http` namespace): `HttpApiSchemas.ts` (wire
  schemas + HTTP error types), `HttpApi.ts` (the typed `AuthApi` contract),
  `HttpServer.ts` (handlers + mountable web handler), `SessionCookieCache.ts`
  (signed session-data cookie), `HttpClient.ts` (typed Effect client derived
  from the contract).

## Stores

Users persist state by implementing plain store interfaces (DESIGN.md D3):

- Stores are **dumb persistence**: lookups return `X | null` when a row may
  legitimately be absent; services convert misses into typed domain errors.
- The store error channel is `AuthError` (infrastructure failure only).
- Vocabulary: `create`, `get`, `getBy<Key>`, `list()`/`listBy<Key>` (arrays),
  `update`, `upsert`, `delete`, `deleteBy<Key>`.

First-party implementations: `@effect-auth/sql` (driver-agnostic, via
`effect/unstable/sql`), `@effect-auth/alchemy` (Cloudflare D1 + Alchemy v2
infra resources), and the KeyValueStore layers in core for ephemeral state.

## Errors

Two mechanisms, by boundary (DESIGN.md D4):

- **Domain errors** are `Data.TaggedError` classes — shared ones in `Errors.ts`
  (`AuthError`, `InvalidCredentialsError`, `SessionExpiredError`, …),
  module-local ones (`TwoFactorError`, `OrganizationError`, …) where only one
  module raises them. `AuthError` means _infrastructure/unexpected_ failure;
  flow outcomes get specific tags. Nothing subclasses `AuthError` — errors
  compose in unions, keeping method signatures honest.
- **HTTP boundary errors** are `Schema.TaggedErrorClass` classes in
  `HttpApiSchemas.ts` with fixed status codes (400/401/403/404/409/429/500).
  Handlers in `HttpServer.ts` map domain errors to these per endpoint;
  `RateLimitError` is always 429, `AuthError` is always 500, and typed flow
  errors carry the specific statuses (e.g. `EmailInUseError` → 409).

## HTTP protocol

- `HttpApi.ts` defines the full contract with `effect/unstable/httpapi` — one
  `auth` group, kebab-case paths (`/sign-in/email-otp`, `/two-factor/enable`),
  camelCase operationIds. OpenAPI 3.1 and a Scalar reference UI can be served
  from the same contract (`makeAuthWebHandler({ docs: true })`).
- **404-until-configured**: optional features resolve their service with
  `Effect.serviceOption`; when the layer isn't provided the endpoint fails
  `NotFound` — a server only exposes what it configures.
- **Cookies**: HttpOnly, SameSite, `Secure` by default; optional HMAC-signed
  session-data cache cookie to skip store reads; multi-session and
  last-login-method helper cookies.
- **CSRF**: a trusted-origin gate runs before any handler — requests with an
  `Origin` header must match the request origin or the configured
  `trustedOrigins`; requests without one (curl, server-to-server) pass.
- **Clients**: `HttpClient.ts` derives a full-parity Effect client from the
  contract (`client.auth.<operationId>`).

## Security Considerations

### Password Security

- PBKDF2-SHA256 with 210,000 iterations (OWASP) by default; scrypt in core;
  Argon2id via `@effect-auth/argon2`; a multi-algorithm verifier supports
  migration between algorithms.
- Random salt per password; timing-safe comparison; plaintext never stored.

### Session Security

- 160-bit cryptographically secure session IDs; active + idle timeouts;
  automatic renewal; whole-user invalidation; optional signed session-data
  cookie with a short TTL.

### Token & Challenge Security

- All bearer tokens — magic-link tokens, email-verification tokens,
  password-reset tokens, device authorization codes, API keys, and OIDC
  codes/tokens — are stored as SHA-256 digests (via the shared `hashToken`
  primitive in `TokenHash.ts`). Only the raw token is delivered to the user;
  the digest is the store key. OTPs follow the same pattern.
- Lookups and comparisons use constant-time equality (`constantTimeHashEqual`)
  to prevent timing side-channels.
- All token flows are single-use with expiry; anti-enumeration responses on
  send/request endpoints.
- WebAuthn: 256-bit challenges with expiry, origin + RP ID verification,
  counter-based replay protection (ES256/RS256/EdDSA).

### Authorization Security

- Explicit permission checks, role-based access control with hierarchy,
  OAuth-style scopes; policies fail closed.

Any design change that would weaken timing-safety, entropy, cookie flags,
CSRF/trusted-origin checks, or replay protection is rejected by policy
(DESIGN.md ground rules).

## Testing

- 490+ core tests plus package suites (SQL storage, client adapters, hashers)
  run with `vp test`; test files typecheck via per-package `tsconfig.test.json`.
- The Effect language service enforces idioms at typecheck time
  (yieldable errors, single-provide layering, requirement leakage).

## Dependencies

- **Core**: `effect` (only runtime dependency), `node:crypto` only.
- **Packages** isolate everything else: `@node-rs/argon2`, `@workos-inc/node`, SQL drivers (dev-only), framework peer deps
  (client).

## References

- [DESIGN.md](./DESIGN.md) — the settled API decision record
- [Lucia](https://lucia-auth.com/) / [Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo](https://github.com/pilcrowonpaper/oslo)
- [BetterAuth](https://www.better-auth.com/) — feature-surface inspiration
- [Effect](https://effect.website/)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 8628 (Device Authorization Grant)
