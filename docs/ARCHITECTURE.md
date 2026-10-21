# Effect Auth Architecture

## Overview

Effect Auth is a generic, type-safe authentication and authorization library for [Effect](https://effect.website/) v4, following best practices from Lucia, the Copenhagen Book, Oslo, and BetterAuth.

The settled API conventions — naming, export shapes, store contracts, error taxonomy — are recorded with rationale in [DESIGN.md](./DESIGN.md). This document describes how the pieces fit together today.

## Core Principles

1. **Services & Layers**: every feature is an Effect `Context.Service` provided
   by a Layer — access with `yield* Auth.X`, provide with `Auth.X.layer(config)`.
2. **Type-Safe**: schema'd domain models and precise tagged-error unions.
3. **Composable**: features are independent layers; provide only what you use.
4. **Storage-Agnostic**: bring your own store implementations (or use
   `@thomasfosterau/effect-auth-sql`, `@thomasfosterau/effect-auth-alchemy`, or the built-in KeyValueStore
   layers).
5. **Secure by Default**: timing-safe comparisons, high-entropy tokens,
   HttpOnly/Secure cookies, trusted-origin CSRF checks, anti-enumeration
   responses.
6. **Minimal dependencies**: the core library depends on `effect` only (plus
   `node:crypto` for the three primitives it doesn't cover — see Dependencies
   below). Native or third-party dependencies live in companion packages.

## The service pattern

Each core module ships a class-style `Context.Service`, plus a module-scoped
low-level constructor:

```ts
// 1. The service class — tag, name, and canonical layer in one. No separate
//    `*Shape` interface: implementors reference `typeof SessionService.Service`.
export class SessionService extends Context.Service<
  SessionService,
  { readonly createSession: (...) => Effect<...>; ... }
>()("@effect-auth/SessionService") {
  static readonly make = make;
  static readonly layer = (config: Types.SessionConfig) =>
    Layer.effect(SessionService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// 2. The module-scoped constructor, for embedding in custom layers. Stores,
//    Hooks, and Crypto are resolved once here — methods on the returned
//    object carry only the error channel (R = never).
export const make = (config: Types.SessionConfig) =>
  Effect.gen(function* () {
    const sessionStore = yield* SessionStore;
    const userStore = yield* UserStore;
    const hooks = yield* Hooks;
    const crypto = yield* Crypto.Crypto;
    return { createSession: Effect.fn("SessionService.createSession")((...) => ...), ... };
  });
```

Canonical usage:

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const sessions = yield* Auth.SessionService;
  const session = yield* sessions.createSession(userId);
  return yield* sessions.validateSession(session.id);
});

const layer = Auth.SessionService.layer(sessionConfig).pipe(
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

- `X` is both the value you `yield*` and the tag you provide with
  `Layer.succeed(Auth.X)(impl)`. There is no separate `XShape` interface — an
  implementation's type is `typeof X.Service` (`const store: typeof
  Auth.SessionStore.Service = {...}`).
- Store/hook/session dependencies are resolved **once, at Layer construction**
  (`Auth.X.layer(config)`), not threaded through every method call — method
  signatures on the returned service carry only the error channel (`R =
  never`). Callers wire store layers into the service layer instead of
  providing stores per call.
- `SessionService.layer` composes `PlatformCrypto.layer` (the default
  `Crypto.Crypto` implementation) internally, so consumers don't provide
  `Crypto` themselves unless they want to override it.
- Constructors are module-scoped `make`/`layer` exports, not
  `makeFooService`/`FooServiceLayer` — disambiguate with a namespace import
  (`EmailPassword.make(config)`) when working inside the package; `X.layer`
  covers the common case from the public API.

## Module map (`src/`)

The package root (`src/`) holds the core spine plus flat, non-clustered
feature modules; related modules are grouped into lowercase cluster
directories, each with its own `index.ts` barrel and matching
`effect-auth/<cluster>` subpath export.

- **Foundations** (root): `Types.ts` (schema'd `User`, `Session`,
  `SessionConfig`, …), `Errors.ts` (shared tagged errors), `Hooks.ts`
  (hooks/plugin system), `TokenHash.ts`, `Cipher.ts`, `Identifier.ts`,
  `Messages.ts`, `PlatformCrypto.ts` (default `Crypto.Crypto` layer),
  `Observability.ts`.
- **Session management** (root, flat — the spine nearly every feature module
  depends on, so it is not a cluster): `SessionService.ts`, `SessionStore.ts`,
  `UserStore.ts`, `TrustedDevice.ts`, plus `SessionContext.ts`,
  `SessionResolution.ts` and `SessionCookies.ts` (namespaced at the root:
  app-edge session resolution and cookie naming). Exported flat from the package root
  (`Auth.SessionService`, `Auth.SessionStore`, `Auth.UserStore`,
  `Auth.TrustedDeviceStore`, …); `TrustedDevice.ts` is additionally namespaced
  as `Auth.TrustedDevice` so its generic `make`/`gate` stay qualified. There is
  no `Auth.Session` namespace — `Types.ts` already owns that name for the flat
  `Session` record.
- **`email/` cluster**: `EmailAddress.ts`, `EmailOtp.ts`, `EmailPassword.ts`,
  `EmailVerification.ts`.
- **`password/` cluster**: `Password.ts` (PBKDF2/scrypt hashers,
  multi-algorithm verifier), `PasswordReset.ts`, `HaveIBeenPwned.ts`. Argon2id
  lives in the separate `effect-auth-argon2` package.
- **Authorization** (root, flat — a first-class feature, not a cluster): the
  policy kernel `Entity.ts` / `Condition.ts` / `Policy.ts` /
  `AuthorizationModel.ts` / `PolicyStore.ts` (namespaced at the root as
  `Auth.Entity`, `Auth.Policy`, … because their member names are generic),
  the `Authorizer.ts` shell, `System.ts` (non-human principals: the reserved
  `System` entity type, provided and granted explicitly, [ADR 0019](adr/0019-system-principals.md)),
  `Protected.ts` (schema-embedded field guards),
  `OrganizationEntities.ts` (the organization → entity-graph bridge), and
  `Rbac.ts` + `Permission.ts` (RBAC authoring sugar and the
  `"resource:action"` vocabulary it is written in), and `Ladder.ts` (an ordered
  role ladder with named capability axes — import-free, also published as the
  `./ladder` subpath for browser UX gates; `Policy.roleAtLeast` compiles an
  axis into a declarative policy), and `Guard.ts` (the zero-IO gates,
  predicates and capability hooks over an application-declared viewer — the
  kernel's fast path over a slice built from facts the caller holds; defines
  `Unauthorized` / `Forbidden`), and `OwnedAccess.ts` (owned-material reads:
  three-state visibility plus drafts, the fail-closed `IsFollower` seam, the
  per-row `canView` and the per-request `readScope` — rendered as SQL by
  `effect-auth-drizzle`'s `ownedListFilter`), and `Cacheability.ts` (the two
  viewer-less-cache questions — may this representation be served to anyone,
  and must this viewer bypass the cache for freshness — plus the
  `private, no-store` rule). Route-level gating lives in
  `http/AuthorizationMiddleware.ts`.

  **There is one authorization model** ([ADR 0018](adr/0018-one-authorization-kernel.md)).
  The kernel is it; everything else is a projection of, or a way of authoring
  for, that kernel — `Protected.ts` is its data-boundary projection, a read
  scope is its set-shaped projection, and `Rbac.ts` compiles a flat
  role/permission configuration into `DeclarativePolicy` values plus the
  principal → role entity fragment. No module evaluates authorization
  independently of `Policy.decide`. (`Ladder.hasAtLeast` is the comparison a
  ladder condition is compiled from, exported for UX gates and per-viewer
  `meta`; a test pins it to the kernel's answer, and it is never the gate.)

- **`oauth/` cluster**: `OAuth.ts` (providers + PKCE), `Scope.ts`.
- **`plugins/` cluster**: `AccountLockout.ts`, `Audit.ts`, `Captcha.ts`,
  `IPRateLimit.ts`, `LastLoginMethod.ts`, `NormalizeEmail.ts`, `RateLimit.ts`
  — first-party Hooks plugins (exported values keep the `*Plugin` suffix,
  e.g. `AuditPlugin`, even though the file names dropped it).
- **`http/` cluster** (also the `Auth.Http` namespace): `HttpApiSchema.ts`
  (wire schemas + HTTP error types), `HttpApi.ts` (the typed `AuthApi`
  contract), `HttpServer.ts` (handlers + mountable web handler),
  `HttpClient.ts` (typed Effect client derived from the contract),
  `HttpMiddleware.ts` (`AuthMiddleware`/`OptionalAuthMiddleware` for
  consumer apps), plus `SessionCookieCache.ts` (signed session-data cookie,
  re-exported here from its root file).
- **`multifactor/` cluster** (also the `Auth.MultiFactor` namespace):
  `MultiFactor.ts` (TOTP + backup codes, integrating into password sign-in
  via the `SecondFactorGate` seam), `OtpSecondFactor.ts` (OTP-based
  alternative second-factor gate), `WebAuthn.ts` (passkeys, merged from
  `WebAuthnService.ts`), `Otp.ts` (RFC 6238/4226 TOTP/HOTP primitives).
- **Sign-in methods** (root, not yet clustered): `Username.ts`,
  `MagicLink.ts`, `PhoneOtp.ts`, `Anonymous.ts`, `Sso.ts` (OIDC relying
  party), `GoogleOneTap.ts`, `DeviceAuthorization.ts` (RFC 8628).
- **Account lifecycle** (root): `AuthLifecycle.ts` (sign-up/sign-in
  orchestration), `AccountManagement.ts` (email change / account deletion).
- **Platform features** (root): `Organization.ts`, `Admin.ts`, `ApiKey.ts`,
  `Jwt.ts` (ES256/EdDSA + JWKS), `OidcProvider.ts` (act as an OIDC identity
  provider), `RateLimit.ts`/`RateLimitPersistence.ts`, `ClientIP.ts`,
  `OneTimeToken.ts`, `Scim.ts` (SCIM 2.0, see
  [guides/scim.md](guides/scim.md)), `Saml.ts` (the `SamlVerifier` seam that
  `effect-auth-saml` implements), `Delivery.ts` (the `EmailSender` /
  `SmsSender` seams the delivery adapters implement).
- **Storage helpers** (root): `KeyValueStores.ts` — layers implementing the
  ephemeral stores (OAuth state, WebAuthn challenges, rate limits,
  tokens/OTPs, pending multi-factor) over `effect/persistence`
  `KeyValueStore` (in-memory, file system, Redis, …).

Every cluster namespace is also re-exported from the package root (`Auth.Email`,
`Auth.Http`, `Auth.OAuth`, `Auth.Password`, `Auth.Plugins`,
`Auth.MultiFactor`), so `import * as Auth from "@thomasfosterau/effect-auth"` reaches the
whole surface; the per-cluster subpaths (`effect-auth/email`, `/http`,
`/oauth`, `/password`, `/plugins`, `/multifactor`) exist for
consumers who want a narrower import.

## Stores

Users persist state by implementing plain store interfaces (DESIGN.md D3):

- Stores are **dumb persistence**: lookups return `X | null` when a row may legitimately be absent; services convert misses into typed domain errors.
- The store error channel is `AuthError` (infrastructure failure only).
- Vocabulary: `create`, `get`, `getBy<Key>`, `list()`/`listBy<Key>` (arrays), `update`, `upsert`, `delete`, `deleteBy<Key>`.

## Errors

Two mechanisms, by boundary (DESIGN.md D4):

- **Domain errors** are `Data.TaggedError` classes — shared ones in `Errors.ts` (`AuthError`, `InvalidCredentialsError`, `SessionExpiredError`, …), module-local ones (`MultiFactorError`, `OrganizationError`, …) where only one module raises them. `AuthError` means _infrastructure/unexpected_ failure; flow outcomes get specific tags. Nothing subclasses `AuthError` — errors compose in unions, keeping method signatures honest.
- **HTTP boundary errors** are `Schema.TaggedError` classes in `HttpApiSchema.ts` with fixed status codes (400/401/403/404/409/429/500). Handlers in `HttpServer.ts` map domain errors to these per endpoint; `RateLimitError` is always 429, `AuthError` is always 500, and typed flow errors carry the specific statuses (e.g. `EmailInUseError` → 409).

## HTTP protocol

- `HttpApi.ts` defines the full contract with `effect/http-api` — one `auth` group, kebab-case paths (`/sign-in/email-otp`, `/multi-factor/enable`), camelCase operationIds. OpenAPI 3.1 (`Http.getOpenApiSpec()`) and a Scalar reference UI can be served from the same contract (`Http.make({ docs: true })`).
- **404-until-configured**: optional features resolve their service with `Effect.serviceOption`; when the layer isn't provided the endpoint fails `NotFound` — a server only exposes what it configures.
- **Cookies**: HttpOnly, SameSite, `Secure` by default; optional HMAC-signed session-data cache cookie to skip store reads; multi-session and last-login-method helper cookies.
- **CSRF**: a trusted-origin gate runs before any handler — requests with an `Origin` header must match the request origin or the configured `trustedOrigins`; requests without one (curl, server-to-server) pass.
- **Clients**: `HttpClient.ts` derives a full-parity Effect client from the contract (`client.auth.<operationId>`).

## Security Considerations

### Password Security

- PBKDF2-SHA256 with 600,000 iterations (OWASP) by default; scrypt also in core; Argon2id via `@thomasfosterau/effect-auth-argon2` (WASM by default, optional native fast-path); a multi-algorithm verifier supports migration between algorithms.
- Random salt per password; timing-safe comparison; plaintext never stored.

### Session Security

- 160-bit cryptographically secure session IDs; active + idle timeouts; automatic renewal; whole-user invalidation; optional signed session-data cookie with a short TTL.

### Token & Challenge Security

- All bearer tokens — magic-link tokens, email-verification tokens, password-reset tokens, device authorization codes, API keys, and OIDC codes/tokens — are stored as SHA-256 digests (via the shared `hashToken` primitive in `TokenHash.ts`). Only the raw token is delivered to the user; the digest is the store key. OTPs follow the same pattern.
- Lookups and comparisons use constant-time equality (`constantTimeHashEqual`) to prevent timing side-channels.
- All token flows are single-use with expiry; anti-enumeration responses on send/request endpoints.
- WebAuthn: 256-bit challenges with expiry, origin + RP ID verification, counter-based replay protection (ES256/RS256/EdDSA).

### Authorization Security

- Explicit permission checks, role-based access control (RBAC) with hierarchy, OAuth-style scopes; policies fail closed.

### Timing and enumeration

- Password verification is timing-safe inside the hasher. Sign-in does constant work: a decoy hash is computed from the active `PasswordHasher` on the first sign-in and cached, and every attempt verifies against either the stored hash or the decoy, so response time doesn't reveal whether an account exists.
- Session ids are stored as SHA-256 digests and looked up by digest, so the raw id never reaches the store; OTP and OIDC secrets are compared with `constantTimeHashEqual`.

### What the library provides, and what the application must

If you mount the included HTTP API, cookie flags (`HttpOnly`, `Secure`, `SameSite`), trusted-origin CSRF checks, rate limiting (`RateLimiter`) and account lockout (`AccountLockoutPlugin`) are provided. If you use only the headless core, they are yours to implement. Either way the application provides secure store implementations (parameterised queries, encrypted connections) and serves over HTTPS.

Encryption at rest of JWT private keys, OAuth tokens and TOTP secrets is opt-in: leave `JWT_ENCRYPT_PRIVATE_KEY_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET` or `TWO_FACTOR_ENCRYPT_SECRET` unset to keep it off. A variable that is set but empty fails `jwtServiceConfig` / `oauthServiceOptionsConfig` / `multiFactorConfig` at startup with a `ConfigError`, rather than silently storing the data unencrypted. A whitespace-only value counts as empty. Known limitation: an empty secret set together with a sibling variable sharing its prefix (for example `TWO_FACTOR_ENCRYPT_SECRET=""` plus `TWO_FACTOR_ENCRYPT_SECRET_FILE=...`) reads as unset.

### Fail-open vs fail-closed session resolution

An app that resolves the session at its own edge — a SvelteKit `hooks.server.ts`, a Worker
calling an auth service binding — has to decide what a **fault** means. Not "no session": a
fault. The store is down, the binding is unreachable, the call threw.

effect-auth ships both directions and defaults to neither, because the right answer depends on
a property of _your_ app that the library cannot see:

| Helper                              | Fault becomes                                | Use when                                         |
| ----------------------------------- | -------------------------------------------- | ------------------------------------------------ |
| `SessionResolution.resolve`         | a failure in the error channel               | anonymous is **not** the lower-privilege outcome |
| `SessionResolution.resolveFailOpen` | an anonymous request, reported as `degraded` | anonymous **is** the lower-privilege outcome     |

**The precondition for fail-open.** Degrading to anonymous is safe only if anonymous is
strictly less privileged than any signed-in viewer — reads are public, and every write is
separately gated server-side on the resolved viewer. Then a session-service fault costs
signed-in users their personalisation and nothing else.

It is **unsafe**, and an escalation, whenever anonymous is privileged in your app:

- A read path that is public by default and gated _down_ for some viewers (a "shadow-banned
  user sees less than a stranger" rule degrades into the stranger's view).
- A deployment where a missing session means "trusted internal caller" rather than "nobody".
- Any surface where authorization is expressed as "deny if the viewer is X" rather than
  "allow if the viewer is Y" — an absent viewer matches no deny rule.

Fail-closed is not free either: with a `SessionStore` behind a database, _any_ store fault
becomes a site-wide 500, including on routes that never touch auth. Choose deliberately.

**Fail-open must be loud.** Its failure mode is silence — an unreachable session service looks
exactly like a site where nobody happens to be signed in, and stays that way until someone
notices the sign-in rate. `resolveFailOpen` therefore takes a mandatory `onDegraded` callback,
and there is no overload that omits it. Log it, count it, alert on it. The `degraded` outcome
is also emitted on the `effect_auth_session_resolutions_total` counter and as an `auth.outcome`
span attribute, distinct from `anonymous`, precisely so a fault is distinguishable from a quiet
day.

**The cookieless skip is not a fault path.** `SessionResolution.hasSessionCredential` answers
"could this request resolve at all?" from the credential names alone; a request with no
credential is reported as `skipped` and never reaches either resolver. Keep the predicate and
the middleware's cookie name derived from one config (`SessionCookies.cookieNames`) — a
predicate that disagrees with the middleware silently signs users out.

Any design change that would weaken timing-safety, entropy, cookie flags, CSRF/trusted-origin checks, or replay protection is rejected by policy (DESIGN.md ground rules).

## Testing

- Each package's tests run with `vp test` (`vp run -r test:unit` runs them all). Each package's `tsconfig.json` excludes `*.test.ts` (it drives the declaration build), so test files are type-checked by a sibling `tsconfig.test.json` — the same config with the test exclusion dropped — which every package's `check` task runs as a second `tsc --noEmit -p tsconfig.test.json` pass.
- The Effect language service enforces idioms at typecheck time (yieldable errors, single-provide layering, requirement leakage).

## Dependencies

- **Core**: `effect`, and nothing else — the effect-only dependency rule now holds with zero exceptions. The WebAuthn wire formats (CBOR, `clientDataJSON`, authenticator data, attestation objects, COSE public keys) are parsed in-repo by `multifactor/WebAuthnCodec.ts`. Most randomness/digest needs go through the `Crypto.Crypto` service (default implementation: `PlatformCrypto.layer`, backed by the platform Web Crypto API); direct `node:crypto` usage is corralled into exactly three modules — `password/Password.ts` (scrypt), `TokenHash.ts` (`timingSafeEqual`), and `Cipher.ts` (AES-256-GCM, HMAC, SHA-256). Native dependencies never enter core: Argon2id hashing lives in `@thomasfosterau/effect-auth-argon2`.
- **Packages** isolate framework/storage-driver/native peer deps (`-client`, `-sql`, `-drizzle`, `-alchemy`, `-argon2`, `-resend`, `-twilio`, `-saml`, and the four framework bindings) so core stays lean.

## References

- [DESIGN.md](./DESIGN.md) — the settled API decision record
- [guides/better-auth-migration.md](./guides/better-auth-migration.md) — moving an application from Better Auth to effect-auth
- [Lucia](https://lucia-auth.com/) / [Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo](https://github.com/pilcrowonpaper/oslo)
- [BetterAuth](https://www.better-auth.com/) — feature-surface inspiration
- [Effect](https://effect.website/)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 8628 (Device Authorization Grant)
