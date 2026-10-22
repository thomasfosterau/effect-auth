# @thomasfosterau/effect-auth

The headless core: sessions, users and identifiers, every sign-in method, multi-factor, OAuth, organizations, admin, API keys, JWT, SSO, SCIM, the OIDC provider and the authorization kernel, as Effect services and layers, plus the optional HTTP tier.

## Boundary

Archetype **Core** (`.fallowrc.json` zone `core`, which may import only `ladder`). Peer: `effect` (`catalog:peers`); no `dependencies` at all. Never a dependency on legation in any field ([docs/BOUNDARY.md](../../docs/BOUNDARY.md)); effect-jsonapi is allowed. Every other package in the workspace builds on this one, so a breaking export change here reaches all twelve.

Layout: flat root modules for the spine (`SessionService`, `SessionStore`, `UserStore`, `Identifier`, `TrustedDevice`, `SessionContext`, `SessionResolution`, `SessionCookies`), the authorization kernel (`Entity`, `Condition`, `Policy`, `AuthorizationModel`, `PolicyStore`, `Authorizer`, `Rbac`, `Permission`, `System`, `Guard`, `OwnedAccess`, `Cacheability`, `Protected`, `OrganizationEntities`, `Ladder`, `LadderSchema`) and the unclustered features (`Organization`, `Admin`, `ApiKey`, `Jwt`, `OidcProvider`, `Sso`, `Saml`, `Scim`, `Delivery`, `KeyValueStores`, `RateLimit`, …). Lowercase cluster directories each have an `index.ts` barrel, a subpath export and a root namespace:

| Subpath         | Directory      | Root namespace     |
| --------------- | -------------- | ------------------ |
| `.`             | `src/index.ts` | `Auth`             |
| `./email`       | `email/`       | `Auth.Email`       |
| `./password`    | `password/`    | `Auth.Password`    |
| `./multifactor` | `multifactor/` | `Auth.MultiFactor` |
| `./oauth`       | `oauth/`       | `Auth.OAuth`       |
| `./plugins`     | `plugins/`     | `Auth.Plugins`     |
| `./http`        | `http/`        | `Auth.Http`        |
| `./ladder`      | `Ladder.ts`    | `Auth.Ladder`      |

`src/testing/` is test support, not exported. A new cluster module is exported from its `index.ts`; a new subpath needs a `package.json` `exports` entry and a `.fallowrc.json` `entry`.

## Invariants

- **`./ladder` imports nothing**, not even `effect`: browser bundles load it. `ModuleGraph.test.ts` pins it; `.fallowrc.json` gives `Ladder.ts` its own zone with no outbound rule.
- **The root barrel must not pull the HTTP tier** (`http/`, `effect/http-api`, effect-jsonapi) into a consumer's graph. Today it does (`export * as Http` in `src/index.ts`) and the `ModuleGraph.test.ts` guard is `it.skip` until #205. Add no other root-reachable import of `effect/http-api`.
- **Services are `Context.Service` classes with a static `layer`**; stores, hooks and `Crypto` are resolved once in the module-scoped `make`, so service methods carry `R = never`. Implementations are typed `typeof X.Service`; there are no `*Shape` interfaces.
- **Stores are dumb persistence**: a lookup returns `X | null` on a miss and fails only with `AuthError` (infrastructure). Services turn a miss into a typed domain error.
- **Errors**: domain errors are `Data.TaggedError` with a stable `code` (`Errors.ts` when two modules raise them, else module-local); HTTP-boundary errors are the `Schema.TaggedError` classes in `http/HttpApiSchema.ts` with fixed statuses (`RateLimitError` → 429, `AuthError` → 500). Nothing subclasses `AuthError`.
- **Bearer secrets are stored as SHA-256 digests** (`hashToken` and its wrappers, ADR-0004): session ids, magic-link, email-verification, password-reset and one-time tokens, device codes, API keys, OIDC codes and tokens, email / phone OTPs, backup codes. The raw value goes to the user once; the digest is the store key.
- **Secrets compare in constant time** with `constantTimeHashEqual` / `timingSafeEqualBytes` (`TokenHash.ts`).
- **Randomness comes from the `Crypto.Crypto` service** (default `PlatformCrypto.layer`, Web Crypto); never `Math.random`. Direct `node:crypto` stays in `password/Password.ts` (scrypt), `TokenHash.ts` and `Cipher.ts`.
- **Session ids are 160 bits** (`crypto.randomBytes(20)` in `SessionService.ts`), with active and idle expiry.
- **Sign-in does constant work**: password verification runs against a cached decoy hash when the account does not exist.
- **One authorization model** (ADR-0018): every decision goes through `Policy.decide`; `Rbac`, `Protected`, `OwnedAccess` read scopes and `Ladder` axes compile to or project the kernel. Default deny, forbid overrides permit. `Ladder.hasAtLeast` is for UX gates, never the gate.
- **System principals are denied by default** (ADR-0019): only a permit whose principal scope names the `System` type can allow one; role permits never match one.
- **404 until configured**: an optional HTTP feature resolves its service with `Effect.serviceOption` and answers `404` when the layer is absent.
- **`Http.make` fails at startup, not per request**, when a configured limit has no `RateLimiter` (`RateLimiterConfigError`) or an IP limit has no client address source (`ClientAddressConfigError`); with `strict: true` it also refuses a `services` build that cannot finish synchronously (`ServicesBuildPendingError`).
- **Optional encryption secrets fail closed when set but empty** (`OptionalSecretConfig.ts`): `JWT_ENCRYPT_PRIVATE_KEY_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET`, `TWO_FACTOR_ENCRYPT_SECRET`.
- **JSDoc `@example`s are type-checked and run** by `vp run docs`: in-memory stores, inline config, no network, no `declare` stubs; failure is a throw or a failed `assert`.
- No change may weaken timing safety, token entropy, cookie flags, the trusted-origin CSRF check or replay protection (DESIGN.md ground rules).

## Terms

- **Credential / Verification / Auth state** — the three entity categories (ADR-0006): a persistent registered means of authenticating (Account, Passkey, ApiKey, MultiFactorEnrollment, TrustedDevice), a single-use artifact proving possession (tokens, OTPs, BackupCode, OAuthState, WebAuthnChallenge, Invitation), and the record of having authenticated (Session, JWT).
- **Account** — a User's link to one Provider; the `credential` provider holds the password hash.
- **Identifier** — a login handle (`email`, `username`, `phone`) in the `IdentifierStore`, unique per `(type, value)`; not a User field (DESIGN.md D12).
- **Hooks / plugin** — `before*` / `after*` hook points; a plugin is a layer composed with `composePlugins` (first-party ones keep the `*Plugin` suffix).
- **Seam** — a service the core declares and an adapter implements: `PasswordHasher`, `EmailSender`, `SmsSender`, `SamlVerifier`, `SecondFactorGate`, `EntityResolver`, `IsFollower`.
- **Principal / entity** — the kernel's typed references (`Type::"id"`); a **system principal** is `System::"<name>"`.
- **Ladder / rung / axis** — an ordered role list, one role per user, and a named "this rung or above" capability.
- **Fail-open / fail-closed resolution** — `SessionResolution.resolveFailOpen` turns a session-service fault into an anonymous request reported as `degraded`; `resolve` fails. Neither is the default.
