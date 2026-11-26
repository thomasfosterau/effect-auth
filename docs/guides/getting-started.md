# Getting started with the core

How to set up `@thomasfosterau/effect-auth`: the runtimes it supports, a first service over your own stores, the root secret, and what the package exports.

Install the package as its [README](https://github.com/thomasfosterau/effect-auth/blob/trunk/packages/effect-auth/README.md#install) shows.

## Runtimes

The core runs on Node.js 22 or later and on Cloudflare Workers; `/saml` is Node-only. Crypto goes through `effect/crypto` and `effect/jose` over Web Crypto; only the opt-in scrypt verifier takes `node:crypto` (and `Buffer` from `node:buffer`). A Worker needs:

- the **`nodejs_compat`** compatibility flag (on by default from compatibility date 2026-08-04), and
- a **compatibility date of 2023-01-01 or later**.

Outbound requests (the OAuth and OIDC provider endpoints, SSO discovery, Cloudflare Access's key set, Google One Tap's JWKS) go through `effect/http`'s `HttpClient`, so the layers that make them require one: provide `FetchHttpClient.layer`, which works on Workers, Node and in browsers, or a stub in tests. `RemoteJwksVerifier.layer` provides fetch itself; `layerHttpClient` takes yours.

Every outbound request is bounded: 10 seconds for the whole exchange, body included, and a 1 MiB response body (`OutboundHttp.defaultLimits`). Provide `OutboundHttp.OutboundLimits` where the layers are built to change both (Cloudflare Access keeps its own `fetchTimeoutMs`). Redirects are never followed. A provider's error body goes to the log as a warning excerpt, never into an error a client could be shown. A remote key set (Cloudflare Access, `verifyIdToken` inside the OAuth, SSO and One Tap services) is cached per URL; a token naming a `kid` it lacks refetches at most once per 30 seconds, and a failed refetch keeps the keys it had. `RemoteJwksVerifier` uses `effect/jose`'s remote key set, which has its own limits (5 seconds, 128 KiB, a 30-second cooldown) and refuses a redirect too.

SSO connections are held to a strict URL policy by default: the discovery, token, userinfo and JWKS URLs must be `https`, carry no credentials, and name no private, loopback, link-local or internal host (`localhost`, `.local`, `.internal`, single-label names). It is checked when a connection is registered and again before each request. Hosts are checked as written, not resolved, since Workers have no DNS lookup: a public name pointing at a private address passes, so restrict egress at the network too. `SsoConfig.allowPrivateIdpUrls: true` turns the check off for an IdP on a private network.

Argon2id (`Password.argon2idHasherLayer`) is the exception: it derives through Effect's `Kdf` service, which only `NodeCrypto.layerKdf` (`@effect/platform-node` or `-bun`, on Node.js 24.7+ or Bun 1.4+) provides with Argon2id. On Workers use `@thomasfosterau/effect-auth-argon2`.

Password hashing is the costly step on Workers. PBKDF2 at its default 600,000 iterations takes about 75 ms of CPU per hash or verify in workerd, so a sign-in that verifies a password fits a paid plan's CPU limit but not the Free plan's 10 ms; lowering `iterations` trades away resistance to offline cracking. Keep the scrypt verifier (`./scrypt`) off Workers: at its default cost (N = 2^17, r = 8) it needs about 128 MiB, the whole memory of an isolate.

The core never relies on the Node globals `nodejs_compat` sets only from 2024-09-23 (`Buffer`, `process`), so an older date works. Every primitive (PBKDF2 hashing and verification, the opt-in scrypt verifier, `hashToken` and the constant-time comparisons, AES-256-GCM, HMAC, the WebAuthn signature checks, and ES256, EdDSA and RS256 JWS through `effect/jose`, `JwtService` and the Apple client secret) is tested inside a real workerd at 2023-01-01 and at workerd's newest date (`src/Workerd.test.ts`). Releases up to 0.4.0 fail there: ES256 signing and verification on every date, JWT key generation from 2025-12-03, and password hashing, AES-GCM and the WebAuthn checks before 2024-09-23.

## Usage

Implement the store interfaces (or take them from an adapter), provide the service layer, and use the service:

```typescript
import { Effect, Layer, Option } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Stores are "dumb persistence": lookups return `Option.none()` on a miss, and the
// service turns that into a typed `SessionNotFoundError` / `UserNotFoundError`.
// `session.id` arrives already hashed (SHA-256); the raw token never reaches the store.
const sessions = new Map<string, Auth.Session>();
const sessionStore: typeof Auth.SessionStore.Service = {
  create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  get: (id) => Effect.sync(() => Option.fromUndefinedOr(sessions.get(id))),
  // Never creates: a session signed out or revoked since the caller read it stays gone.
  update: (session) =>
    Effect.sync(() => {
      if (sessions.has(session.id)) sessions.set(session.id, session);
      return session;
    }),
  // The sliding refresh: moves only the expiry, never recreates a deleted session.
  touch: (id, touch) =>
    Effect.sync(() => {
      const session = sessions.get(id);
      if (session === undefined || session.expiresAt < touch.lastActivityAt) return Option.none();
      const touched = { ...session, ...touch };
      sessions.set(id, touched);
      return Option.some(touched);
    }),
  delete: (id) => Effect.sync(() => void sessions.delete(id)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
};

// Users carry first-class fields (name, image, createdAt, updatedAt) plus an
// `attributes` bag for app-specific data; email, username and phone are identifiers.
const userStore: typeof Auth.UserStore.Service = {
  get: (id) =>
    Effect.succeedSome({ id, createdAt: new Date(), updatedAt: new Date(), attributes: {} }),
};

const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days, the absolute maximum lifetime
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days idle timeout and renewal window
  },
};
// Both periods must be finite and positive (and `updateAge`, when set, 0 or
// more), or the layer build dies with `SessionConfigError`: a `NaN` from
// an unset `Number(env)` would otherwise issue sessions that never expire.

// Every service class exposes a static `layer`, the canonical way to provide it.
const AuthLive = Auth.SessionService.layer(sessionConfig).pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      Layer.succeed(Auth.SessionStore)(sessionStore),
      Layer.succeed(Auth.UserStore)(userStore),
      Auth.Hooks.Default, // no-op hooks; compose plugins here instead
    ),
  ),
);

const program = Effect.gen(function* () {
  const service = yield* Auth.SessionService;
  // `token` is the raw token: put it in the cookie. `session.id` is its hash.
  const { token } = yield* service.createSession("user-123", { ip: "127.0.0.1" });
  const { user } = yield* service.validateSession(token);
  return user.id;
});

console.log(await Effect.runPromise(Effect.provide(program, AuthLive)));
```

Most services expose their `make(config)` constructor for embedding in your own layers when the static `X.layer(config)` isn't flexible enough:

```typescript
import { Effect, Layer } from "effect";
import { SessionService, type SessionConfig } from "@thomasfosterau/effect-auth";

const sessionConfig: SessionConfig = {
  sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
};

// Still requires SessionStore, UserStore, Hooks and SecureRandom, like `SessionService.layer`.
const customSessionLayer = Layer.effect(
  SessionService,
  Effect.gen(function* () {
    // ...acquire resources, read config, etc.
    return yield* SessionService.make(sessionConfig);
  }),
);
export { customSessionLayer };
```

### The session hooks

No hook ever sees a raw session token. `beforeValidateSession` (fired by `SessionService.validateSession`), `beforeSignOut` (fired by `invalidateSession`, so by every sign-out) and `afterSignOut` receive a `SessionRef`, `{ sessionId }`, whose `sessionId` is the session's stored id: `hashToken(token)`, the SHA-256 digest that `session.id` carries everywhere else. A plugin can log it or match it against `session.id` without ever holding the credential.

The two `before*` session hooks are observe-or-deny. A plugin refuses the validation or the sign-out by failing, and the operation stops with that error (the session is not deleted on a refused sign-out). Otherwise the services read nothing back: the token the client presented decides which session is looked up or deleted, so a hook cannot rewrite it or redirect the operation to another session.

## What's included

- **Sessions:** active and idle expiry with renewal, hashed session ids, an optional HMAC-signed session-data cookie (`cookie.cache`), multi-session, trusted devices.
- **Passwords:** PBKDF2-SHA256 (600,000 iterations, the default, over `effect/crypto`'s `Kdf`), an opt-in Node-only scrypt verifier for older hashes (`@thomasfosterau/effect-auth/scrypt`), a multi-algorithm verifier with rehash on sign-in, password reset, Have I Been Pwned checks. Argon2id over Effect's `Kdf` (`Password.argon2idHasherLayer`, with `NodeCrypto.layerKdf` on Node.js 24.7+ or Bun 1.4+); on Cloudflare Workers, which has no native Argon2, use `@thomasfosterau/effect-auth-argon2`.
- **Sign-in methods:** email and password, username (case-insensitive uniqueness), magic link, email OTP, phone (SMS) OTP with a pluggable E.164 normalizer, anonymous guests (`isAnonymousUser`, upgraded on sign-up through a `linkAccount` callback), Google One Tap, the RFC 8628 device authorization grant, passkeys (WebAuthn).
- **Multi-factor:** TOTP with backup codes integrated into sign-in, an OTP second factor, and the RFC 6238 / RFC 4226 primitives. **Every sign-in method is gated on it:** email and password, username, magic link, email and phone OTP, one-time tokens, the sign-in after an email verification, OAuth, SSO (OIDC and SAML) and Google One Tap each consult the `SecondFactorGate` before issuing a session, and a user it requires a second factor of gets a challenge to redeem instead. Possession of the mailbox, the phone or the IdP account is not enough on its own. To treat a method as sufficient alone (an IdP that enforces its own multi-factor policy, say), provide `Email.exemptFromSecondFactor("sso")`; the exempt list is empty by default. A host that issues a session itself, such as after a passkey assertion, calls `Email.secondFactorChallenge(user, "passkey")` first. Anonymous guests and the device grant (approved from a signed-in session) are not gated.
- **OAuth 2.0 social login:** 20 provider presets (Google, GitHub, Discord, Microsoft, Apple, and more) plus custom providers, PKCE, and a complete sign-in flow with verified-email account linking.
- **Cloudflare Access:** verify the identity Access forwards (`Cf-Access-Jwt-Assertion`, optionally the `CF_Authorization` cookie) against the team's keys, and run as the matching user (see [Cloudflare Access](./sign-in-methods.md#cloudflare-access)).
- **Enterprise:** OIDC and SAML SSO with per-organization connections and JIT provisioning (the SAML XML verification is the Node-only [`/saml` subpath](./saml.md)), SCIM 2.0, and an OIDC provider with RFC 7591 dynamic client registration for MCP clients.
- **Account management:** verification-gated email change and self-service account deletion (single-use tokens, a `beforeDelete` cleanup hook, and every credential, session and identifier of the account deleted with it; see [Deleting a user](./storage.md#deleting-a-user)).
- **Organizations and admin:** members (with deactivation), invitations, teams, per-organization roles and default role (no member grants, defines, redefines or deletes a role, or acts on a member, beyond the permissions their own role carries, nor edits their own role; the default `owner` role is `*:*`), verified email domains with opt-in JIT provisioning; admin ban and impersonation.
- **API keys and JWT:** hashed API keys with permissions and quotas; ES256 / EdDSA JWTs with JWKS, and `RemoteJwksVerifier` for RS256, ES256 and EdDSA tokens against any issuer's JWKS.
- **Authorization:** one policy kernel (`Policy`, `Entity`, `Condition`, `Authorizer`) with RBAC as authoring sugar, schema-embedded field guards (`protectedField`), zero-IO guards and role ladders.
- **Abuse protection:** rate limiting with presets and an optional `effect/persistence` backend (`rateLimiterPersistenceLayer`), per-IP limits, account lockout (`AccountLockoutPlugin`), captcha (Turnstile, reCAPTCHA, hCaptcha).
- **HTTP API:** a typed `effect/http-api` contract served as a mountable Web handler (`Http.make`, or `Http.makeAsync` for services that build asynchronously), with session cookies, trusted-origin CSRF checks, a derived typed client and an OpenAPI 3.1 document (`Http.getOpenApiSpec()`, or `Http.make({ docs: true })` for a Scalar reference page).
- **Hooks:** `before*` / `after*` hook points, composed as plugins with `composePlugins`; first-party plugins include audit logging and a last-login-method hint. Every credential-verifying flow fires `beforeAuthenticate` (see [Abuse protection](./abuse-protection.md#abuse-protection)). No hook ever sees a raw session token: the session hooks get the stored id, its digest (see [The session hooks](#the-session-hooks)).

## Configuration

Every deployment sets one root secret: `AUTH_SECRET`, at least 32 bytes (`openssl rand -hex 32`), read by `RootSecret.layerConfig` (or given to `RootSecret.layer(secret)`), which fails at startup with `RootSecretError` when it is missing or short. Each keyed primitive gets its own key from it through HKDF-SHA256 with a purpose string, so no two share a key: the pepper for email, phone and second-factor OTPs and backup codes (stored as HMAC-SHA256, so a database read alone cannot brute-force a six-digit code), the PKCE `code_verifier` (derived from the OAuth `state`, never stored), and the encryption keys for TOTP secrets, OAuth provider tokens and JWT private keys. Those three are always sealed at rest with AES-256-GCM, bound to the purpose and the row they are stored in, so a ciphertext copied to another row does not open: TOTP secrets and OAuth tokens as `v2.` + base64url with the row as associated data, JWT private keys as a compact JWE (`dir` + `A256GCM`) whose protected header names the key id. `MultiFactorService`, `OtpSecondFactorService`, `EmailOtpService`, `PhoneOtpService`, `OAuthService`, `SsoService` and `JwtService` require `RootSecret`; `Testing.memoryStores` provides a fixed test secret. Raw change-email, account-deletion and pending second-factor tokens, and the OAuth `state`, are stored as SHA-256 digests, as the other bearer tokens are.

`JWT_ENCRYPT_PRIVATE_KEY_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET` and `TWO_FACTOR_ENCRYPT_SECRET` (or `encryptPrivateKey` / `encryptTokens` / `encryptSecret: { secret }`) override the root secret's key for one purpose; the key is derived from the override the same way. A variable that is set but empty (for example `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`) fails `jwtServiceConfig` / `oauthServiceOptionsConfig` / `multiFactorConfig` at startup with a `ConfigError` naming the variable, because Effect rc.118 reads an empty value as absent and would otherwise silently fall back to the root secret's key. A value that is only whitespace (for example `"   "` or a lone newline) counts as empty and fails the same way; a secret with surrounding spaces but other content is accepted unchanged. The check reads the active `ConfigProvider`, so it also applies to map providers. Known limitation: an empty secret set together with a sibling variable sharing its prefix (for example `TWO_FACTOR_ENCRYPT_SECRET=""` plus `TWO_FACTOR_ENCRYPT_SECRET_FILE=...`) is not detected and reads as unset.

Upgrading from a release without the root secret: rows stay readable while they are rewritten. A stored value without the current format's `v2.` prefix is opened with the override secret's earlier cipher when one is set, and is otherwise read as the plaintext an unencrypted deployment wrote; the next write seals it. Backup codes stored under their bare SHA-256 digest still redeem. Email, phone and second-factor OTPs that are live at the upgrade stop verifying (they are minutes old; the user requests a new one), and so do OAuth states, pending second-factor challenges and change-email and account-deletion links issued before it.

## What the root exports

`import * as Auth from "@thomasfosterau/effect-auth"` reaches the whole headless surface. Each cluster is also a subpath export for a narrower import. The HTTP tier, the browser client, SQL storage and SAML are the exception: each is published only as its subpath, so importing the root never pulls in `effect/http-api`, `effect/sql` or `@node-saml/node-saml`:

| Entry                                        | Root namespace     | Contents                                                                                                                                                                              |
| -------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@thomasfosterau/effect-auth`                | `Auth`             | Sessions, users, identifiers, hooks, errors, the authorization kernel, organizations, admin, API keys, JWT, SSO, …                                                                    |
| `@thomasfosterau/effect-auth/email`          | `Auth.Email`       | Email and password sign-in, email verification, email OTP                                                                                                                             |
| `@thomasfosterau/effect-auth/password`       | `Auth.Password`    | `PasswordHasher` (PBKDF2), password reset, `HaveIBeenPwnedPlugin`                                                                                                                     |
| `@thomasfosterau/effect-auth/multifactor`    | `Auth.MultiFactor` | TOTP and backup codes, the OTP second factor, WebAuthn, and the OTP primitives                                                                                                        |
| `@thomasfosterau/effect-auth/oauth`          | `Auth.OAuth`       | `OAuthService`, provider presets, `provider` for custom ones, `generateState`, `generatePKCE`                                                                                         |
| `@thomasfosterau/effect-auth/plugins`        | `Auth.Plugins`     | First-party hooks plugins: account lockout, audit, captcha, IP rate limit, last login method, email normalization                                                                     |
| `@thomasfosterau/effect-auth/http`           | — (subpath only)   | The HTTP contract, the mountable handler (`make`, `makeAsync`), the typed Effect client, `AuthMiddleware`, the authorization middleware, `RemoteSession` (auth as a separate service) |
| `@thomasfosterau/effect-auth/client`         | — (subpath only)   | The browser client over the HTTP contract ([below](./client-reference.md))                                                                                                            |
| `@thomasfosterau/effect-auth/client/atoms`   | — (subpath only)   | The client session as `effect/reactivity` Atoms ([below](./client-reference.md#the-session-atoms-clientatoms))                                                                        |
| `@thomasfosterau/effect-auth/client/testing` | — (subpath only)   | An in-process server fixture and cookie-jar `fetch` for client tests                                                                                                                  |
| `@thomasfosterau/effect-auth/sql`            | — (subpath only)   | Every store contract it covers over `effect/sql`'s `SqlClient`, plus the DDL ([below](./storage.md#sql-storage-sql))                                                                  |
| `@thomasfosterau/effect-auth/saml`           | — (subpath only)   | The `SamlVerifier` over `@node-saml/node-saml`; Node-only ([below](./saml.md))                                                                                                        |
| `@thomasfosterau/effect-auth/scrypt`         | — (subpath only)   | `scryptHasher` and its layer, to verify and rehash scrypt hashes; Node-only                                                                                                           |
| `@thomasfosterau/effect-auth/ladder`         | —                  | An ordered role ladder for browser UX gates; imports only `effect/Option`                                                                                                             |
| `@thomasfosterau/effect-auth/testing`        | —                  | Test helpers: run as a fixture principal, fixture users, guard assertions, store conformance suites                                                                                   |

The package root also carries these namespaces, each a module whose member names are too generic to sit flat:

| Namespace                                                                                     | Contents                                                                                                                                                   |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Auth.Entity`, `Auth.Condition`, `Auth.Policy`, `Auth.AuthorizationModel`, `Auth.PolicyStore` | The policy kernel: entity references, conditions, declarative and custom policies, `decide`, model validation, stored policies and templates               |
| `Auth.Rbac`                                                                                   | Role/permission configuration compiled to kernel policies and the principal → role entity graph                                                            |
| `Auth.System`                                                                                 | Non-human principals: `declaration`, `provide`, `grant`, `ref`                                                                                             |
| `Auth.Guard`                                                                                  | Zero-IO gates, predicates and capability hooks over a resolved viewer (`Unauthorized` / `Forbidden` are also flat)                                         |
| `Auth.OwnedAccess`                                                                            | Owned-material visibility: `make` (per-row `canView`, per-request `readScope`), the `IsFollower` and `IsMember` seams                                      |
| `Auth.ReferenceAccess`                                                                        | Ownerless reference rows on the same visibility axis: `make` (per-row `canView`, the owned `readScope` shape)                                              |
| `Auth.Cacheability`                                                                           | Whether a representation may be served from a viewer-less cache; `publicReach` / `publicReachByType` derive which types are public, for a drift-guard test |
| `Auth.Ladder`, `Auth.LadderSchema`                                                            | The ordered role ladder and its rungs as a `Schema`                                                                                                        |
| `Auth.OrganizationEntities`                                                                   | Organizations, members and roles as kernel entities                                                                                                        |
| `Auth.SessionContext`                                                                         | Layers and accessors for an already-resolved session (`CurrentSession`, `CurrentUser`, `MaybeCurrentSession` are also flat)                                |
| `Auth.SessionResolution`                                                                      | Session resolution at an app's own edge: `hasSessionCredential`, `resolve`, `resolveFailOpen`                                                              |
| `Auth.SessionCookies`                                                                         | Cookie naming shared by the middleware and the edge predicates                                                                                             |
| `Auth.TrustedDevice`                                                                          | Trusted-device `make` / `gate` (the store, service and config are also flat)                                                                               |

Flat root exports beyond those also include the delivery seams (`EmailSender`, `SmsSender`, `emailCallbacks`, `smsCallbacks`), identifiers (`IdentifierStore`, `memoryIdentifierStore`, `lookupIdentifier` (the exact-match read every service uses), `claimIdentifier`, `replaceIdentifier`), `KeyValueStore`-backed layers for the short-lived stores (`OAuthStateStoreKV`, `ChallengeStoreKV`, `RateLimitStoreKV`, …, bundled as `layerKV` and `layerKVSingleProcess`; see [`KeyValueStore` stores](./storage.md#keyvaluestore-stores)), the SAML seam (`SamlVerifier`, `SamlReplayStore`), `ClientIP`, the observability counters and record helpers, and the token primitives `hashToken`, `constantTimeHashEqual` and `timingSafeEqualBytes`.

Errors are tagged (`Schema.TaggedError`) and carry a stable `code`; the shared ones are flat root exports: `AuthError` (infrastructure failure only), `InvalidCredentialsError`, `SessionNotFoundError`, `SessionExpiredError`, `UserNotFoundError`, `PermissionDeniedError`, `HashingError`, `ChallengeNotFoundError`, `ChallengeExpiredError`, `CredentialNotFoundError`, `WebAuthnVerificationError`, `OAuthStateNotFoundError`, `OAuthStateExpiredError`, `OAuthProviderError`, `RateLimitError`, `EmailVerificationError`, `MagicLinkError`, `PasswordResetError`, and more. The HTTP API maps them to status codes (`RateLimitError` → 429, `AuthError` → 500).
