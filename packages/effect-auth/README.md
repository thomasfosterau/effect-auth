# @thomasfosterau/effect-auth

An experimental Auth library for Effect: sessions, passwords, multi-factor, passkeys, OAuth, organizations and a policy-based authorization kernel, as Effect services and layers.

The headless core is the whole library as far as a consumer is concerned; the HTTP API, the typed client and the framework bindings are tiers you opt into (the other `@thomasfosterau/effect-auth-*` packages). The core depends on `effect` only.

## Install

```bash
pnpm add @thomasfosterau/effect-auth effect
```

`effect` is a peer dependency (`>=4.0.0-rc.118`). Storage comes from your own store implementations or an adapter package (`@thomasfosterau/effect-auth-sql`, `@thomasfosterau/effect-auth-drizzle`).

## Usage

Implement the store interfaces (or take them from an adapter), provide the service layer, and use the service:

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Stores are "dumb persistence": lookups return `null` on a miss, and the
// service turns that into a typed `SessionNotFoundError` / `UserNotFoundError`.
// `session.id` arrives already hashed (SHA-256); the raw token never reaches the store.
const sessions = new Map<string, Auth.Session>();
const sessionStore: typeof Auth.SessionStore.Service = {
  create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  get: (id) => Effect.sync(() => sessions.get(id) ?? null),
  update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
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
  get: (id) => Effect.succeed({ id, createdAt: new Date(), updatedAt: new Date(), attributes: {} }),
};

const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days, the absolute maximum lifetime
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days idle timeout and renewal window
  },
};

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
  // `session.id` is the raw token: put it in the cookie.
  const session = yield* service.createSession("user-123", { ip: "127.0.0.1" });
  const { user } = yield* service.validateSession(session.id);
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

// Still requires SessionStore, UserStore, Hooks and Crypto, like `SessionService.layer`.
const customSessionLayer = Layer.effect(
  SessionService,
  Effect.gen(function* () {
    // ...acquire resources, read config, etc.
    return yield* SessionService.make(sessionConfig);
  }),
);
export { customSessionLayer };
```

## What's included

- **Sessions:** active and idle expiry with renewal, hashed session ids, an optional HMAC-signed session-data cookie (`cookie.cache`), multi-session, trusted devices.
- **Passwords:** PBKDF2-SHA256 (600,000 iterations, the default) and scrypt, a multi-algorithm verifier, password reset, Have I Been Pwned checks. Argon2id is in `@thomasfosterau/effect-auth-argon2`.
- **Sign-in methods:** email and password, username (case-insensitive uniqueness), magic link, email OTP, phone (SMS) OTP with a pluggable E.164 normalizer, anonymous guests (`isAnonymousUser`, upgraded on sign-up through a `linkAccount` callback), Google One Tap, the RFC 8628 device authorization grant, passkeys (WebAuthn). Every password-based method honours the multi-factor gate.
- **Multi-factor:** TOTP with backup codes integrated into sign-in, an OTP second factor, and the RFC 6238 / RFC 4226 primitives.
- **OAuth 2.0 social login:** 20 provider presets (Google, GitHub, Discord, Microsoft, Apple, and more) plus custom providers, PKCE, and a complete sign-in flow with verified-email account linking.
- **Enterprise:** OIDC and SAML SSO with per-organization connections and JIT provisioning, SCIM 2.0, and an OIDC provider with RFC 7591 dynamic client registration for MCP clients.
- **Account management:** verification-gated email change and self-service account deletion (single-use tokens, session revocation, a `beforeDelete` cleanup hook).
- **Organizations and admin:** members (with deactivation), invitations, teams, per-organization roles and default role, verified email domains with opt-in JIT provisioning; admin ban and impersonation.
- **API keys and JWT:** hashed API keys with permissions and quotas; ES256 / EdDSA JWTs with JWKS.
- **Authorization:** one policy kernel (`Policy`, `Entity`, `Condition`, `Authorizer`) with RBAC as authoring sugar, schema-embedded field guards (`protectedField`), zero-IO guards and role ladders.
- **Abuse protection:** rate limiting with presets and an optional `effect/persistence` backend (`rateLimiterPersistenceLayer`), per-IP limits, account lockout (`AccountLockoutPlugin`), captcha (Turnstile, reCAPTCHA, hCaptcha).
- **HTTP API:** a typed `effect/http-api` contract served as a mountable Web handler (`Http.make`), with session cookies, trusted-origin CSRF checks, a derived typed client and an OpenAPI 3.1 document (`Http.getOpenApiSpec()`, or `Http.make({ docs: true })` for a Scalar reference page).
- **Hooks:** `before*` / `after*` hook points, composed as plugins with `composePlugins`; first-party plugins include audit logging and a last-login-method hint.

## Authorization

There is one authorization model: the policy kernel. `Auth.Rbac` turns a flat role and permission configuration into declarative policies plus the principal → role entity graph:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const AuthorizationLive = Auth.Rbac.layer({
  userRoles: { "user-123": ["editor"] },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "create" }],
    admin: [{ resource: "*", action: "*" }], // superadmin wildcard
  },
  roleHierarchy: { editor: ["viewer"] }, // editor also gets viewer's grants
});

const program = Effect.gen(function* () {
  const authorizer = yield* Auth.Authorizer;

  // Boolean form.
  const canCreate = yield* authorizer.check({
    action: "create",
    resource: Auth.Entity.ref("posts", "post-1"),
  });

  // Enforced form: fails with `AuthorizationDeniedError`, carrying the full
  // decision trace (which policies determined it, and why).
  yield* authorizer.authorize({
    action: "create",
    resource: Auth.Entity.ref("posts", "post-1"),
  });
  return canCreate;
}).pipe(Auth.CurrentPrincipal.provide(Auth.Entity.ref("User", "user-123")));

console.log(await Effect.runPromise(Effect.provide(program, AuthorizationLive)));
```

Because the output is `DeclarativePolicy` data, a rule authored this way is storable, traceable, validatable against an `AuthorizationModel`, and enforceable at the data boundary with `Auth.protectedField`. Mix it with hand-written policies by composing `Auth.Rbac.policies(...)` into your own `Auth.Authorizer.layer({ policies })`. Migrating from the removed `RoleStore` / `AuthorizationPolicy` API? See [docs/guides/authorization-kernel-migration.md](../../docs/guides/authorization-kernel-migration.md).

### System principals

A background job, cron handler or pipeline step acts with no person behind it. It is a
principal of its own, `System::"<name>"`, not a user and not an API key. It is denied everything
by default and allowed exactly what an explicit grant names:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const Model = Auth.AuthorizationModel.make({
  entities: {
    User: {},
    System: Auth.System.declaration, // lets grants validate
    Invoice: {},
  },
  actions: {
    "invoice:charge": { appliesTo: { principal: ["System"], resource: ["Invoice"] } },
  },
});

const AuthorizationLive = Auth.Authorizer.layer({
  model: Model,
  policies: [
    // The billing job may charge invoices, and nothing else.
    Auth.System.grant("billing-cron", {
      id: "billing-cron:charge-invoices",
      action: "invoice:charge",
      resource: Auth.Policy.isType("Invoice"),
    }),
  ],
});

const chargeInvoices = Effect.gen(function* () {
  const authorizer = yield* Auth.Authorizer;
  yield* authorizer.authorize({
    action: "invoice:charge",
    resource: Auth.Entity.ref("Invoice", "inv-1"),
  });
}).pipe(Auth.System.provide("billing-cron"), Effect.provide(AuthorizationLive));

await Effect.runPromise(chargeInvoices);
```

The rules a system principal follows:

- **Denied by default.** Only a permit whose principal scope names the `System` type can allow it
  anything: `System.grant`, `Policy.eq(System.ref(…))`, `Policy.inScope(System.ref(…))` (a group of
  system principals) or `Policy.isType("System")`. The kernel
  enforces this for every policy set, so a permit with no principal scope (`Policy.permit` without
  `principal`, `Policy.permission`, even `{ action: "*", resource: "*" }`, `Policy.action`,
  `Policy.roleAtLeast`, the `OwnedAccess` read policies), a role permit (`Rbac`, `Policy.role`) and a
  `Policy.custom` permit never match one. There is no allow-all for system principals.
- **Named by a grant.** `System.grant` takes one action and one resource scope, so a job is granted what it
  needs and nothing wider. A wider grant is several grants, each with its own id.
- **Not a user.** `System` is a reserved entity type. `Guard.make` refuses it as a viewer's
  principal type, and a user policy (`Policy.isType("User")`, or `Policy.eq(User::"…")`) never
  matches a system principal, nor does a system grant match a user with the same name.
- **No roles.** Role assignment is for users. `Rbac` refuses `"System"` as its principal type, and
  a role permit never matches a system principal, whatever parents a resolver gives it, so a role
  change cannot widen what a job may do. One exception is under the application's control: if its entity resolver places a `Role` inside a `System` group, a grant to that group (`inScope(System::"…")`) reaches every member of the role, users included, so keep `Role` entities out of `System` groups.
- **Named in the audit.** `Authorizer` and `Auth.protectedField` log every decision about a system
  principal with `System::"<name>"` and the policies that decided it (allows at info, denials at
  warning), and a denial's error message names it.

Forbids are not narrowed: an unscoped forbid binds a system principal like everyone else. A forbid
whose condition reads a user attribute therefore errors for a system principal, and an erroring
forbid denies, so scope such forbids to users (`Policy.isType("User")`). See
[ADR 0019](../../docs/adr/0019-system-principals.md).

## Passwords

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const hasher = yield* Auth.Password.PasswordHasher;
  const hashed = yield* hasher.hash("correct horse battery staple");
  return yield* hasher.verify("correct horse battery staple", hashed.hash);
});

// The default hasher is PBKDF2-SHA256 with 600,000 iterations; pass
// `{ iterations }` to `layer` to change the count.
console.log(await Effect.runPromise(Effect.provide(program, Auth.Password.PasswordHasher.layer())));
```

## Multi-factor authentication

TOTP (RFC 6238):

```typescript
import { Crypto, Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// The OTP primitives take the `Crypto` service directly. Build one from the
// platform's Web Crypto API (effect-auth's own layer for this is internal).
const CryptoLive = Layer.succeed(
  Crypto.Crypto,
  Crypto.make({
    randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
    digest: (algorithm, data) =>
      Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
        Effect.map((buf) => new Uint8Array(buf)),
      ),
  }),
);

const program = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  // 20 bytes = 160 bits, the RFC 4226 recommendation.
  const secret = yield* Auth.MultiFactor.generateBase32Secret(crypto, 20);

  // Encode this URI as a QR code for the user's authenticator app.
  const uri = Auth.MultiFactor.generateOtpUri({
    type: "totp",
    label: "user@example.com",
    issuer: "MyApp",
    secret,
  });

  // Later, verify the code the user typed (accepts ±1 time step by default).
  // The result is the matched time step, or `null` for a wrong code: persist
  // it and reject a later code with the same or a lower step (replay).
  const code = yield* Auth.MultiFactor.generateTotp(secret);
  const step = yield* Auth.MultiFactor.verifyTotp(code, secret);
  return { uri, valid: step !== null };
});

console.log(await Effect.runPromise(Effect.provide(program, CryptoLive)));
```

HOTP (RFC 4226) and custom configuration:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// HOTP is counter-based: store the counter per user and advance it only after
// a successful verification.
const verifyHotpCode = (code: string, secret: string, counter: number) =>
  Effect.gen(function* () {
    const valid = yield* Auth.MultiFactor.verifyHotp(code, secret, counter);
    return { valid, nextCounter: valid ? counter + 1 : counter };
  });

// Both TOTP and HOTP take an optional config; pass the same one to generate and verify.
const totpConfig: Auth.MultiFactor.TotpConfig = {
  period: 60, // seconds per step (default 30)
  digits: 8, // default 6
  algorithm: "sha256", // default "sha1"
  window: 2, // accept ±2 steps (default 1)
};
const hotpConfig: Auth.MultiFactor.HotpConfig = { digits: 8, algorithm: "sha512" };

const example = (secret: string) =>
  Effect.gen(function* () {
    const totp = yield* Auth.MultiFactor.generateTotp(secret, totpConfig);
    const step = yield* Auth.MultiFactor.verifyTotp(totp, secret, totpConfig);
    const hotp = yield* Auth.MultiFactor.generateHotp(secret, 0, hotpConfig);
    const hotpValid = yield* Auth.MultiFactor.verifyHotp(hotp, secret, 0, hotpConfig);
    const counter = yield* verifyHotpCode(
      yield* Auth.MultiFactor.generateHotp(secret, 0),
      secret,
      0,
    );
    return { step, hotpValid, counter };
  });

console.log(await Effect.runPromise(example("JBSWY3DPEHPK3PXP")));
```

## Passkeys (WebAuthn)

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Challenges are short-lived (an in-memory or Redis store is fine); credentials
// are persistent. Lookups return `null` on a miss.
// Challenges are raw bytes; key them by their base64 form.
const key = (challenge: Uint8Array) => Buffer.from(challenge).toString("base64");
const challenges = new Map<string, Auth.MultiFactor.WebAuthnChallenge>();
const challengeStore: typeof Auth.MultiFactor.ChallengeStore.Service = {
  create: (c) => Effect.sync(() => (challenges.set(key(c.challenge), c), c)),
  get: (challenge) => Effect.sync(() => challenges.get(key(challenge)) ?? null),
  delete: (challenge) => Effect.sync(() => void challenges.delete(key(challenge))),
};
const credentials = new Map<string, Auth.MultiFactor.WebAuthnCredential>();
const credentialStore: typeof Auth.MultiFactor.CredentialStore.Service = {
  create: (c) => Effect.sync(() => (credentials.set(c.id, c), c)),
  get: (id) => Effect.sync(() => credentials.get(id) ?? null),
  // Resolves by the raw credential id, for the discoverable (usernameless) login path.
  getByCredentialId: (credentialId) => Effect.sync(() => credentials.get(credentialId) ?? null),
  update: (c) => Effect.sync(() => (credentials.set(c.id, c), c)),
  delete: (id) => Effect.sync(() => void credentials.delete(id)),
  listByUserId: (userId) =>
    Effect.sync(() => [...credentials.values()].filter((c) => c.userId === userId)),
};

const WebAuthnLive = Auth.MultiFactor.WebAuthnService.layer({
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000, // 5 minutes
}).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.MultiFactor.ChallengeStore)(challengeStore),
      Layer.succeed(Auth.MultiFactor.CredentialStore)(credentialStore),
    ),
  ),
);

// Registration: send `challenge` to the browser, which calls
// `navigator.credentials.create()` and returns the attestation.
const beginRegistration = Effect.gen(function* () {
  const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
  return yield* webAuthn.generateRegistrationChallenge({
    id: "user-123",
    name: "user@example.com",
    displayName: "User Name",
  });
});
const finishRegistration = (
  challenge: Uint8Array,
  response: Auth.MultiFactor.RegistrationResponse,
) =>
  Effect.gen(function* () {
    const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
    const { credential } = yield* webAuthn.verifyRegistration(challenge, response);
    return credential; // now stored and usable for sign-in
  });

// Authentication: the browser signs the challenge with `navigator.credentials.get()`.
const finishAuthentication = (
  challenge: Uint8Array,
  response: Auth.MultiFactor.AuthenticationResponse,
) =>
  Effect.gen(function* () {
    const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
    const { credential } = yield* webAuthn.verifyAuthentication(challenge, response);
    return credential.userId; // create a session for this user
  });

const { challenge } = await Effect.runPromise(Effect.provide(beginRegistration, WebAuthnLive));
export { challenge, finishRegistration, finishAuthentication };
```

## OAuth 2.0 social login

```typescript
import { Effect, Redacted } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const providers = {
  google: Auth.OAuth.GoogleProvider({
    clientId: process.env["GOOGLE_CLIENT_ID"] ?? "",
    clientSecret: Redacted.make(process.env["GOOGLE_CLIENT_SECRET"] ?? ""),
    redirectUri: "https://example.com/auth/google/callback",
  }),
  github: Auth.OAuth.GitHubProvider({
    clientId: process.env["GITHUB_CLIENT_ID"] ?? "",
    clientSecret: Redacted.make(process.env["GITHUB_CLIENT_SECRET"] ?? ""),
    redirectUri: "https://example.com/auth/github/callback",
  }),
};

// Requires OAuthStateStore (temporary, about 10 minutes), OAuthAccountStore,
// OAuthUserStore, IdentifierStore, UserStore and SessionService; a storage
// adapter such as @thomasfosterau/effect-auth-sql provides the stores.
const OAuthLive = Auth.OAuth.OAuthService.layer(providers);

// Step 1: redirect the user to the provider (PKCE and `state` are handled for you).
const begin = Effect.gen(function* () {
  const oauth = yield* Auth.OAuth.OAuthService;
  const { url } = yield* oauth.generateAuthorizationUrl("google", {
    scopes: ["email", "profile"],
    returnTo: "/dashboard",
  });
  return url;
});

// Step 2: the provider redirects back with `code` and `state`. This resolves or
// creates the user (auto-linking on a provider-verified email), links the
// account and issues a session.
const callback = (state: string, code: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    const { user, session } = yield* oauth.signInWithCallback(state, code);
    return { userId: user.id, sessionToken: session.id };
  });

// Link another provider to a signed-in user, or refresh a stored access token.
const link = (userId: string, code: string, state: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    return yield* oauth.linkAccount(userId, "github", code, state);
  });
const refresh = (userId: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    return yield* oauth.refreshAccessToken(userId, "google");
  });

export { OAuthLive, begin, callback, link, refresh };
```

## Email verification

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Stand-in for your mail client.
declare const sendMail: (message: { to: string; subject: string; html: string }) => Promise<void>;

const emailVerificationStore: typeof Auth.Email.EmailVerificationStore.Service = {
  create: (verification) => Effect.succeed(verification),
  get: (_token) => Effect.succeed(null), // null when unknown
  delete: (_token) => Effect.void,
  deleteByUserId: (_userId) => Effect.void,
};

const EmailVerificationLive = Auth.Email.EmailVerificationService.layer({
  expiresIn: 24 * 60 * 60 * 1000, // 24 hours
  sendEmail: (to, token) =>
    Effect.tryPromise({
      try: () =>
        sendMail({
          to,
          subject: "Verify your email",
          html: `Verify: https://example.com/verify?token=${token}`,
        }),
      catch: (cause) => new Auth.EmailVerificationError({ message: "Failed to send email", cause }),
    }),
}).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.Email.EmailVerificationStore)(emailVerificationStore),
      Auth.Hooks.Default,
    ),
  ),
);

// Tokens are single-use and stored as SHA-256 digests.
const sendVerification = (userId: string, email: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;
    return yield* service.createVerification(userId, email);
  });

const verifyEmail = (token: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;
    const result = yield* service.verifyToken(token);
    return result.verified ? result.userId : undefined;
  });

export { EmailVerificationLive, sendVerification, verifyEmail };
```

## Rate limiting

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Use a shared store (Redis, SQL) when you run more than one instance.
const counts = new Map<string, Auth.RateLimitEntry>();
const rateLimitStore: typeof Auth.RateLimitStore.Service = {
  get: (key) => Effect.sync(() => counts.get(key) ?? null),
  set: (key, entry, _ttl) => Effect.sync(() => void counts.set(key, entry)),
  increment: (_key, _ttl) => Effect.succeed(1), // must be atomic in a real store
  delete: (key) => Effect.sync(() => void counts.delete(key)),
};

const RateLimiterLive = Auth.RateLimiter.layer().pipe(
  Layer.provide(Layer.succeed(Auth.RateLimitStore)(rateLimitStore)),
);

// Fails with `RateLimitError` once the key is over its limit.
const guardSignIn = (ip: string) =>
  Effect.gen(function* () {
    const limiter = yield* Auth.RateLimiter;
    yield* limiter.consumeToken(`sign-in:${ip}`, Auth.RateLimitPresets.login);
  });

// Presets: login 5 per 15 min · passwordReset 3 per hour · emailVerification
// 3 per 10 min · registration 3 per hour · oauth 10 per 5 min ·
// totpVerification 5 per 5 min. Or write your own:
const strict: Auth.RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60 * 1000, // 1 minute
  blockDurationMs: 5 * 60 * 1000, // then block for 5 minutes
};

await Effect.runPromise(Effect.provide(guardSignIn("192.0.2.1"), RateLimiterLive));
export { strict };
```

### Client IP behind Cloudflare

Per-IP rate limits (and any hook of your own that reads `ClientIP`) need the visitor's address. Behind Cloudflare the socket address is Cloudflare's, so tell the handler which single header carries the visitor's address:

```typescript
import * as Auth from "@thomasfosterau/effect-auth";

// `services` is the layer graph from the sections above.
const { handler } = Auth.Http.make({
  services,
  trustedProxy: Auth.ClientIP.cloudflare, // trusts CF-Connecting-IP alone
  ipRateLimit: {},
});

// Behind another edge, name its header instead: Auth.ClientIP.trustedHeader("x-real-ip").
```

This is correct only when the app is reachable solely through Cloudflare. A request that bypasses the edge can set `CF-Connecting-IP` to any value and choose its own key. Only that one header is read; `X-Forwarded-For` and the rest are ignored. A value is taken only when it is exactly one IPv4 or IPv6 address. A missing, empty or malformed value, or a comma-separated list, falls back to the socket address. The first entry of a list is never used. Behind Cloudflare that fallback is an edge address shared by many visitors, so it is a fallback, not a per-visitor key. Under `Http.make` serving Web `Request`s (Workers, for example) there is no socket address. So `ipRateLimit` needs a `trustedProxy`: without one, `Http.make` throws `ClientAddressConfigError` at build, unless `allowMissingClientIp: true` is set. When the header is unusable, the request resolves no address, and when a `RateLimiter` is in `services`, a request to a rate-limited endpoint is refused with `429`. It is never let through unlimited and never counted under a bucket shared with other callers. An accepted IPv6 address is canonicalised (RFC 5952), and an IPv4-mapped address becomes dotted IPv4, so one visitor has one key.

Without `trustedProxy`, forwarded headers are ignored and the socket address is used as-is. Under `Http.make` there is no socket address, so `ipRateLimit` without `trustedProxy` is a build error. Set `allowMissingClientIp: true` to accept refusing address-less requests on rate-limited endpoints instead. Dynamic client registration is keyed the same way: `OidcProviderConfig.dynamicRegistration` declares the same `trustedProxy` (or `allowMissingClientIp: true`), and `OidcProviderService.layer` fails at build without one of them.

The IP-keyed limits also need a `RateLimiter` in the handler's `services`: `ipRateLimit`, the dynamic registration limit and the device user-code limit. Without one, `Http.make`'s layer build fails with `RateLimiterConfigError`, and every request rejects with it, so a limit is never silently off (#389).

## Abuse protection

`CaptchaPlugin` and `HaveIBeenPwnedPlugin` are hooks plugins composed with `composePlugins`. Both use `effect/http`'s `HttpClient`, so provide `FetchHttpClient.layer` (or a stub in tests).

```typescript
import { Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";

// Reject compromised passwords (k-anonymity range query) and require a captcha
// token on sign-up and sign-in. Array order is execution order.
const plugins = Auth.composePlugins([
  Auth.Password.HaveIBeenPwnedPlugin({ threshold: 1 }),
  Auth.Plugins.CaptchaPlugin({
    provider: "cloudflare-turnstile",
    secretKey: Redacted.make(process.env["TURNSTILE_SECRET"] ?? ""),
    endpoints: ["signUp", "signIn"],
  }),
]);

// The plugin stack requires `Hooks.Default` and an `HttpClient`.
export const HooksLive = plugins.pipe(
  Layer.provide(Auth.Hooks.Default),
  Layer.provide(FetchHttpClient.layer),
);
```

The captcha token is read from the optional `captchaToken` field on the sign-up and sign-in inputs (and the `SignUpPayload` / `SignInPayload` HTTP schemas). Have I Been Pwned fails open on API errors by default (`failClosed: false`).

## Configuration

Encryption at rest of JWT private keys, OAuth tokens and TOTP secrets is opt-in: leave `JWT_ENCRYPT_PRIVATE_KEY_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET` or `TWO_FACTOR_ENCRYPT_SECRET` **unset** to keep it off. A variable that is set but empty (for example `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`) fails `jwtServiceConfig` / `oauthServiceOptionsConfig` / `multiFactorConfig` at startup with a `ConfigError` naming the variable, because Effect rc.118 reads an empty value as absent and would otherwise silently store the data unencrypted. A value that is only whitespace (for example `"   "` or a lone newline) counts as empty and fails the same way; a secret with surrounding spaces but other content is accepted unchanged. The check reads the active `ConfigProvider`, so it also applies to map providers. Known limitation: an empty secret set together with a sibling variable sharing its prefix (for example `TWO_FACTOR_ENCRYPT_SECRET=""` plus `TWO_FACTOR_ENCRYPT_SECRET_FILE=...`) is not detected and reads as unset.

## API

`import * as Auth from "@thomasfosterau/effect-auth"` reaches the whole surface. Each cluster is also a subpath export for a narrower import:

| Entry                                     | Root namespace     | Contents                                                                                                           |
| ----------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `@thomasfosterau/effect-auth`             | `Auth`             | Sessions, users, identifiers, hooks, errors, the authorization kernel, organizations, admin, API keys, JWT, SSO, … |
| `@thomasfosterau/effect-auth/email`       | `Auth.Email`       | Email and password sign-in, email verification, email OTP                                                          |
| `@thomasfosterau/effect-auth/password`    | `Auth.Password`    | `PasswordHasher` (PBKDF2, scrypt), password reset, `HaveIBeenPwnedPlugin`                                          |
| `@thomasfosterau/effect-auth/multifactor` | `Auth.MultiFactor` | TOTP and backup codes, the OTP second factor, WebAuthn, and the OTP primitives                                     |
| `@thomasfosterau/effect-auth/oauth`       | `Auth.OAuth`       | `OAuthService`, provider presets, `provider` for custom ones, `generateState`, `generatePKCE`                      |
| `@thomasfosterau/effect-auth/plugins`     | `Auth.Plugins`     | First-party hooks plugins: account lockout, audit, captcha, IP rate limit, last login method, email normalization  |
| `@thomasfosterau/effect-auth/http`        | `Auth.Http`        | The HTTP contract, the mountable handler, the typed Effect client, `AuthMiddleware`                                |
| `@thomasfosterau/effect-auth/ladder`      | —                  | An ordered role ladder for browser UX gates; imports nothing, not even `effect`                                    |

Errors are tagged (`Data.TaggedError`) and carry a stable `code`; the shared ones are flat root exports: `AuthError` (infrastructure failure only), `InvalidCredentialsError`, `SessionNotFoundError`, `SessionExpiredError`, `UserNotFoundError`, `PermissionDeniedError`, `HashingError`, `ChallengeNotFoundError`, `ChallengeExpiredError`, `CredentialNotFoundError`, `WebAuthnVerificationError`, `OAuthStateNotFoundError`, `OAuthStateExpiredError`, `OAuthProviderError`, `RateLimitError`, `EmailVerificationError`, `MagicLinkError`, `PasswordResetError`, and more. The HTTP API maps them to status codes (`RateLimitError` → 429, `AuthError` → 500).

## Further reading

- [The three-library boundary](../../docs/BOUNDARY.md): how this library relates to effect-jsonapi and legation.
- [Architecture](../../docs/ARCHITECTURE.md), including the security model; [design decisions](../../docs/DESIGN.md) and [ADRs](../../docs/adr/README.md).
- Guides: [bring your own store](../../docs/guides/byo-stores.md), [the browser client](../../docs/guides/client.md), [MCP provider](../../docs/guides/mcp-provider.md), [SCIM](../../docs/guides/scim.md), [auth as a separate service](../../docs/guides/split-auth-service.md), [migrating from Better Auth](../../docs/guides/better-auth-migration.md).
- [Observability](../../docs/OBSERVABILITY.md): spans and metrics.

## License

MIT
