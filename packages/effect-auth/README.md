# @thomasfosterau/effect-auth

An experimental Auth library for Effect: sessions, passwords, multi-factor, passkeys, OAuth, organizations and a policy-based authorization kernel, as Effect services and layers.

The headless core is the whole library as far as a consumer is concerned; the HTTP API (`/http`), the typed browser client (`/client`), SQL storage (`/sql`) and SAML (`/saml`) are subpaths you opt into, and the framework bindings and the adapters that bring a dependency of their own are the other `@thomasfosterau/effect-auth-*` packages. The core's only required peer is `effect`; the root barrel loads none of the subpaths.

## Install

```bash
pnpm add @thomasfosterau/effect-auth effect
```

`effect` is a peer dependency (`^4.1.0`). Two subpaths take an optional peer: `/http` (and `/client/testing` through it) needs `@thomasfosterau/effect-jsonapi`, and `/saml` needs `@node-saml/node-saml`. Storage comes from your own store implementations, the [`/sql` subpath](#sql-storage-sql) or an adapter package (`@thomasfosterau/effect-auth-drizzle`).

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

## What's included

- **Sessions:** active and idle expiry with renewal, hashed session ids, an optional HMAC-signed session-data cookie (`cookie.cache`), multi-session, trusted devices.
- **Passwords:** PBKDF2-SHA256 (600,000 iterations, the default) and scrypt, a multi-algorithm verifier, password reset, Have I Been Pwned checks. Argon2id is in `@thomasfosterau/effect-auth-argon2`.
- **Sign-in methods:** email and password, username (case-insensitive uniqueness), magic link, email OTP, phone (SMS) OTP with a pluggable E.164 normalizer, anonymous guests (`isAnonymousUser`, upgraded on sign-up through a `linkAccount` callback), Google One Tap, the RFC 8628 device authorization grant, passkeys (WebAuthn). Every password-based method honours the multi-factor gate.
- **Multi-factor:** TOTP with backup codes integrated into sign-in, an OTP second factor, and the RFC 6238 / RFC 4226 primitives.
- **OAuth 2.0 social login:** 20 provider presets (Google, GitHub, Discord, Microsoft, Apple, and more) plus custom providers, PKCE, and a complete sign-in flow with verified-email account linking.
- **Enterprise:** OIDC and SAML SSO with per-organization connections and JIT provisioning (the SAML XML verification is the Node-only [`/saml` subpath](#saml-saml)), SCIM 2.0, and an OIDC provider with RFC 7591 dynamic client registration for MCP clients.
- **Account management:** verification-gated email change and self-service account deletion (single-use tokens, session revocation, a `beforeDelete` cleanup hook).
- **Organizations and admin:** members (with deactivation), invitations, teams, per-organization roles and default role, verified email domains with opt-in JIT provisioning; admin ban and impersonation.
- **API keys and JWT:** hashed API keys with permissions and quotas; ES256 / EdDSA JWTs with JWKS.
- **Authorization:** one policy kernel (`Policy`, `Entity`, `Condition`, `Authorizer`) with RBAC as authoring sugar, schema-embedded field guards (`protectedField`), zero-IO guards and role ladders.
- **Abuse protection:** rate limiting with presets and an optional `effect/persistence` backend (`rateLimiterPersistenceLayer`), per-IP limits, account lockout (`AccountLockoutPlugin`), captcha (Turnstile, reCAPTCHA, hCaptcha).
- **HTTP API:** a typed `effect/http-api` contract served as a mountable Web handler (`Http.make`, or `Http.makeAsync` for services that build asynchronously), with session cookies, trusted-origin CSRF checks, a derived typed client and an OpenAPI 3.1 document (`Http.getOpenApiSpec()`, or `Http.make({ docs: true })` for a Scalar reference page).
- **Hooks:** `before*` / `after*` hook points, composed as plugins with `composePlugins`; first-party plugins include audit logging and a last-login-method hint. Every credential-verifying flow fires `beforeAuthenticate` (see [Abuse protection](#abuse-protection)).

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

Because the output is `DeclarativePolicy` data, a rule authored this way is storable, traceable, validatable against an `AuthorizationModel`, and enforceable at the data boundary with `Auth.protectedField`. Mix it with hand-written policies by composing `Auth.Rbac.policies(...)` into your own `Auth.Authorizer.layer({ policies })`. Migrating from the removed `RoleStore` / `AuthorizationPolicy` API? See [docs/guides/authorization-kernel-migration.md](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/authorization-kernel-migration.md).

### Empty entity ids

An entity id is never empty. `Auth.Entity.EntityRef` refuses `""` when it decodes, and a reference
built by hand with one (`Auth.Entity.ref("User", "")`) names no entity: it equals nothing, itself
included. `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or resource
has an empty id, with reason `"invalid-request"`, before any policy runs, and `ReadScope.compile`
compiles such a principal or action to `ReadScope.deny`. Never use an empty id as a "no user"
stand-in: it would match every row whose owner column is `""`. A signed-out caller is a principal
of its own type, such as `Anonymous::"anonymous"`, which user-typed policies never match.
`Guard.make` reads a viewer whose id is empty as anonymous.

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
[ADR 0019](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0019-system-principals.md).

`Guard`'s viewer gates (`requireUser`, `requireRoleAtLeast`, `requireOwnerOrRole`) admit users
only. For an operation a job may also perform, `Auth.Guard.requireSystem({ action, resource })` is
the system gate: it admits the current principal when it is a system principal a policy grants the
action (decided by the `Authorizer` in context, so the decision is logged), and yields its
`EntityRef`. Ask the user gate when a viewer is signed in (`guards.isSignedIn`) and the system gate
otherwise; the `Guard` module docs have the full example. After the write, report it with
`Auth.recordWrite({ principal, action, resource })`, naming whichever principal passed:
`AuditPlugin` logs it as `auth.write`, so unattended writes are audited alongside a person's.

### Owned and reference material

`Auth.OwnedAccess.make({ guards, viewPrivate })` decides reads of a member's own material: a
`visibility` of `public | followers | group | private`, narrowed by two publication flags (`draft`
and `unapproved`, a moderated row whose state is anything but approved), with `canView(row)` for one
row, `readScope` for a list's `WHERE`, and the `policies` (plus the `binding` they compile against
with `ReadScope.compile`) both are decided by. `Auth.ReferenceAccess.make({ guards, viewPrivate })`
decides ownerless corpus rows on the same axis: read by a `followersOf` account and its followers,
or by a group's members, with no draft or moderation axis; its `readScope` has the owned shape, so
one renderer filters both kinds.

| Row                                | Who may read it                                                    |
| ---------------------------------- | ------------------------------------------------------------------ |
| `public`, published                | everyone, anonymous included                                       |
| `followers`, published             | the owner (reference: the `followersOf` account) and its followers |
| `group`, published                 | the owner (owned rows) and the members of its group                |
| `private`, a draft, or unapproved  | the owner and the `viewPrivate` axis                               |
| no owner (`ownerId: undefined`)    | nobody's own: public and published, or the `viewPrivate` axis      |
| `group` with no group              | read as `private`                                                  |
| reference row with no `visibility` | everyone: the view has no visibility axis                          |

Followers and group members are external facts, read through the `IsFollower` and `IsMember`
seams. Both fail closed: an unprovided seam answers "no" (`isFollowerNever` / `isMemberNever` make
it explicit), and neither is ever asked about a missing owner, followers-of account or group. A
`false` from `canView` is a 404, never a 403.

`Auth.Cacheability.publiclyServeable(Auth.OwnedAccess.serveableAxes)` decides whether a
representation may sit in a viewer-less cache: `visibility` must be `public`, `draft` and
`unapproved` absent or `false`, `moderationState` absent or `"approved"`, and `deletedAt` absent
(`null` included). The four role questions a content application asks — view private material,
view deleted rows, moderate, write the corpus — are `Ladder` axes handed to `Guard`'s gates and
predicates, and each fails closed on a role outside the ladder; the `OwnedAccess` module docs show
the pattern.

## Testing

`@thomasfosterau/effect-auth/testing` runs an Effect as a fixture principal in one call, so an app tests its own guards and policies without HTTP. It is not re-exported from the package root and does not load the HTTP tier.

```ts
import { Effect } from "effect";
import * as Testing from "@thomasfosterau/effect-auth/testing";

// As this library's User: the session context the required-auth middleware provides
// (CurrentSession, CurrentUser, MaybeCurrentSession, CurrentPrincipal, CurrentCredential).
await Effect.runPromise(program.pipe(Testing.runAs(ada)));
await Effect.runPromise(program.pipe(Testing.runAs(ada, { credentialClass: "machine" })));
// Anonymous: MaybeCurrentSession as none, and nothing else.
await Effect.runPromise(program.pipe(Testing.runAs(null)));

// As the app's own viewer (the service handed to Guard.make), plus the same session context.
await Effect.runPromise(
  requireModerator.pipe(Testing.runAsViewer(CurrentViewer, { id: "u-1", role: "moderator" })),
);
```

`layerAs` / `viewerLayerAs` return the same context as a `Layer`. The fixture session is minted from the `Clock` and expires 24 hours later.

`fixtureUsers()` gives the canonical trio (`admin`, `member`, `otherMember` for cross-author checks) with fixed UUID ids (`fixtureUserIds`), so apps whose tables reference `users.id` as `uuid` can insert them as real rows; `fixtureUser({ role, name, id })` makes one more with a fresh random UUID. Roles live in `attributes.role`, where `isAdmin` and `SessionContext.withRole` read them; ids, roles and timestamps are overridable.

The guard-negative helpers make the 401 / 403 / 404 mapping testable in one line. `expectGuarded` runs an operation anonymously, one rung below its minimum, at the minimum and (optionally) as the owner, and fails with `GuardExpectationError` listing every case that came out wrong:

```ts
await Effect.runPromise(
  Testing.expectGuarded(editPost, CurrentViewer, {
    ladder: Roles,
    min: Axes.moderate,
    viewerAt: (role) => ({ id: `u-${role}`, role }),
    owner: author, // held below the minimum: admitted by ownership alone
    // access: "read" expects the app's NotFound for both refusals instead of Unauthorized / Forbidden
  }),
);
```

`expectRefusesAnonymous`, `expectRefusesBelow` and `expectAllowsOwner` check one case each.

The store-contract conformance suites (`sessionStoreConformance`, `userStoreConformance`, `identifierStoreConformance`, `apiKeyStoreConformance`, `emailOtpStoreConformance` and `phoneOtpStoreConformance` (the OTP records and their failure budget, #590), and `organizationStoreConformance` for the `OrganizationStore` records the HTTP API addresses by id: memberships, team memberships and custom roles) check a bring-your-own store against the semantics its contract states. Each suite is a list of cases, and each case is an `Effect` that fails with `ConformanceError` on a mismatch. The suites import no test runner. Register the cases with your own, as the [bring-your-own-store guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/byo-stores.md#7-check-your-store-against-the-contract) shows.

`memoryStores` is a layer of in-memory reference stores: sessions, users (one table shared by `UserStore`, `EmailPasswordStore`, `OAuthUserStore` and `OAuthAccountStore.hasPassword`), identifiers, TOTP and OTP second factors, trusted devices, JWT keys, OAuth accounts, the four OIDC provider stores, and the `KeyValueStore`-backed token stores over an in-memory `KeyValueStore`, which it also provides with its `KeyValueStoreKeys` listing so `purgeExpiredKV` runs against it. Each build starts empty. It lets a test or a demo build `SessionService`, `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService` or `OidcProviderService` with no database. Each store is also exported on its own (`memorySessionStore()`, `memoryUserStore(table)`, …). `memoryPhoneOtpStore()` is a `PhoneOtpStore` outside the layer, and `memoryOtpFailures()` the failure-budget half of either OTP store, to spread into one of your own.

`sessionServiceLayer({ users, config? })` provides `SessionService` (plus its `SessionStore` and `UserStore`) over a `UserStore` seeded with `users` (any iterable of `User`, e.g. `fixtureUser()`s), an empty session store and `Hooks.Default`. `config` defaults to `defaultSessionConfig`: a 24 hour `activePeriod` and a 1 hour `idlePeriod`. `apiKeyServiceLayer({ keys?, config? })` provides `ApiKeyService` (plus its `ApiKeyStore` and `RateLimitStore`) over a `memoryApiKeyStore` seeded with `keys` and an in-memory `RateLimiter`, so `verifyWithRateLimit` works; `config` is `ApiKeyService.layer`'s own. Each build starts from fresh state, and `memoryApiKeyStore(keys?)` is also exported on its own (and part of `memoryStores`).

```ts
const program = Effect.gen(function* () {
  const sessions = yield* Auth.SessionService;
  const session = yield* sessions.createSession(ada.id);
  yield* sessions.validateSession(session.id);
  yield* sessions.invalidateSession(session.id); // validateSession now fails
});
await Effect.runPromise(
  program.pipe(Effect.provide(Testing.sessionServiceLayer({ users: [ada] }))),
);
```

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
import { Effect } from "effect";
import { SecureRandom } from "effect/crypto";
import * as Auth from "@thomasfosterau/effect-auth";

// The OTP primitives take Effect's `SecureRandom` service directly;
// `SecureRandom.layerWebCrypto` draws from the platform's Web Crypto API.
const program = Effect.gen(function* () {
  const crypto = yield* SecureRandom.SecureRandom;
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

console.log(await Effect.runPromise(Effect.provide(program, SecureRandom.layerWebCrypto)));
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
import { Base64 } from "effect/encoding";
import * as Auth from "@thomasfosterau/effect-auth";

// Challenges are short-lived (an in-memory or Redis store is fine); credentials
// are persistent. Lookups return `null` on a miss.
// Challenges are raw bytes; key them by their base64 form.
const key = (challenge: Uint8Array) => Base64.encode(challenge);
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
// adapter such as @thomasfosterau/effect-auth/sql provides the stores.
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
// creates the user, links the account and issues a session. A first sign-in
// whose email matches an existing user auto-links only when both the provider
// and this application verified the address; otherwise it fails with
// `EmailInUseError` (#588).
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

Account linking on `signInWithCallback`: when a provider identity is new and its email matches an existing user, the account is linked to that user only if the provider reports `email_verified: true`, the local email identifier is verified, and auto-linking applies to the provider (`autoLinkByVerifiedEmail`, default `true`, or the provider is in `trustedProviders`, which auto-link even with `autoLinkByVerifiedEmail: false`). Every other match fails with `EmailInUseError` and changes nothing. An unverified local address may have been claimed by someone who signed up with it and a password, so its real holder proves it first (the verification link, a magic link or an email OTP, which clear the earlier sign-up's password and sessions) and then signs in with the provider.

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

## Delivery

An adapter implements `EmailSender` / `SmsSender` once (`@thomasfosterau/effect-auth-resend`, `@thomasfosterau/effect-auth-twilio`), and `emailCallbacks` / `smsCallbacks` derive every feature's send callback from it. Each derived callback awaits its send. A flow that hides whether an account exists hands its send to the host's `DeliveryScheduler` instead, whichever callback it was given. In that flow only a known address gets a message, so an inline send would answer that address later than an unknown one, and answer a vendor failure with an error the unknown address never sees.

| Flow                                                                                 | Send                  | Why                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-up: verification email and existing-account notice                              | off the response path | Under `antiEnumeration` a fresh address gets the verification email and a held one the notice (or nothing), so neither answer may wait on the vendor. The send is advisory: a lost one is resent through `POST /email-verifications`. |
| Magic link with `disableSignUp`                                                      | off the response path | Only a known address gets the link.                                                                                                                                                                                                   |
| Email OTP `sign-in` with `disableSignUp`, and `forget-password`                      | off the response path | Only a known address gets the code.                                                                                                                                                                                                   |
| Phone OTP `sign-in` with `disableSignUp`                                             | off the response path | Only a known number gets the code.                                                                                                                                                                                                    |
| Password reset request                                                               | off the response path | Only a known address gets the link.                                                                                                                                                                                                   |
| Magic link and OTP sign-in with sign-up enabled, OTP `email-verification`            | inline                | Every address gets the message, and the user is waiting on it: a failed send is answered, not dropped.                                                                                                                                |
| Verification email sent directly (`createVerification`, `POST /email-verifications`) | inline                | No account is being hidden.                                                                                                                                                                                                           |
| Change email, delete account, second-factor OTP, organization invitations            | inline                | The caller is signed in; nothing is hidden.                                                                                                                                                                                           |

A send off the response path never fails the request. Its failure is logged, counted on `effect_auth_delivery_sends_total` (by purpose and outcome) and passed to the `afterDeliveryFailure` hook, which `AuditPlugin` logs as `auth.deliveryFailure`. The message's parameters (its token or code) are in none of them.

Without a `DeliveryScheduler`, those sends run on a detached fiber, which a long-lived server runs to completion. Workers can drop that fiber once the response is returned, so on Workers provide `DeliveryScheduler.waitUntil` per request:

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `ctx` is the Worker's ExecutionContext; the scheduler is read per call, so
// providing it per request is enough even when the services are built once.
declare const ctx: { waitUntil(promise: Promise<unknown>): void };
declare const handle: Effect.Effect<Response>;

const response = handle.pipe(
  Effect.provide(Auth.DeliveryScheduler.waitUntil((promise) => ctx.waitUntil(promise))),
);
```

Detaching does not make the two sign-up answers identical: the fresh branch still writes a verification record that the duplicate branch does not.

**No-op transports.** `EmailSender.logging` and `SmsSender.logging` send nothing and log each message's recipient and purpose. They are for development only, and you opt into them explicitly. Behind them, every flow that waits on a message (magic link, OTP, password reset) is a lockout. The sign-up verification email tolerates being dropped only while verification is advisory, that is, while `requireEmailVerification` does not gate sign-in. effect-auth-resend's `layerConfig` fails at boot when its key is missing rather than falling back to one.

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
import * as Http from "@thomasfosterau/effect-auth/http";

// `services` is the layer graph from the sections above.
const { handler } = Http.make({
  services,
  trustedProxy: Auth.ClientIP.cloudflare, // trusts CF-Connecting-IP alone
  ipRateLimit: {},
});

// Behind another edge, name its header instead: Auth.ClientIP.trustedHeader("x-real-ip").
```

This is correct only when the app is reachable solely through Cloudflare. A request that bypasses the edge can set `CF-Connecting-IP` to any value and choose its own key. Only that one header is read; `X-Forwarded-For` and the rest are ignored. A value is taken only when it is exactly one IPv4 or IPv6 address. A missing, empty or malformed value, or a comma-separated list, falls back to the socket address. The first entry of a list is never used. Behind Cloudflare that fallback is an edge address shared by many visitors, so it is a fallback, not a per-visitor key. Under `Http.make` serving Web `Request`s (Workers, for example) there is no socket address. So `ipRateLimit` needs a `trustedProxy`: without one, `Http.make` throws `ClientAddressConfigError` at build, unless `allowMissingClientIp: true` is set. When the header is unusable, the request resolves no address, and a request to a rate-limited endpoint is refused with `429`. It is never let through unlimited and never counted under a bucket shared with other callers. An accepted IPv6 address is canonicalised (RFC 5952), and an IPv4-mapped address becomes dotted IPv4, so one visitor has one key.

Without `trustedProxy`, forwarded headers are ignored and the socket address is used as-is. Under `Http.make` there is no socket address, so `ipRateLimit` without `trustedProxy` is a build error. Set `allowMissingClientIp: true` to accept refusing address-less requests on rate-limited endpoints instead. Dynamic client registration is keyed the same way, by the address this `trustedProxy` resolves: with registration enabled and neither option set, `Http.make` fails at startup with `ClientAddressConfigError`.

**`IPRateLimitPlugin` refuses every request without a client address.** The plugin limits authentication attempts (every `beforeAuthenticate`: one `signin` bucket for the first-factor methods, a `second-factor` bucket for second-factor redemptions), sign-up and password-reset requests per address. A request it cannot key is refused with `RateLimitError` (`429` over HTTP), never let through: a request whose address cannot be resolved, and any hook run with no `ClientIP` service in scope, such as a direct `EmailPasswordService.signIn` call from server code. So under `Http.make` the plugin needs `trustedProxy`. When the `Hooks` in `services` include it and `make` has neither `trustedProxy` nor `allowMissingClientIp: true`, `make` throws `ClientAddressConfigError`. With `allowMissingClientIp: true` and no `trustedProxy`, every sign-in, sign-up and password-reset request is refused with `429` (#389).

The limits also need a `RateLimiter` in the handler's `services`: `ipRateLimit`, the dynamic registration limit and the device user-code limit (5 approve/deny attempts per user code per 15 minutes). The device limit counts as configured whenever a `DeviceAuthorizationService` is in `services`; build it with `allowMissingRateLimiter: true` to run approve and deny without the limit instead. Without a `RateLimiter`, `Http.make` throws `RateLimiterConfigError`, so the app fails to start rather than run a limit as a no-op. `make` builds `services` once to check this and the handler reuses that build. Any other failure of the `services` build also makes `make` throw (the OIDC layer's `ClientAddressConfigError`, for example). Before it throws, `make` releases what the build acquired: a finalizer that does asynchronous work finishes after `make` has thrown, and a finalizer that fails is logged as an error. `make` waits for the build only. A fiber the build forks with `Effect.forkChild` is interrupted when the layer that forks it finishes building. Under `Layer.merge` or `Layer.mergeAll` that is the merged layer's own build, which can end ahead of the whole `services` build, so a fiber that has not started by then never runs. One forked into the layer's scope (`Effect.forkScoped`) keeps running after `make` returns and stops on `dispose`; one forked with `Effect.forkDetach` keeps running, and `dispose` does not stop it. Outside `Http.make`, the exported group layers (`Http.groupLayers`, or a group such as `Http.authGroupLayer` on its own) answer `429` when a configured limit finds no `RateLimiter` in scope (#389).

### Services that build asynchronously: `Http.makeAsync`

`Http.make` is synchronous, so it can throw only when the `services` build finishes before it returns. It runs the build the way `Effect.runSync` does, and the build is still running when `make` returns if it waits on:

- asynchronous work, such as a database connection or `Effect.promise`;
- a merged layer (`Layer.merge`, `Layer.mergeAll`) whose build yields, or runs past Effect's per-slice operation budget (2,048 operations by default), since each merged layer builds on a fiber of its own;
- a forked fiber that yields before it completes a `Deferred` the build awaits;
- a finalizer that does asynchronous work, when the build fails.

For those, `make` cannot throw: the same checks fail the handler's build instead, and every request rejects with the error. `Http.makeAsync` takes the same options and waits for the build however it is composed. It resolves to the same `{ handler, dispose }`, serving that one build, and rejects with the errors `make` throws, so the app fails to start. Before it rejects, it releases what the build acquired and waits for every finalizer, asynchronous ones included.

```typescript
import * as Auth from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";

// `services` connects to a database while it builds.
const { handler, dispose } = await Http.makeAsync({
  services,
  trustedProxy: Auth.ClientIP.cloudflare,
  ipRateLimit: {},
});
```

To keep `Http.make` and have it refuse a build it cannot finish, set `strict: true`. `make` then throws `ServicesBuildPendingError` (also exported as `Http.ServicesBuildPendingError`) when the `services` build has not finished by the time it has run the build synchronously, so the app fails to start; the error's message names `Http.makeAsync`. Before it throws, `make` interrupts the build and releases what the build acquired, as far as that runs synchronously. Two parts finish after `make` has thrown: a finalizer that does asynchronous work, and, when the build is in an uninterruptible step that waits on asynchronous work (an `Effect.acquireRelease` acquire that awaits), the whole release, since the interrupt waits for that step to end. A build that was failing when `make` threw (a step that failed while a finalizer it runs awaits) ends with that failure, which `make` logs with `Effect.logError`, since `ServicesBuildPendingError` cannot carry it. A build that finishes synchronously is unaffected: `make` throws the startup errors or the build's own failure, or returns the handler, as without the option. `Http.makeAsync` ignores the option, since it waits for the build whatever it says.

```typescript
// Throws ServicesBuildPendingError if `services` cannot finish building synchronously.
const { handler } = Http.make({ services, strict: true });
```

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

The captcha token is read from the optional `captchaToken` field on the sign-up input and on the email and username sign-in inputs (and the `SignUpPayload` HTTP schema and the `password` and `username` sign-in credentials). Have I Been Pwned fails open on API errors by default (`failClosed: false`).

### The `beforeAuthenticate` hook

Every flow that verifies a credential fires `beforeAuthenticate` before it checks the credential and before it spends or creates anything: email and password, username and password, email OTP, phone OTP, magic link, and second-factor redemption (TOTP, backup code, OTP second factor). Its input is `{ method, identifier: { type, value }, userId?, captchaToken? }`: the method (`AuthenticationMethod`), the handle the attempt names (normalized; a second-factor redemption names its challenge's user, `type: "user"`), the user the handle resolves to when one does, and the captcha token for the two password methods. A plugin denies the attempt by failing. The flows read nothing back; `beforeSignIn` stays the place to rewrite an email and password sign-in's input (`NormalizeEmailPlugin`).

`AccountLockoutPlugin`, `CaptchaPlugin`, `RateLimitPlugin` and `IPRateLimitPlugin` guard it:

- **`AccountLockoutPlugin`** counts every attempt per account (`authenticationSubject`: `user:<id>` for a resolved handle, so an account's email, username and phone share one count, else the handle itself, so an unknown handle locks like a known one) and locks after `maxAttempts` for `lockoutDurationMs`. The counts clear only when a session is issued for the user (`afterCreateSession`), never on a correct password that earned only a second-factor challenge. Second-factor redemptions have a per-user count of their own (`maxSecondFactorAttempts`, default 5) that runs across challenges, so fresh challenges buy no fresh guesses; only someone past the first factor can drive it. A lock refuses every method of the account until it lapses, so anyone who knows a handle can lock the account for `lockoutDurationMs`: pair it with `IPRateLimitPlugin` or a captcha.
- **`CaptchaPlugin`** with the `"signIn"` endpoint verifies the token on the two password methods; the code, link and second-factor flows carry no token.
- **`RateLimitPlugin`** draws first-factor attempts from one bucket per account (`RateLimitPresets.login`) and second-factor redemptions from another (`RateLimitPresets.totpVerification`).

### One-time code guessing

Email and phone OTP sign-in (`EmailOtpService`, `PhoneOtpService`) bound the wrong codes an address accepts across resends, not only per code (#590). `maxAttempts` (default 3) limits one code; every wrong code is also counted against the address and purpose in the store's failure budget, which a resend, an expiry or the attempt limit never resets. Once the count reaches `backoff.freeFailures` (default 5), `send` answers `ResendTooSoonError` (`429` with `Retry-After` over HTTP) until `backoff.baseDelay` (default one minute), doubled for each further wrong code and capped at `backoff.maxDelay` (default one day), has passed since the latest one. A successful verification resets the count.

There is no lockout: once the delay has passed a send goes through, so an attacker can slow an address's owner down but never lock them out. Under the defaults, an attacker gets 18 guesses at a six-digit code in the first day and 3 a day after that. `resendCooldown` (default 60 s; `0` turns it off) still spaces sends of an outstanding code. Both apply alike to an address with and without an account, so neither reveals which addresses are registered. The code length stays 6 digits by default (`otpLength`).

## Expired codes and links

No store deletes an email OTP or a magic link that nobody redeems: it stays until a later send for the same address replaces it, and the sends that hide whether an account exists write one for any address. The services refuse an expired record, so this is about space, not access, but a caller can grow the store by one record per address it tries. Purge on a schedule the host owns (a cron trigger on Workers, a timer or job on a long-lived server):

- `@thomasfosterau/effect-auth/sql`'s `purgeExpired` (and `@thomasfosterau/effect-auth-alchemy-cloudflare`'s `purgeExpired(db)` on D1) deletes the expired rows in one statement per table.
- `purgeExpiredKV` does the same for `MagicLinkStoreKV` and `EmailOtpStoreKV` (so `layerKV` and `Testing.memoryStores`). It finds the records through the store's own `keys` (Effect 4.1), so any `KeyValueStore` serves, `KeyValueStore.layerMemory` included. A backend that lists by prefix more cheaply than it lists everything (a large or shared Workers KV namespace, Redis) can also provide `KeyValueStoreKeys`, whose `list(prefix)` the purge then uses instead; `layerMemoryKeyValueStore` provides both over one in-memory map.

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Optional, for Workers KV: list one prefix, following every cursor. `KV` is the namespace binding.
export const workersKvKeys = (KV: {
  list: (options: { prefix: string; cursor?: string }) => Promise<{
    keys: ReadonlyArray<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }>;
}) =>
  Layer.succeed(Auth.KeyValueStoreKeys, {
    list: (prefix) =>
      Effect.tryPromise({
        try: async () => {
          const names: Array<string> = [];
          let cursor: string | undefined;
          do {
            const page = await KV.list(cursor === undefined ? { prefix } : { prefix, cursor });
            names.push(...page.keys.map((key) => key.name));
            cursor = page.list_complete ? undefined : page.cursor;
          } while (cursor !== undefined);
          return names;
        },
        catch: () => new Auth.AuthError({ message: "KV list failed" }),
      }),
  });

// In the scheduled handler, with the same KeyValueStore the stores use:
// yield* Auth.purgeExpiredKV  // { magicLinks, emailOtps }
```

The listing must name keys as the `KeyValueStore` sees them: behind a `KeyValueStore.prefix` view, strip that prefix. The KV purge is read-then-delete like the stores' other multi-step writes, so an OTP re-sent for the same address and purpose mid-purge can be deleted with the expired one; that code is then refused and the user asks for another.

## Configuration

Encryption at rest of JWT private keys, OAuth tokens and TOTP secrets is opt-in: leave `JWT_ENCRYPT_PRIVATE_KEY_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET` or `TWO_FACTOR_ENCRYPT_SECRET` **unset** to keep it off. A variable that is set but empty (for example `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`) fails `jwtServiceConfig` / `oauthServiceOptionsConfig` / `multiFactorConfig` at startup with a `ConfigError` naming the variable, because Effect rc.118 reads an empty value as absent and would otherwise silently store the data unencrypted. A value that is only whitespace (for example `"   "` or a lone newline) counts as empty and fails the same way; a secret with surrounding spaces but other content is accepted unchanged. The check reads the active `ConfigProvider`, so it also applies to map providers. Known limitation: an empty secret set together with a sibling variable sharing its prefix (for example `TWO_FACTOR_ENCRYPT_SECRET=""` plus `TWO_FACTOR_ENCRYPT_SECRET_FILE=...`) is not detected and reads as unset.

## API

`import * as Auth from "@thomasfosterau/effect-auth"` reaches the whole headless surface. Each cluster is also a subpath export for a narrower import. The HTTP tier, the browser client, SQL storage and SAML are the exception: each is published only as its subpath, so importing the root never pulls in `effect/http-api`, `effect/sql` or `@node-saml/node-saml`:

| Entry                                        | Root namespace     | Contents                                                                                                                                                                              |
| -------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@thomasfosterau/effect-auth`                | `Auth`             | Sessions, users, identifiers, hooks, errors, the authorization kernel, organizations, admin, API keys, JWT, SSO, …                                                                    |
| `@thomasfosterau/effect-auth/email`          | `Auth.Email`       | Email and password sign-in, email verification, email OTP                                                                                                                             |
| `@thomasfosterau/effect-auth/password`       | `Auth.Password`    | `PasswordHasher` (PBKDF2, scrypt), password reset, `HaveIBeenPwnedPlugin`                                                                                                             |
| `@thomasfosterau/effect-auth/multifactor`    | `Auth.MultiFactor` | TOTP and backup codes, the OTP second factor, WebAuthn, and the OTP primitives                                                                                                        |
| `@thomasfosterau/effect-auth/oauth`          | `Auth.OAuth`       | `OAuthService`, provider presets, `provider` for custom ones, `generateState`, `generatePKCE`                                                                                         |
| `@thomasfosterau/effect-auth/plugins`        | `Auth.Plugins`     | First-party hooks plugins: account lockout, audit, captcha, IP rate limit, last login method, email normalization                                                                     |
| `@thomasfosterau/effect-auth/http`           | — (subpath only)   | The HTTP contract, the mountable handler (`make`, `makeAsync`), the typed Effect client, `AuthMiddleware`, the authorization middleware, `RemoteSession` (auth as a separate service) |
| `@thomasfosterau/effect-auth/client`         | — (subpath only)   | The browser client over the HTTP contract ([below](#browser-client-client))                                                                                                           |
| `@thomasfosterau/effect-auth/client/atoms`   | — (subpath only)   | The client session as `effect/reactivity` Atoms ([below](#the-session-atoms-clientatoms))                                                                                             |
| `@thomasfosterau/effect-auth/client/testing` | — (subpath only)   | An in-process server fixture and cookie-jar `fetch` for client tests                                                                                                                  |
| `@thomasfosterau/effect-auth/sql`            | — (subpath only)   | Every store contract it covers over `effect/sql`'s `SqlClient`, plus the DDL ([below](#sql-storage-sql))                                                                              |
| `@thomasfosterau/effect-auth/saml`           | — (subpath only)   | The `SamlVerifier` over `@node-saml/node-saml`; Node-only ([below](#saml-saml))                                                                                                       |
| `@thomasfosterau/effect-auth/ladder`         | —                  | An ordered role ladder for browser UX gates; imports nothing, not even `effect`                                                                                                       |
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

Flat root exports beyond those also include the delivery seams (`EmailSender`, `SmsSender`, `emailCallbacks`, `smsCallbacks`), identifiers (`IdentifierStore`, `memoryIdentifierStore`, `lookupIdentifier` (the exact-match read every service uses, #602), `claimIdentifier`, `replaceIdentifier`), `KeyValueStore`-backed layers for the short-lived stores (`OAuthStateStoreKV`, `ChallengeStoreKV`, `RateLimitStoreKV`, …), the SAML seam (`SamlVerifier`, `SamlReplayStore`), `ClientIP`, the observability counters and record helpers, and the token primitives `hashToken`, `constantTimeHashEqual` and `timingSafeEqualBytes`.

Errors are tagged (`Data.TaggedError`) and carry a stable `code`; the shared ones are flat root exports: `AuthError` (infrastructure failure only), `InvalidCredentialsError`, `SessionNotFoundError`, `SessionExpiredError`, `UserNotFoundError`, `PermissionDeniedError`, `HashingError`, `ChallengeNotFoundError`, `ChallengeExpiredError`, `CredentialNotFoundError`, `WebAuthnVerificationError`, `OAuthStateNotFoundError`, `OAuthStateExpiredError`, `OAuthProviderError`, `RateLimitError`, `EmailVerificationError`, `MagicLinkError`, `PasswordResetError`, and more. The HTTP API maps them to status codes (`RateLimitError` → 429, `AuthError` → 500).

### HTTP endpoint reference

The included HTTP API speaks [JSON:API](https://jsonapi.org/) through `@thomasfosterau/effect-jsonapi`, an optional peer that only the `./http` subpath needs (#205). Every endpoint is one of two tiers ([ADR-0024](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0024-json-api-http-tier.md)): a JSON:API resource operation, or an endpoint whose wire format another specification fixes. The paths below are relative to the mount prefix (`/api/auth` by default). Upgrading from routes that are gone: the [migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md) maps every old endpoint to its replacement.

#### JSON:API resources

These take and answer `application/vnd.api+json` (a request with another media type is `415`, an `Accept` that excludes it `406`) and fail with JSON:API error documents (`Http.JsonApiErrors`: `status`, `detail` the message, `meta` carrying the `message` and, when there is one, the stable `code`). The resources are declared once, in `Http.Resources`.

| Endpoint                                                                               | Answer                                                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /sessions/current?include=user`                                                   | The session the request carries, its user in `included`                                                                                                                                                                                                                                                                                                                       |
| `DELETE /sessions/current`                                                             | Sign out: `204`, the session cookies cleared                                                                                                                                                                                                                                                                                                                                  |
| `GET /sessions` · `GET /sessions/:id`                                                  | The caller's sessions; an `id` is the stored id (the token's hash), never the token                                                                                                                                                                                                                                                                                           |
| `DELETE /sessions/:id`                                                                 | Revoke one of them; a foreign or unknown id is `404`                                                                                                                                                                                                                                                                                                                          |
| `DELETE /sessions?filter[current]=false`                                               | Revoke every session but the current one                                                                                                                                                                                                                                                                                                                                      |
| `GET /identifiers` · `DELETE /identifiers/:id`                                         | The caller's login handles (`kind` is the identifier's type); removing the last one is `403`                                                                                                                                                                                                                                                                                  |
| `PATCH /users/me`                                                                      | Update `name` / `image`; nothing else is writable, the `attributes` bag included                                                                                                                                                                                                                                                                                              |
| `POST /sessions`                                                                       | Sign in: a `sessions` document whose write-only `credential` attribute names the method (`password`, `username`, `email-otp`, `phone-otp`, `magic-link`, `anonymous`, `google-one-tap`). `201` with the session, its user in `included`; `202` with a `second-factor-challenges` resource, or with only `meta.needsEmailVerification` when the address must be verified first |
| `POST /second-factor-challenges/verifications`                                         | Redeem a second-factor challenge, named in the body, with a `totp` or `backup-code`; `201` with the session                                                                                                                                                                                                                                                                   |
| `POST /users`                                                                          | Sign up: `201` with the session when one is issued, else `202` with only `meta.needsEmailVerification`. Under `antiEnumeration` a fresh address and a held one both get the same `202`                                                                                                                                                                                        |
| `POST /otp-challenges`                                                                 | Send an email or SMS code, or a magic link (`channel`: `email`, `phone`, `magic-link`); `202` whether or not the account exists                                                                                                                                                                                                                                               |
| `POST /email-verifications` · `POST /email-verifications/redemptions`                  | (Re)send a verification link (`202`); verify with its token, `201` with the session when verification signs in, else `204`                                                                                                                                                                                                                                                    |
| `POST /password-resets` · `POST /password-resets/redemptions`                          | Request a reset link (`202`); set the new password with its token (`204`)                                                                                                                                                                                                                                                                                                     |
| `POST /google-one-tap-nonces`                                                          | A One Tap nonce, as the resource's id                                                                                                                                                                                                                                                                                                                                         |
| `PATCH /users/me/password`                                                             | Change the password (`currentPassword`, `newPassword`, `revokeOtherSessions`): `204`                                                                                                                                                                                                                                                                                          |
| `POST /email-changes` · `POST /email-changes/redemptions`                              | Request an address change (`202`, the link goes to the new address); confirm it with its token (`204`)                                                                                                                                                                                                                                                                        |
| `POST /account-deletions` · `POST /account-deletions/redemptions`                      | Request deletion (`202`, a confirmation link by email); confirm it with its token: `204`, the session cookies cleared                                                                                                                                                                                                                                                         |
| `POST /multi-factor-enrollments`                                                       | Start TOTP enrolment with the password: `201`, an unverified `multi-factor-enrollments` resource with `meta.secret`, `meta.totpUri` and `meta.backupCodes`                                                                                                                                                                                                                    |
| `PATCH /multi-factor-enrollments/current` · `DELETE /multi-factor-enrollments/current` | Confirm the enrolment with a `code` (`200`, `verified: true`); remove it with the password in `meta` (`204`)                                                                                                                                                                                                                                                                  |
| `POST /backup-code-sets`                                                               | A fresh set of backup codes, in `meta.backupCodes`; the old set stops working                                                                                                                                                                                                                                                                                                 |
| `GET /device-sessions`                                                                 | The accounts signed in on this device (multi-session), their users in `included`, `active` marking the current one; ids are the stored ids, never the tokens                                                                                                                                                                                                                  |
| `PATCH /device-sessions/active` · `DELETE /device-sessions/:id`                        | Switch the active account to a linked `device-sessions` id (`204`); sign one of them out (`204`)                                                                                                                                                                                                                                                                              |
| `GET /organizations` · `POST /organizations`                                           | The caller's organizations; create one (`201`)                                                                                                                                                                                                                                                                                                                                |
| `GET` · `PATCH` · `DELETE /organizations/:id`                                          | One organization; `PATCH` sets `name`, `slug`, `logo`, `metadata`, `jitProvisioning` and `defaultRole`                                                                                                                                                                                                                                                                        |
| `PATCH /organizations/active`                                                          | The session's active organization: a linkage to it, or `data: null` to clear it; `204`                                                                                                                                                                                                                                                                                        |
| `GET` · `POST /organizations/:id/members`                                              | Its `organization-members`; add one, the user as the `user` relationship (`201`)                                                                                                                                                                                                                                                                                              |
| `PATCH` · `DELETE /organization-members/:id`                                           | One membership by its stored id: `role`, and `status` (`inactive` deactivates, `active` reactivates); remove it (`204`)                                                                                                                                                                                                                                                       |
| `GET` · `POST /organizations/:id/invitations`                                          | Its invitations; invite by `email` and `role` (`201`)                                                                                                                                                                                                                                                                                                                         |
| `PATCH /invitations/:id` · `POST /invitations/:id/deliveries`                          | Move the `status` to `accepted` (the new membership in `meta.membership`), `rejected` or `canceled`; send it again with a fresh expiry (`202`)                                                                                                                                                                                                                                |
| `GET` · `POST /organizations/:id/domains`                                              | Its `organization-domains` (any member); claim one by `domain`, always a `dns` claim answering the `verificationToken` to publish (`201`, `domain:manage`); `verificationStrategy: "manual"` answers `400` (#598). Another organization's claim on the domain is never revealed                                                                                               |
| `DELETE /organization-domains/:id` · `POST /organization-domains/:id/verifications`    | Release a claim (`204`); run its DNS check, `200` with the claim `verified` or `failed`; `domain:manage` is never the proof, and a domain verified for another organization is refused                                                                                                                                                                                        |
| `GET` · `POST /organizations/:id/roles`                                                | Its custom `organization-roles` (any member); define one by `role` and `permissions` (`201`, `role:manage`), `409` when the organization already defines it                                                                                                                                                                                                                   |
| `PATCH` · `DELETE /organization-roles/:id`                                             | One definition by its stored id: replace its `permissions`; remove it (`204`)                                                                                                                                                                                                                                                                                                 |
| `GET` · `POST /organizations/:id/teams`                                                | Its `teams` (any member); create one by `name` (`201`, `team:create`)                                                                                                                                                                                                                                                                                                         |
| `PATCH` · `DELETE /teams/:id`                                                          | Rename a team; delete it and its memberships (`204`)                                                                                                                                                                                                                                                                                                                          |
| `GET` · `POST /teams/:id/members`                                                      | Its `team-members`; add a member of the organization, the user as the `user` relationship (`201`)                                                                                                                                                                                                                                                                             |
| `DELETE /team-members/:id`                                                             | Remove one team membership by its stored id (`204`)                                                                                                                                                                                                                                                                                                                           |
| `GET /organization-members/:id/teams`                                                  | The teams a membership's user belongs to                                                                                                                                                                                                                                                                                                                                      |
| `GET /admin/users`                                                                     | Admin: the `users`, `filter[email]` a case-insensitive substring of an address, paged by `page[offset]` / `page[limit]`, `meta.total` counting every match                                                                                                                                                                                                                    |
| `PATCH` · `DELETE /admin/users/:id` · `DELETE /admin/users/:id/sessions`               | Admin: set a user's `role`; delete the user (`204`); revoke every session of the user (`204`)                                                                                                                                                                                                                                                                                 |
| `POST /user-bans` · `DELETE /user-bans/:id`                                            | Admin: ban the user the `user` relationship names (optional `reason`, `expiresIn`), revoking their sessions: `201` with the `user-bans` resource (its id is the user's), the user included; lift it (`204`)                                                                                                                                                                   |
| `POST /admin/organization-domains`                                                     | Admin (`isAdmin`, never an organization permission): attest, after checking ownership out of band, that the `organization` relationship controls `domain` (`OrganizationService.attestDomain`, #598): `201` with its claim, `verified` with the `manual` strategy; a refusal is `400`                                                                                         |
| `POST /impersonations` · `DELETE /impersonations/current`                              | Admin: act as the user the `user` relationship names: `201` with the `impersonations` resource (its id the session's stored id, never the token), the session cookie swapped; end it, signing that session out (`204`; `404` on a session that is not an impersonation)                                                                                                       |
| `GET` · `POST /api-keys` · `PATCH` · `DELETE /api-keys/:id`                            | The caller's `api-keys`; mint one (`201`, the plaintext once in `meta.key`; the session cookie required, a bearer credential is `403`); change or delete one                                                                                                                                                                                                                  |
| `GET` · `POST /oauth-clients` · `PATCH` · `DELETE /oauth-clients/:id`                  | Admin: the OIDC provider's `oauth-clients` (their `type` as `clientType`); register one (`201`, a confidential client's secret once in `meta.clientSecret`)                                                                                                                                                                                                                   |
| `POST /sso-providers`                                                                  | Admin: register an OIDC or SAML connection (`201`, never the client secret; the optional `organization` relationship, `{ data: { type: "organizations", id } }` or `data: null`, in the request and the answer)                                                                                                                                                               |
| `POST /sso-authorizations`                                                             | Start an SSO sign-in by `email`, `domain` or `providerId`: `201`, the IdP `url` to send the browser to, the round-trip state as the id                                                                                                                                                                                                                                        |
| `POST /tokens`                                                                         | A JWT for the signed-in user: `201`, `token` and `expiresAt`, the id the token's digest                                                                                                                                                                                                                                                                                       |
| `POST /device-authorizations/decisions`                                                | Approve (signed in) or deny a device's `userCode`, carried in the body: `204`                                                                                                                                                                                                                                                                                                 |

#### The RFC tier

These keep the wire format their specification fixes, and are never JSON:API documents: an OAuth client, an IdP or a SCIM provisioner built to the specification would not accept one, so "finishing the conversion" here would break every conforming peer. They are the `auth` and `scim` groups of the contract. `OpenApi.test.ts` checks that none of them declares `application/vnd.api+json` (and that every resource group does), and each endpoint's suite pins its media type.

| Endpoint                                                                                                                   | Specification                                                        | Wire format                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /device/code` · `POST /device/token`                                                                                 | RFC 8628 (device authorization grant), the device side               | `application/json` in and out. The poll refuses with the grant's error codes (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`) as the `message` of a `400`; an approved poll answers the user and sets the session cookie. Its members are camelCase (`deviceCode`, `userCode`, `verificationUri`, `expiresIn`, `interval`) |
| `GET /oauth2/authorize`                                                                                                    | OAuth 2.0 (RFC 6749 §3.1), OIDC Core                                 | A `302` to the client's `redirect_uri` (with `code` and `state`), the login page or the consent page; never a body                                                                                                                                                                                                                                 |
| `POST /oauth2/consent`                                                                                                     | The consent step of the same authorization request                   | `application/json` `{ consentCode, accept }` from the consent page, answered with `{ redirectTo }`, the authorization response to send the browser to                                                                                                                                                                                              |
| `POST /oauth2/token`                                                                                                       | OAuth 2.0 (RFC 6749 §3.2), OIDC Core                                 | `application/x-www-form-urlencoded` (or JSON), client credentials in the body or a Basic header; answers `application/json` `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token`, `scope`                                                                                                                                       |
| `GET /oauth2/userinfo`                                                                                                     | OIDC Core §5.3                                                       | The bearer access token's claims, as `application/json`                                                                                                                                                                                                                                                                                            |
| `POST /register` · `GET` · `PUT` · `DELETE /register/:clientId`                                                            | RFC 7591 / RFC 7592 (dynamic client registration and its management) | `application/json` client metadata (`201` on register, `204` on delete); refusals are `{ error, error_description }`. `404` unless the provider is configured with `dynamicRegistration`                                                                                                                                                           |
| `GET /.well-known/openid-configuration` · `GET /.well-known/oauth-authorization-server`                                    | OIDC Discovery, RFC 8414                                             | `application/json` metadata; `registration_endpoint` is advertised only while dynamic registration is enabled                                                                                                                                                                                                                                      |
| `GET /jwks` · `GET /.well-known/jwks.json`                                                                                 | RFC 7517 (JSON Web Key Set)                                          | `application/json` `{ keys }`: the keys that verify `POST /tokens`' JWTs and the OIDC provider's ID tokens                                                                                                                                                                                                                                         |
| `POST /sso/callback`                                                                                                       | OIDC relying party: the authorization response                       | `application/json` `{ state, code }` as the IdP returned them; answers the user and sets the session cookie                                                                                                                                                                                                                                        |
| `POST /sso/saml/acs/:providerId`                                                                                           | SAML 2.0 HTTP-POST binding (assertion consumer service)              | The IdP's browser form, `application/x-www-form-urlencoded` `SAMLResponse` and `RelayState`; answers the user and sets the session cookie                                                                                                                                                                                                          |
| `GET /sso/saml/metadata/:providerId`                                                                                       | SAML 2.0 metadata                                                    | The SP's `EntityDescriptor` as `application/samlmetadata+xml`, for an IdP to import by URL                                                                                                                                                                                                                                                         |
| `/scim/v2/Users` · `/Users/:id` · `/Groups` · `/Groups/:id` · `GET /ServiceProviderConfig` · `/ResourceTypes` · `/Schemas` | SCIM 2.0 (RFC 7643 / RFC 7644)                                       | `application/scim+json` in and out, SCIM error bodies (RFC 7644 §3.12); authenticated by an organization's provisioning bearer token                                                                                                                                                                                                               |

`Http.groupLayers` is every group of the contract with the JSON:API protocol middleware on the resource groups, for serving `AuthApi` from your own `HttpApiBuilder`.

## Browser client (`/client`)

The browser half of [effect-auth](https://github.com/thomasfosterau/effect-auth), in two subpaths:

- `/client`: a small client over the effect-auth HTTP contract (plain `fetch`, no Effect runtime in the bundle). It holds no session state; it tells its observers when a call changed the session.
- `/client/atoms`: the session as [`effect/reactivity`](https://effect.website/) Atoms over that client, read through your application's `AtomRegistry`, so auth shares one Atom graph and one runtime with the rest of the page.

Only the wire _types_ come from the `/http` subpath, and those erase at compile time, so nothing server-side reaches the browser bundle. `/client` needs `effect` for its types only; `/client/atoms` imports `effect` at runtime, and only it does. The root barrel re-exports neither.

### Usage

```ts
import { AuthClientError, createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";
import { AtomRegistry } from "effect/reactivity";

const client = createAuthClient({ baseUrl: "/api/auth" });

// The session, as Atoms over the client, read through the page's one registry.
const registry = AtomRegistry.make();
const auth = makeSessionAtoms(client, { refresh: { onFocus: true } });
const unsubscribe = registry.subscribe(
  auth.state,
  ({ data, isPending, error }) => {
    console.log(isPending ? "loading" : (data?.user.id ?? "signed out"), error?.message);
  },
  { immediate: true },
);

// Commands are plain calls named after the contract's endpoints. A
// session-changing call resolves once the observed session has refetched.
const result = await client.signIn({ email: "ada@example.com", password: "correct horse" });
if (result.secondFactor) {
  // Password accepted; a second factor is required before a session is issued.
  await client.multiFactor.continueChallenge(result).verifyTotp("123456");
}
console.log(registry.get(auth.isSignedIn)); // true

try {
  await client.signIn({ email: "ada@example.com", password: "wrong" });
} catch (error) {
  if (error instanceof AuthClientError && error.status === 401) {
    console.log("bad credentials");
  }
}

unsubscribe();
```

Every request is sent with `credentials: "include"`, so the session cookie flows on cross-origin deployments too (the server must list your origin in `trustedOrigins`). A non-2xx response rejects with an `AuthClientError` carrying the HTTP `status` and the server's `message`. Optional server features that are not configured answer `404`: a method existing on the client does not mean the server mounted it.

### Options

`createAuthClient(options: AuthClientOptions): AuthClient`

| Option    | Type                     | Purpose                                                              |
| --------- | ------------------------ | -------------------------------------------------------------------- |
| `baseUrl` | `string`                 | Where the auth handler is mounted: `"/api/auth"` or an absolute URL. |
| `fetch`   | `typeof fetch`           | Custom `fetch`: SSR, tests, or an in-process handler.                |
| `headers` | `Record<string, string>` | Extra headers on every request.                                      |

`client.onSessionChange(listener)` registers an observer of session-changing calls (every sign-in and sign-up, sign-out, second-factor redemption, email verification, the email-change and account-deletion confirmations, `updateUser`, `multiSession.setActive`, `organization.setActive`, impersonation, the SSO callback and the device token poll) and returns its removal; the call resolves only once every observer's promise has settled, and an observer's rejection never fails it. `client.invalidateSession()` notifies the observers by hand, for a change the client did not make. The session Atoms are such an observer; you rarely register one yourself.

### The session Atoms (`/client/atoms`)

`makeSessionAtoms(client, options?: SessionAtomsOptions): SessionAtoms`. Make them once per client and read them through your registry:

| Atom            | Value                                                                                 |
| --------------- | ------------------------------------------------------------------------------------- |
| `result`        | `AsyncResult<SessionWithUserView \| null, AuthClientError>`, the session read itself  |
| `state`         | `SessionState`: `{ data, isPending, error }`                                          |
| `data`          | The `SessionWithUserView`, or `null` when signed out                                  |
| `isSignedIn`    | `boolean`                                                                             |
| `isPending`     | `boolean`: the read is in flight                                                      |
| `error`         | The last unexpected `AuthClientError`, or `null`                                      |
| `sessions`      | `AsyncResult<readonly SessionView[], AuthClientError>`, the signed-in user's sessions |
| `sessionsState` | `SessionListState`: `{ data, isPending, error }` over `sessions`                      |

The read is lazy: nothing is fetched until a registry reads or mounts an Atom, and it starts pending, so a UI never flashes "signed out" before the first fetch. A `401` is `data: null`, not an error; any other failure keeps the last `data` and sets `error`; a refetch superseded by a later one is interrupted, so its answer never lands. While a session Atom is mounted, every session-changing call refetches it before it resolves; with nothing mounted, the round trip is skipped, and the next subscriber starts from the last read. `registry.refresh(auth.isSignedIn)` (or any session Atom) refetches; `registry.refresh(auth.sessions)` re-reads the list.

A session change propagates through the graph: an Atom of your own that reads `auth.data` or `auth.isSignedIn` recomputes on sign-in and sign-out with no invalidation list, and `sessions` refetches when the session's id changes (signed out, it is empty without a request).

`options.refresh` (`RefreshOptions`) turns on background refresh while the session is observed, all off by default: `intervalMs` polls `GET /sessions/current`; `onFocus` refetches on window focus and when the tab becomes visible; `crossTab` mirrors session changes across tabs over a `BroadcastChannel` (`true` for the default channel name `"effect-auth-session"`, or a name of your own). Each starts with the first subscriber, stops with the last, and degrades to a no-op outside a browser.

### Methods

Each method resolves to the contract's own view type (`Http.*`). Groups:

| Group            | Methods                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Session and user | `signUp`, `signIn`, `signOut`, `signInAnonymous`, `signInUsername`, `getSession` (`null` when signed out), `updateUser`, `changePassword`, `listSessions`, `revokeSession`, `revokeOtherSessions`, `jwtToken`, `jwks`                                                                                                                                                                                                                                                         |
| Email            | `sendVerificationEmail`, `verifyEmail`, `passwordResetRequest`, `passwordResetConfirm`, `magicLink.send` / `.verify`, `emailOtp.send` / `.signIn`, `changeEmail.request` / `.confirm`                                                                                                                                                                                                                                                                                         |
| Phone and others | `phoneOtp.send` / `.signIn`, `googleOneTap.nonce` / `.signIn`, `device.code` / `.token` / `.approve` / `.deny` (RFC 8628)                                                                                                                                                                                                                                                                                                                                                     |
| Account          | `identifiers.list` / `.delete`, `deleteUser.request` / `.confirm`, `multiSession.list` / `.setActive` / `.revoke`                                                                                                                                                                                                                                                                                                                                                             |
| Multi-factor     | `multiFactor.enable`, `.confirm`, `.disable`, `.regenerateBackupCodes`, `.verifyTotp`, `.verifyBackupCode`, `.challenge(challenge)`, `.continueChallenge(result)`                                                                                                                                                                                                                                                                                                             |
| Organizations    | `organization.create`, `list`, `get`, `update`, `delete`, `setActive`, members (`addMember`, then by the membership's own `id`: `updateMemberRole`, `removeMember`, `deactivateMember`, `reactivateMember`, `listTeamsForMember`; `setDefaultRole`), invitations, domains (`removeDomain` / `verifyDomain` by the claim's `id`), roles (`createRole`, then `updateRole` / `deleteRole` by the definition's `id`) and teams (`removeTeamMember` by the team membership's `id`) |
| API keys         | `apiKeys.create` (the plaintext key is returned once), `list`, `update`, `delete`                                                                                                                                                                                                                                                                                                                                                                                             |
| Admin            | `admin.listUsers`, `setRole`, `banUser`, `unbanUser` (resolves with nothing), `removeUser`, `revokeSessions`, `impersonate`, `stopImpersonating`, `attestDomain` (the operator's domain attestation)                                                                                                                                                                                                                                                                          |
| SSO and OIDC     | `sso.register` / `.signIn` / `.callback`; `oidc.registerClient`, `listClients`, `updateClient`, `deleteClient`, `consent`                                                                                                                                                                                                                                                                                                                                                     |

`multiFactor.continueChallenge(result)` takes the `AuthResult` a sign-in returned and binds its pending challenge, so the caller passes only the code. It throws `SecondFactorChallengeError` (`reason: "missing"`) when the result carries no challenge, and its `verifyTotp` / `verifyBackupCode` reject with `reason: "expired"` once the challenge window has passed, without a request.

### Plugins

`definePlugin(install)` builds a plugin whose `install(context)` returns extra methods; `client.extend(plugin)` returns the client with them added. The context (`AuthClientPluginContext`) exposes `request(method, path, body?)` and `mutating(run)` (run a session-changing call, then notify the session observers).

```ts
import { createAuthClient, definePlugin } from "@thomasfosterau/effect-auth/client";

interface Profile {
  readonly bio: string;
}

const profilePlugin = definePlugin((ctx) => ({
  profile: () => ctx.request<Profile>("GET", "/profile"),
}));

const client = createAuthClient({ baseUrl: "/api/auth" }).extend(profilePlugin);
const profile = await client.profile();
```

### Testing: `/client/testing`

An in-process effect-auth server for end-to-end client tests: the real `Http.make` handler over in-memory stores, and a `fetch` that emulates the browser's cookie jar. Unlike `/client`, it imports the core and `effect` at runtime (and `@thomasfosterau/effect-jsonapi`, through the HTTP tier), so keep it to tests.

```ts
import { createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeCookieJarFetch, makeServerFixture } from "@thomasfosterau/effect-auth/client/testing";

const server = makeServerFixture({ features: true });
const client = createAuthClient({
  baseUrl: "http://localhost", // the fixture handler is mounted at the root
  fetch: makeCookieJarFetch(server.handler),
});

await client.signUp({ email: "ada@example.com", password: "correct horse battery staple" });
console.log(server.sessions.size); // 1
```

`makeServerFixture(options?)` mounts optional modules only when asked: `features` (username and anonymous sign-in, multi-factor, account management, phone OTP, device authorization, with an in-memory `RateLimiter`), `organization`, and `multiSession`. It returns the `handler` plus the in-memory state and the messages the server "sent" (`sentChangeEmail`, `sentDeleteTokens`, `sentPhoneOtps`), for assertions.

### API

- `createAuthClient(options)`, `AuthClient`, `AuthClientOptions`, `SessionChangeListener`
- `AuthClientError` (`status`), `SecondFactorChallengeError` (`reason`), `SecondFactorContinuation`
- `definePlugin`, `AuthClientPlugin`, `AuthClientPluginContext`
- `./client/atoms`: `makeSessionAtoms`, `SessionAtoms`, `SessionAtomsOptions`, `RefreshOptions`, `SessionState`, `SessionListState`, `SessionResult`, `SessionListResult`
- `./client/testing`: `makeServerFixture`, `ServerFixtureOptions`, `makeCookieJarFetch`

### Framework bindings

| Framework | Package                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------- |
| Svelte    | [`@thomasfosterau/effect-auth-svelte`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-svelte) |

The [client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) walks through the binding and its form components.

## SQL storage (`/sql`)

Driver-agnostic SQL storage, built on `effect/sql`: one `Layer` that implements the core's store contracts over any `SqlClient`, plus the DDL that creates their tables.

`effect/sql` ships in `effect`, so the subpath adds no dependency. Add a `SqlClient` driver for a [supported dialect](#dialects) at the same version as `effect` (for example `@effect/sql-pg`); the package bundles none. On Alchemy, [`@thomasfosterau/effect-auth-alchemy-cloudflare`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-cloudflare) (D1) and [`@thomasfosterau/effect-auth-alchemy-postgres`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/alchemy-postgres) wire these stores to a database and reconcile the schema on deploy.

### Usage

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

// `SqlLive` is any layer providing `SqlClient` for a supported dialect (SQLite, D1, PostgreSQL).
export const makeAuth = (SqlLive: Layer.Layer<SqlClient.SqlClient>) => {
  // Creates the `auth_*` tables; idempotent, so it is safe on every deploy.
  const migrate = AuthSql.migrate.pipe(Effect.provide(SqlLive));

  const sessionConfig: Auth.SessionConfig = {
    sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
  };
  const AuthLive = Auth.SessionService.layer(sessionConfig).pipe(
    Layer.provideMerge(Layer.mergeAll(AuthSql.layer, Auth.Hooks.Default)),
    Layer.provide(SqlLive),
  );
  return { migrate, AuthLive };
};
```

`AuthSql.layer` provides every store below at once, so any service built over them (`EmailPasswordService`, `OAuthService`, `WebAuthnService`, `MagicLinkService`, `MultiFactorService`, `ApiKeyService`, `AdminService`, …) has persistence once it is composed on top.

### Stores

`layer` is `Layer<…every store…, never, SqlClient>`. Each store is also available on its own, as an `Effect` that builds it (`make<Name>`) and as a `Layer` (`<Name>Layer`), for wiring a subset:

| Store (core tag)                           | Constructor / layer                                            | Table                                                             |
| ------------------------------------------ | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| `Auth.SessionStore`                        | `makeSessionStore` / `SessionStoreLayer`                       | `auth_sessions`                                                   |
| `Auth.UserStore`                           | `makeUserStore` / `UserStoreLayer`                             | `auth_users`                                                      |
| `Auth.UserServiceStore`                    | `makeUserServiceStore` / `UserServiceStoreLayer`               | `auth_users`                                                      |
| `Auth.IdentifierStore`                     | `makeIdentifierStore` / `IdentifierStoreLayer`                 | `auth_identifiers`                                                |
| `Auth.Email.EmailPasswordStore`            | `makeEmailPasswordStore` / `EmailPasswordStoreLayer`           | `auth_users`                                                      |
| `Auth.Email.EmailVerificationStore`        | `makeEmailVerificationStore` / `EmailVerificationStoreLayer`   | `auth_email_verifications`                                        |
| `Auth.Email.EmailOtpStore`                 | `makeEmailOtpStore` / `EmailOtpStoreLayer`                     | `auth_email_otps`, `auth_email_otp_failures`                      |
| `Auth.Email.EmailOtpUserStore`             | `makeEmailOtpUserStore` / `EmailOtpUserStoreLayer`             | `auth_users`                                                      |
| `Auth.Password.PasswordResetStore`         | `makePasswordResetStore` / `PasswordResetStoreLayer`           | `auth_password_resets`                                            |
| `Auth.Password.PasswordResetUserStore`     | `makePasswordResetUserStore` / `PasswordResetUserStoreLayer`   | `auth_users`                                                      |
| `Auth.MagicLinkStore`                      | `makeMagicLinkStore` / `MagicLinkStoreLayer`                   | `auth_magic_links`                                                |
| `Auth.MagicLinkUserStore`                  | `makeMagicLinkUserStore` / `MagicLinkUserStoreLayer`           | `auth_users`                                                      |
| `Auth.RateLimitStore`                      | `makeRateLimitStore` / `RateLimitStoreLayer`                   | `auth_rate_limits`                                                |
| `Auth.MultiFactor.ChallengeStore`          | `makeChallengeStore` / `ChallengeStoreLayer`                   | `auth_webauthn_challenges`                                        |
| `Auth.MultiFactor.CredentialStore`         | `makeCredentialStore` / `CredentialStoreLayer`                 | `auth_webauthn_credentials`                                       |
| `Auth.MultiFactor.MultiFactorStore`        | `makeMultiFactorStore` / `MultiFactorStoreLayer`               | `auth_multi_factor`                                               |
| `Auth.MultiFactor.PendingMultiFactorStore` | `makePendingMultiFactorStore` / `PendingMultiFactorStoreLayer` | `auth_pending_multi_factor`, `auth_pending_multi_factor_attempts` |
| `Auth.OAuth.OAuthStateStore`               | `makeOAuthStateStore` / `OAuthStateStoreLayer`                 | `auth_oauth_states`                                               |
| `Auth.OAuth.OAuthAccountStore`             | `makeOAuthAccountStore` / `OAuthAccountStoreLayer`             | `auth_oauth_accounts`                                             |
| `Auth.OAuth.OAuthUserStore`                | `makeOAuthUserStore` / `OAuthUserStoreLayer`                   | `auth_users`                                                      |
| `Auth.Plugins.AccountLockoutStore`         | `makeAccountLockoutStore` / `AccountLockoutStoreLayer`         | `auth_account_lockouts`                                           |
| `Auth.ApiKeyStore`                         | `makeApiKeyStore` / `ApiKeyStoreLayer`                         | `auth_api_keys`                                                   |
| `Auth.AdminUserStore`                      | `makeAdminUserStore` / `AdminUserStoreLayer`                   | `auth_users`                                                      |

```typescript
import { Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

// Only sessions, users and identifiers, on top of an existing `SqlClient` layer.
export const coreStores = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.mergeAll(
    AuthSql.SessionStoreLayer,
    AuthSql.UserStoreLayer,
    AuthSql.IdentifierStoreLayer,
  ).pipe(Layer.provide(SqlLive));
```

Not covered yet: the stores added to the core later (one-time tokens, trusted devices, phone OTP, organizations, the OIDC provider, SSO, device authorization). Implement those contracts yourself for now. (The core's `KeyValueStore`-backed layers, `OAuthStateStoreKV`, `ChallengeStoreKV`, `RateLimitStoreKV` and the rest, cover only the short-lived stores, not these.)

### Schema and migration

- `schemaStatements: readonly string[]` — the ordered DDL, one statement per entry, every one `CREATE TABLE IF NOT EXISTS` or `CREATE [UNIQUE] INDEX IF NOT EXISTS` over `auth_`-prefixed tables, so they live beside your own.
- `migrate: Effect<void, Auth.AuthError, SqlClient>` — runs `schemaStatements` through the ambient `SqlClient`. Safe on every deploy and every cold start.

Storage format: instants are epoch milliseconds in `BIGINT` columns (past 2038 on every engine), booleans `0`/`1`, attribute bags JSON `TEXT`, binary values (WebAuthn challenges and public keys) base64 `TEXT`. Token columns (`auth_sessions.id`, the magic-link, verification and reset tokens, `auth_api_keys.key_hash`) hold the SHA-256 digest the service layer computed: the database never sees a raw bearer token.

- `purgeExpired: Effect<PurgeExpiredResult, Auth.AuthError, SqlClient>` — deletes the `auth_magic_links` and `auth_email_otps` rows whose `expires_at` has passed (read from the `Clock`) and reports how many went from each. No store deletes them on its own: a code or link nobody redeems stays until a later send for the same address replaces it, and the sends that hide whether an account exists write one for any address, so without a purge those tables grow with every distinct address a caller tries. Schedule it from the host: a cron trigger on Workers, a timer or job on a long-lived server. The services already refuse an expired row, so a purge changes no outcome.

Upserts and counters are single `ON CONFLICT … DO UPDATE` / `UPDATE … RETURNING` statements, so they are atomic without a transaction. Multi-step writes (`ChallengeStore.create`, `OAuthStateStore.create`, `EmailOtpStore.upsert`, `IdentifierStore.replace`) run inside `sql.withTransaction`.

### Authorization

Role data lives in two tables, `auth_user_roles` (user → role) and `auth_role_permissions` (role → `resource` / `action`), but `layer` does not wire authorization: an `EntityResolver` is one slot the application composes, not a store.

- `makeRbacEntityResolver` / `RbacEntityResolverLayer` — an `Auth.EntityResolver` that answers `User::"<id>"` references with a `Role::"<role>"` parent per assigned role. It answers only `User` references and adds no role-to-role edges, so compose it with your own resolver when policies name other entities.
- `readRbacPolicies: Effect<ReadonlyArray<Auth.Policy.DeclarativePolicy>, never, SqlClient>` — reads `auth_role_permissions` and compiles it with `Auth.Rbac.policies`, the same policies a hand-written `Auth.Rbac` configuration produces.

```typescript
import { Effect, Layer } from "effect";
import type { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

export const authorization = (SqlLive: Layer.Layer<SqlClient.SqlClient>) =>
  Layer.unwrap(
    Effect.map(AuthSql.readRbacPolicies, (policies) => Auth.Authorizer.layer({ policies })),
  ).pipe(Layer.provide(AuthSql.RbacEntityResolverLayer), Layer.provide(SqlLive));
```

Policies are read once, when the layer is built; re-read them behind a `PolicyStore` if role edits must apply without a restart.

### Read scopes

`readScopeWhere(scope, { columns, sets? })` renders a core `Auth.ReadScope` as a `WHERE` fragment, so a LIST filters in the database rather than after the fact. `Auth.ReadScope.compile` produces the scope from a policy set (ADR-0020).

```typescript
import { Effect } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthSql from "@thomasfosterau/effect-auth/sql";

export const listPosts = (scope: Auth.ReadScope.ReadScope, viewerId: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const where = yield* AuthSql.readScopeWhere(scope, {
      columns: { owner: sql("owner_id"), visibility: sql("visibility"), draft: sql("draft") },
      sets: { following: sql`SELECT followee FROM follows WHERE follower = ${viewerId}` },
    });
    return yield* sql`SELECT * FROM posts WHERE ${where}`;
  });
```

- `AllowAll` renders `1 = 1` and `Deny` renders `1 = 0`, so the fragment always splices in.
- Every comparison carries an `IS NOT NULL` guard, so a NULL column decides as the core decides an absent attribute and never through SQL's third truth value.
- A named set is a subquery and is never materialised. A set with no fragment in `sets` is dropped with `ReadScope.withoutSets`, which narrows the scope.
- An attribute with no column in `columns` lists nothing.

### Dialects

- **SQLite:** supported. The test suite runs every store over `better-sqlite3`.
- **Cloudflare D1:** supported. D1 is SQLite; [`@thomasfosterau/effect-auth-alchemy-cloudflare`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-alchemy-cloudflare) wires it, and its suite runs these stores over a SQLite-backed D1 shim. D1 has no interactive transactions, so there a transaction's writes are sent as `batch()`es: the writes between two reads commit together, but not across a read (see that package's README).
- **PostgreSQL:** supported. The same suite runs over PostgreSQL through PGlite (`@effect/sql-pglite`).
- **MySQL:** not supported ([#260](https://github.com/thomasfosterau/effect-auth/issues/260)). MySQL has no `ON CONFLICT` clause, so the upserts and counters fail. For MySQL, use [`@thomasfosterau/effect-auth-drizzle`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-drizzle) with its MySQL tables (`Drizzle.MySql`). That package covers only `SessionStore`, `UserStore` and `IdentifierStore`, and its MySQL suite runs against `drizzle-orm/mysql-proxy`, not a MySQL server.

### Errors

Every store method fails only with `Auth.AuthError` (an infrastructure failure, the driver's error kept as `cause`); a lookup that finds nothing returns `null`, and the core services turn that into their typed errors. A unique-index violation (an identifier, an OAuth account, an API key hash) is an `AuthError` too, which the core resolves into the domain error (`IdentifierTakenError`, …).

## SAML (`/saml`)

SAML 2.0 service-provider support, as an Effect `Layer`.

The root of the core declares the `SamlVerifier` contract but implements none
of it: XML canonicalisation, XML-DSig verification and DEFLATE need a
dependency the rest of the core does not carry. This subpath is the
implementation, over [`@node-saml/node-saml`](https://github.com/node-saml/node-saml),
an **optional peer** of `@thomasfosterau/effect-auth` that only `/saml`
imports:

```sh
pnpm add @thomasfosterau/effect-auth @node-saml/node-saml effect
```

**`/saml` is Node-only.** node-saml needs Node APIs, so this subpath does not
run on Cloudflare Workers or in a browser; the rest of the core does. The root
barrel never reaches node-saml (`ModuleGraph.test.ts` pins it).

The **flow** stays in the root's `SsoService` — domain routing, one-time use of
the `AuthnRequest` and the assertion, issuer pinning, user provisioning,
sessions. Only the XML job lives here.

### Usage

```ts
import { Layer } from "effect";
import * as Saml from "@thomasfosterau/effect-auth/saml";
import { SamlReplayStore, SsoService, memorySamlReplayStore } from "@thomasfosterau/effect-auth";

const samlSupport = Layer.mergeAll(
  Saml.layer,
  Layer.succeed(SamlReplayStore)(memorySamlReplayStore()),
);

const ssoLayer = SsoService.layer().pipe(Layer.provide(samlSupport));
```

Register a connection, then start and finish sign-ins:

```ts
import { Effect } from "effect";
import { SsoService } from "@thomasfosterau/effect-auth";

// Register once (admin-gated), with the IdP's signing certificate(s) pinned.
const register = (adminUserId: string, idpCertificatePem: string) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    return yield* sso.registerSamlProvider(adminUserId, {
      protocol: "saml",
      domain: "acme.test",
      entityId: "https://idp.acme.test/metadata", // the IdP's Issuer
      ssoUrl: "https://idp.acme.test/sso", // HTTP-Redirect binding
      idpCertificates: [idpCertificatePem], // pinned; rotation-ready
      spEntityId: "https://app.test/saml/metadata",
      acsUrl: "https://app.test/api/auth/sso/saml/acs",
      organizationId: "org-1",
    });
  });

// Start: redirect the browser to `url`; the IdP echoes `state` back as RelayState.
const start = (email: string) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    return yield* sso.signIn({ email });
  });

// Finish, at the ACS endpoint: verify the posted SAMLResponse and issue a session.
const finish = (providerId: string, samlResponse: string, relayState: string) =>
  Effect.gen(function* () {
    const sso = yield* SsoService;
    const { user, session, isNewUser } = yield* sso.handleSamlCallback(
      providerId,
      samlResponse,
      relayState,
    );
    return { userId: user.id, sessionToken: session.id, isNewUser };
  });

export { register, start, finish };
```

`memorySamlReplayStore` is single-process. Behind more than one instance,
implement `SamlReplayStore` against shared storage — a replay defence that only
remembers what one process saw is not a replay defence. Both of its operations
must be atomic; the tag's docs spell out what that means.

### What gets checked

`verify` refuses a response unless all of the following hold. Every one is a
rejection, not a warning:

| Check                                                                 | Enforced by                |
| --------------------------------------------------------------------- | -------------------------- |
| Signature verifies against a **pinned** certificate (never `KeyInfo`) | node-saml + xml-crypto     |
| Profile data read only from signature-covered bytes                   | node-saml `getVerifiedXml` |
| At most one `Assertion` per `Response`                                | node-saml                  |
| No `ID` referring to more than one element                            | node-saml                  |
| `Assertion` signed (or the whole `Response`, if you disable that)     | node-saml                  |
| `Issuer` matches the connection's IdP entity id                       | node-saml + `/saml`        |
| `AudienceRestriction` contains the SP entity id                       | node-saml                  |
| `Conditions` `NotBefore`/`NotOnOrAfter`, within the clock-skew window | node-saml                  |
| `SubjectConfirmationData` `Recipient` equals the ACS URL              | `/saml`                    |
| `SubjectConfirmationData` `NotOnOrAfter`                              | `/saml`                    |
| `Destination` equals the ACS URL                                      | `/saml`                    |
| Signed `InResponseTo` agrees with the `Response` attribute            | `/saml`                    |
| Signature/digest algorithms on an allow-list (SHA-256+ by default)    | `/saml`                    |
| HMAC signature methods refused outright                               | `/saml`                    |
| Encrypted assertions refused with an actionable message               | `/saml`                    |
| `AuthnRequest` and `Assertion` ids each spendable once                | core `SsoService`          |

`src/saml/Verifier.test.ts` reproduces the corresponding attack shapes against
hand-built, signed XML fixtures.

### Encrypted assertions

Not supported in this version. Configure the IdP for **signed, unencrypted**
assertions delivered over TLS; a half-implemented decryption path is worth less
than a clear refusal.

### Version floor

`@node-saml/node-saml` is pinned to `^5.1.0` and must never be relaxed below it.
5.1.0 is the release that fixed the July 2025 signature-scope vulnerabilities
(CVE-2025-54419, CVE-2025-54369), where a crafted document could get profile
data read from bytes the signature did not cover.

### API

- `layer: Layer<SamlVerifier>` — core's `SamlVerifier`, for the layer stack that builds `SsoService` (together with a `SamlReplayStore`).
- `verifier` — the same implementation as a plain object (`verify`, `buildAuthnRequest`, `spMetadataXml`), for a call site with no Effect context, such as a metadata script.
- `EMAIL_NAMEID_FORMAT` — the `emailAddress` NameID format, the default for `AuthnRequest`s and SP metadata.

Every failure is core's `SamlError`. The input and output types (`SamlVerifyInput`, `SamlAssertion`, `SamlAuthnRequestInput`, `SamlMetadataInput`, `SamlSignatureAlgorithm`) and the defaults `defaultSignatureAlgorithms` (SHA-256, SHA-512) and `defaultClockSkewMs` (3 minutes) are exported by `@thomasfosterau/effect-auth`.

## Further reading

- [The three-library boundary](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/BOUNDARY.md): how this library relates to effect-jsonapi and legation.
- [Architecture](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/ARCHITECTURE.md), including the security model; [design decisions](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/DESIGN.md) and [ADRs](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/README.md).
- Guides: [bring your own store](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/byo-stores.md), [the browser client](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md), [MCP provider](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/mcp-provider.md), [SCIM](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/scim.md), [auth as a separate service](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/split-auth-service.md), [rate limits and sessions on Durable Objects](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/workers-durable-objects.md), [migrating from Better Auth](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/better-auth-migration.md).
- [Observability](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/OBSERVABILITY.md): spans and metrics.

## License

MIT
