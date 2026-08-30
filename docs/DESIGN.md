# effect-auth — Settled Design & Public API (pre-1.0 decision record)

Status: **Adopted and applied.** The non-breaking normalizations landed first;
the breaking proposals below were put to the maintainer (2026-07-03), approved
(see "Maintainer decisions" at the end), and have been applied behind
Changesets. Date: 2026-07-03/04. Supersedes the architectural framing in `ARCHITECTURE.md`
(rewritten alongside this document) and the status header of `HOOKS_DESIGN.md`.

> **Superseded (partially) by the directory/export restructure.** The API
> restructure milestone (`docs/refactor-plan.md`, `docs/migration.md`) landed
> after this document and revisited two calls made below: the service formerly
> named `SessionManager` is now `SessionService` (renamed as part of the
> restructure's naming pass), and the `XShape` interface convention decided in
> D1's "implementation finding" was reversed — `*Shape` interfaces are deleted
> outright; implementors reference `typeof X.Service` instead. The rest of this
> document's rationale and decisions still hold; read D1 and D9 below with
> those two corrections in mind, and see `docs/migration.md` for the full
> rename table.

This document records, per design dimension: **status quo → problem → decision →
rationale → migration & blast radius → risk**. Evidence lines reference the tree at
the time of writing. The yardstick throughout is the Effect v4 service idiom
(`effect-solutions show services-and-layers error-handling`): `Context.Service`
classes named after the service, layers as camelCase `static` members (`layer`,
`layerConfig`, `testLayer`), `R = never` on service methods, tagged errors.

---

## The settled surface in one screen

```ts
import * as Auth from "@thomasfosterau/effect-auth";

// Canonical: the service name IS the export; layers are statics on it.
const app = Effect.gen(function* () {
  const sessions = yield* Auth.SessionService;
  const session = yield* sessions.createSession(userId);
}).pipe(
  Effect.provide(Auth.SessionService.layer({ sessionExpiresIn })),
  Effect.provide(Auth.Email.EmailPasswordService.layer()),
  Effect.provide(Auth.Hooks.Default),
);
```

- **Service access:** `yield* Auth.X` where `X` is the service name
  (`SessionService`, `EmailPasswordService`, `WebAuthnService`, …).
- **Layer construction:** `Auth.X.layer(config)` — a `static` on the service class,
  mirroring `Hooks.Default` (core) and `WorkOS.layer/layerOptions/layerClient`
  (`packages/workos/src/WorkOS.ts:246`), which already follow the Effect v4 idiom.
- **Stores:** you implement a value of type `typeof Auth.XStore.Service` (no
  separate `XStoreShape` interface) and provide it with
  `Layer.succeed(Auth.XStore)(impl)` or a first-party layer from
  `@effect-auth/sql`, `@effect-auth/alchemy`, or the KV layers in core.
- **Errors:** tagged errors, `AuthError` for infrastructure failure, specific tags
  for flow outcomes; lookups that can legitimately miss return `X | null` from
  stores and surface typed errors from services.
- **HTTP:** the `AuthApi` contract under `Auth.HTTP`, one flat `auth` group,
  404-until-configured for optional features, trusted-origin CSRF gate.

---

## D1. The Tag–Service–Layer quartet (highest leverage)

> **Superseded (partially) by the API restructure** (`docs/refactor-plan.md`
> §3, `docs/migration.md` §4): the `Shape`-suffix decision below did not
> survive contact with real usage and was reversed — `*Shape` interfaces
> (`SessionStoreShape`, `EmailOtpServiceShape`, and ~65 others) are deleted
> outright; implementors use `typeof X.Service` in type position instead.
> Separately, `SessionManager` (the example service used throughout this
> section) was renamed to `SessionService` in the same restructure, with no
> compat alias. The rest of D1 — bare service names, `X.layer(config)` as the
> sole constructor — still holds.

**Status quo.** Every module ships four things (e.g. `session/SessionService.ts` (then flat `Session.ts`)):

1. `interface SessionManager` — the service shape;
2. `class SessionManagerTag extends Context.Service<SessionManagerTag, SessionManager>()("@effect-auth/SessionManager")`;
3. `export const SessionManager = SessionManagerTag` — bare ergonomic alias
   (**68** such dual exports, one per tag; only `Hooks` has none);
4. `SessionService.make(config)` (Effect) + `export const SessionManagerLayer =
(config) => Layer.effect(...)` (standalone const).

**Problem.** Two names for every service (`XServiceTag` vs `X`) double the API
reference, confuse autocompletion, and match no Effect v4 codebase. The layer
lives in a free-floating const disconnected from the service it implements, and
its naming drifts (see D2). Meanwhile the two newest surfaces — `Hooks`
(`Hooks.ts:161–163`, class named plainly with `static Default`) and the WorkOS
package — already use the idiomatic shape, so the library disagrees with itself
about its own convention.

**Decision.**

- **Canonical service name is the bare name `X`** (`SessionManager`,
  `EmailPasswordService`, …). Docs, examples, and new code use it exclusively.
- **Canonical layer construction is `X.layer(config)`**, a `static readonly` on
  the service class. The static mirrors the exact signature of the existing
  `XServiceLayer` constructor (required config, optional config, or no config).
- The service shape stays exported as a named interface so users can type
  implementations — named `XShape` (see the implementation finding below).
- `makeX(config)` stays exported as the low-level constructor (it is what the
  static composes) — useful for embedding a service in a custom layer.
- **Applied (additive first, then approved rename):** `static readonly layer`
  landed on all 26 primary service classes first; after maintainer approval the
  classes now carry the bare names themselves, the `XServiceTag` exports and
  alias consts are gone, and the standalone `XServiceLayer` consts are removed.
- **Implementation finding (shape naming):** the plan to keep the shape
  interface under the same bare name does not survive TypeScript declaration
  merging — `class X` + `interface X` merge, so `Context.Service<X, X>`
  resolves Shape to the merged type and every implementation is asked for tag
  internals (`Service`, `key`, `[ServiceTypeId]`); verified empirically with a
  minimal probe. The shape interfaces therefore carry a `Shape` suffix
  (`SessionStoreShape`, `EmailOtpServiceShape`, …), mirroring the
  `WorkOS`/`WorkOSService` split in `@effect-auth/workos`. Migration:
  type-position uses of the old bare names (`const s: Auth.SessionStore` /
  `satisfies Auth.SessionStore`) become `Auth.SessionStoreShape`; value uses
  are unchanged.

**Rationale.** Matches `effect-solutions` services-and-layers exactly ("Layer
naming: camelCase with `Layer` suffix [as statics]: `layer`, `testLayer`,
`postgresLayer`"), matches the two in-repo modules that were written most
recently (Hooks, WorkOS) — i.e. the library was already converging on this — and
is achievable additively today because the alias const exposes class statics.

**Migration & blast radius.** `XServiceTag` → `X`, `XServiceLayer(cfg)` →
`X.layer(cfg)`, shape annotations `X` → `XShape`; all compile-visible and
codemod-friendly (applied across sql/alchemy/client, all tests, all 13
examples, and the site guides in this repo).

**Risk.** Low. Statics are lazily-bound arrows so no TDZ/ordering hazards; the
existing test suite plus a new static-layer test guard behavior.

### Static-layer coverage rule

A service class carries only the layers defined in its own module. Layers that
implement a tag from _another_ module keep their standalone names to avoid
import cycles: `MultiFactorGateLayer` (`MultiFactor.ts:631`, provides
`SecondFactorGate` from EmailPassword), `rateLimiterPersistenceLayer`
(`RateLimitPersistence.ts:114`, provides `RateLimiter` from RateLimit), and
the KV store layers (`KeyValueStores.ts`, provide store tags from many modules).

## D2. Layer constructor naming

**Status quo.** 31 `*Layer` exports: 24 `XServiceLayer(config)` functions; 3
no-config functions (`RateLimiterLayer()` `RateLimit.ts:212`,
`AuthorizationPolicyLayer()` `authz/Authorization.ts` (then flat `Authorization.ts`), `UserServiceLayer()`
`User.ts:153`); 4 bare Layer values (`RateLimiterPersistenceLayer`,
`ScryptHasherLayer`, `PasswordHasherLayer`, `MultiFactorGateLayer` — `secondfactor/MultiFactor.ts`
(then flat `TwoFactor.ts`)); one
`make`-prefixed (`makeMultiAlgorithmVerifierLayer` `password/Password.ts` (then flat `Password.ts`)); one
lowercase two-arg (`authGroupLayer(config?, multiSession?)` `http/HTTPServer.ts` (then flat `HttpServer.ts`));
plus `PasswordHasherLive`/`PBKDF2HasherLive` (`password/Password.ts` (then flat `Password.ts`)) which are
**`Context.make` values, not Layers**, wearing a `Live` suffix used nowhere else.

**Decision.**

- Canonical construction is `X.layer(...)` per D1. Where a module offers several
  implementations, statics are named `layer<Variant>` (`layerOptions`,
  `layerClient` — the WorkOS precedent).
- Standalone cross-module layers (see coverage rule above) keep the
  `<What>Layer` PascalCase-value convention; a **function** returning a layer is
  named `<What>Layer(args)` too (the call site reads identically).
- **Applied (proposal 7, approved 2026-07-04):** the hasher family now lives as
  statics — `PasswordHasher.layer()` (PBKDF2 default) and
  `PasswordHasher.layerScrypt(options)`; `MultiAlgorithmVerifier.layer(hashers)`
  replaces `makeMultiAlgorithmVerifierLayer`. Removed: `PasswordHasherLayer`,
  `ScryptHasherLayer`, `PasswordHasherLive`, `PBKDF2HasherLive`,
  `makePasswordHasher` (use `makePBKDF2Hasher`, since renamed to
  `pbkdf2Hasher`). `Argon2HasherLayer` stays a
  package export in `@effect-auth/argon2` — native dependencies never enter
  core. Still open: the `authGroupLayer` naming (unasked; revisit with any
  future HTTP-surface change).

**Rationale.** One construction verb (`X.layer`) beats four spellings; the
`Live` suffix is an Effect-v2-era habit; a `Context.make` in a layer's clothing
is a footgun (it type-checks in `Effect.provide` but skips lifecycle).

**Migration.** Mechanical renames, compile-time errors; hasher consolidation
needs a short migration note in the changeset.

**Risk.** Low.

## D3. Store contracts

**Status quo.** 38 store interfaces. 30+ return `X | null` for lookups with an
`AuthError` channel; 4 fail typed not-found errors (`SessionStore.get` →
`SessionNotFoundError` `session/SessionService.ts` (then flat `Session.ts`); `UserStore.get`/`UserServiceStore.get` →
`UserNotFoundError`; `ChallengeStore.get`/`CredentialStore.get` →
`Challenge/CredentialNotFoundError` `WebAuthn.ts:191–216`); one —
`OAuthStateStore.get` (`OAuth.ts:147`) — is neither: non-nullable success with
only broad `AuthError`. Method vocabulary drifts: `get` vs `getById` vs
`getByHash`; `listByUserId` vs `getByUserId` (returns array) vs
`listMembersByOrganization`; `deleteByUserId` vs cascade-on-delete.

**Decision.** One store contract style:

1. **Stores are dumb persistence.** Lookup methods return `X | null` when the row
   may legitimately be absent; the _service_ converts `null` into the typed
   domain error. Store error channel is `AuthError` only (infrastructure
   failure), `never` where the store cannot fail meaningfully (`RoleStore`).
   `Option<X>` is rejected: implementors write these against raw drivers and
   `null` keeps implementations dependency-light and obvious.
2. **Vocabulary:** `create`, `get` (by natural/primary key), `getBy<Key>` for
   secondary keys, `list()`/`listBy<Key>` (always array-returning), `update`,
   `upsert`, `delete`, `deleteBy<Key>`. Array-returning lookups are `list*`,
   never `get*`.
3. **Proposed (breaking, 1.0):** migrate the 5 outlier stores to the convention —
   `SessionStore.get`, `UserStore.get`, `UserServiceStore.get`,
   `ChallengeStore.get`, `CredentialStore.get` become nullable (their services
   already own the typed errors); `OAuthStateStore.get` becomes nullable;
   `CredentialStore.getByUserId` → `listByUserId`; `APIKeyStore.getById` → `get`.
   `@effect-auth/sql` and `@effect-auth/alchemy` update in lockstep.

**Rationale.** The nullable convention is the de-facto majority (30+ of 38), is
the easiest contract to implement correctly against any driver, and keeps typed
errors where they carry meaning — the service boundary that decides _why_ a
miss matters (expired vs invalid vs enumeration-safe silence).

**Migration.** Store _implementors_ (including the two first-party packages)
touch the 5 outlier stores; store _consumers_ are unaffected because services
keep their error unions.

**Risk.** Medium — this changes implementor-facing signatures; staged behind a
Changeset with a migration table.

### First-party implementation coverage

`@effect-auth/sql` and `@effect-auth/alchemy` both implement the same 20
stores (the alchemy gap — MagicLink, MagicLinkUser, EmailOTP, EmailOTPUser,
MultiFactor, PendingMultiFactor — was closed 2026-07-04). Neither implements the
advanced-feature stores (Organization, APIKey, SSO, OIDC\*,
DeviceAuthorization, …); that remains a tracked feature gap, not an API
question.

## D4. Error taxonomy

**Status quo.** 37 domain errors, all `Data.TaggedError` — 20 central
(`Errors.ts`) + 17 module-local. `AuthError` is a nominal base **nothing
subclasses**; it composes via unions. 6 HTTP boundary errors use
`Schema.TaggedErrorClass` + `HttpApiSchema.status`
(`http/HTTPApiSchemas.ts`, then flat `HttpApiSchemas.ts:703–739`). Domain→HTTP mapping happens per-endpoint in ~40
`Effect.catchTags` blocks in `http/HTTPServer.ts` (then flat `HttpServer.ts`), with real
inconsistencies: `AuthError` → 409 in `signUp` but → 500 in `signIn`
(`:634`); `RateLimitError` → 400 in signUp (`:611`) but → 403 in signIn
(`:638`); there is **no 429** anywhere.

**Decision.**

1. **Mechanism:** domain errors stay `Data.TaggedError`; HTTP boundary errors
   stay `Schema.TaggedErrorClass` (they must serialize and carry status). A
   module may switch a domain error to `Schema.TaggedErrorClass` only when it
   crosses the wire as-is. (A wholesale migration to Schema errors is _not_
   proposed: it buys serialization the library doesn't need internally and
   would churn 37 classes.)
2. **Taxonomy rules:** `AuthError` means _infrastructure/unexpected_ failure
   only — never a flow outcome. A flow outcome gets a specific tagged error.
   Central `Errors.ts` holds errors shared by ≥2 modules; a module-local error
   is fine when only that module raises it. New modules follow the
   `XError { cause? }` + specific tags pattern. Examples of new flow-outcome
   errors (all in `Errors.ts`): `PasswordPolicyError`, `SignUpDisabledError`,
   `InvalidInputError`, `PasswordAlreadySetError`, `AccountLockedError`,
   `UserBannedError`, `CaptchaError`, `PwnedPasswordError`, plus five
   `OAuth*Error` types.
3. **Stable codes:** every domain error carries a stable, documented, append-only
   `code` field (e.g. `"PASSWORD_TOO_SHORT"`, `"EMAIL_IN_USE"`) sourced from the
   `ErrorCode` const object in `Errors.ts`. Existing errors expose it via a `get
code()` getter (no construction-site changes); new errors take `code` as a
   constructor field (enabling union variants like `PASSWORD_TOO_SHORT |
PASSWORD_TOO_LONG` on `PasswordPolicyError`). HTTP response bodies surface the
   code via an optional `code` field on all non-500 schemas.
4. **HTTP mapping:** target state is a single documented table (tag → status)
   applied uniformly. `AuthError` → **500**; `RateLimitError` → **429** (via
   `TooManyRequests`); `PasswordPolicyError`, `InvalidInputError`, `CaptchaError`,
   `PwnedPasswordError` → **400**; `SignUpDisabledError`, `AccountLockedError`,
   `UserBannedError` → **403**; `EmailInUseError` → **409**;
   `InvalidCredentialsError` → **401** (anti-enumeration: uniform "Invalid email
   or password" message). Session-validation ban failures use `code:
"USER_BANNED"` on the 401 response (clients detect via `code`; a full 403
   upgrade would require updating all ~80 endpoint declarations and is deferred).
5. **Pluggable i18n:** a `Messages` service (`@effect-auth/Messages`) maps
   `(code, locale?, params?) → string`. The `resolveMessage(code, fallback,
params?)` helper in HTTP handlers falls back to the error's own `.message`
   when the service is absent (uses `Effect.serviceOption`). English defaults ship
   in `Messages.Default`; override via `Layer.succeed(Auth.Messages, { resolve: ... })`.
6. **Honest unions:** public service methods keep precise unions; `HookError`
   remains a type alias, now expanded to include `AccountLockedError`,
   `UserBannedError`, `CaptchaError`, `PwnedPasswordError`.

```ts
// Before: AuthError overloaded for all outcomes
signUp: (...) => Effect<Result, AuthError | RateLimitError | EmailInUseError, ...>
//  → AuthError gets 409 in signUp, 500 in signIn — inconsistent!

// After: specific tags, stable codes
signUp: (...) => Effect<
  Result,
  | AuthError              // infrastructure only → 500
  | EmailInUseError        // code: "EMAIL_IN_USE"  → 409
  | RateLimitError         // code: "RATE_LIMIT_EXCEEDED" → 429
  | PasswordPolicyError    // code: "PASSWORD_TOO_SHORT" | "PASSWORD_TOO_LONG" → 400
  | SignUpDisabledError     // code: "SIGN_UP_DISABLED" → 403
  | InvalidInputError       // code: "INVALID_INPUT" → 400
  | AccountLockedError      // code: "ACCOUNT_LOCKED" → 403 (via plugin)
  | UserBannedError         // code: "USER_BANNED" → 403 (via plugin)
  | CaptchaError            // code: "CAPTCHA_FAILED" → 400 (via plugin)
  | PwnedPasswordError,     // code: "PWNED_PASSWORD" → 400 (via plugin)
  ...
>
```

**Applied** (approved): the 429 `TooManyRequests` schema on all 17 rate-limited
endpoints, uniform `AuthError` → 500, the typed `EmailInUseError` (now in
shared `Errors.ts`) carrying signUp's duplicate-email 409, and the full
flow-outcome error taxonomy above.

**Rationale.** `Data.TaggedError` vs `Schema.TaggedErrorClass` split follows
what each layer needs; the mapping table removes the per-handler drift that
makes client error handling guesswork; 429 is the semantically correct status
and clients (`retryAfter` field already exists on `RateLimitError`) can act on it.

**Risk.** Mapping changes can break API consumers matching on status codes —
that is exactly why they are proposals.

## D5. Config objects

**Status quo.** All 34 `*Config` types are plain interfaces (none `Schema`, none
effect `Config`), defaults applied per-field with `??` inside factories; two
factory styles (`config: XConfig = {}` vs `config?: XConfig`), sometimes mixed
between a module's factory and its layer (`Username.ts:123` vs `:241`);
`email/EmailPassword.ts:191–195` (then flat `EmailPassword.ts`) resolves defaults upfront; `OAuthClientConfig` uses
spread-merge; `SessionConfig` and `RateLimitConfig` have required fields (the
latter with `RateLimitPresets`).

**Decision.**

- Config stays **plain interfaces named `XConfig`**. This is code-level wiring,
  not environment config — effect `Config` remains appropriate only where env
  credentials are read (the WorkOS package does this; core has no env inputs).
  Schema validation of config is rejected: every field is already
  compile-checked, and runtime validation would add failure paths to layer
  construction for no attack-surface gain.
- **Signature convention:** when every field is optional, factories and layers
  take `config: XConfig = {}` (never `config?:` — the `= {}` form removes
  `config?.` noise inside). When any field is required, config is a required
  parameter. _(Applied now — signature-level normalization, type-identical to
  callers.)_
- **Defaults convention:** resolve all defaults once at the top of the factory
  (the `email/EmailPassword.ts:191` style, then flat `EmailPassword.ts`) so the rest of the code reads resolved
  values. Applied opportunistically; enforced for new code.
- Security-relevant defaults (cookie `Secure: true`, `HttpOnly`, `SameSite`,
  timing-safe comparisons, entropy sizes) are **not** configurable knobs beyond
  what already exists; no config normalization may loosen one.

**Risk.** None (type-identical signatures).

## D6. Request/Resolver vs Service/Layer

**Status quo.** `Requests.ts` (20 request types) and `Resolvers.ts` (18
resolvers, 3 of them missing the `make` prefix; `CheckPermissionRequest` has no
resolver at all) are exported from the barrel and _promoted as the core
architecture_ by README (`:7,64,159–175`), ARCHITECTURE.md, and the generated
docs. **Nothing uses them**: not one library module, not one of 13 examples, not
the HTTP server — only `Resolvers.test.ts` self-tests. The real pattern
everywhere is `Context.Service` + `Layer` + `Hooks`.

**Decision.** **`Context.Service` + `Layer` is the public pattern.**
`Requests.ts`/`Resolvers.ts` are vestigial.

- **Applied:** deprecation first; after approval `Requests.ts`/`Resolvers.ts`
  were deleted outright. If a batching/caching story is ever wanted, it returns
  as a documented recipe over the service API, not a parallel surface.

**Rationale.** A second, incomplete, untested-in-anger way to do everything the
services do is pure API surface cost; Effect v4 guidance builds libraries on
services/layers, with `Request`/`RequestResolver` reserved for
batching/caching data access — a need this library's own code never exhibited.

**Risk.** Low; deprecation is reversible, deletion is compile-visible.

## D7. HTTP contract conventions

**Status quo.** One flat `auth` group with ~84 endpoints (`http/HTTPApi.ts` (then flat `HttpApi.ts:21,576`)).
Paths are consistently kebab-case. operationIds drift across four schemes:
`signIn<Method>` family (6 endpoints) vs `ssoSignIn` (`:449`, sits at
`/sign-in/sso`); `siweNonce` (`:462`) vs sibling `signInSiwe` (`:467`);
verb-first (`listSessions`, `getSession`) vs noun-first (`orgList`,
`apiKeyList`) vs verb-in-middle (`adminListUsers`, `orgListInvitations`);
action-first `requestPasswordReset`/`resetPassword` vs feature-first
`changeEmailRequest`/`changeEmailConfirm`. `jwt*`/`oidc*` operationId prefixes
never appear in their paths (`/token`, `/oauth2/*`); two JWKS endpoints
(`/jwks`, `/.well-known/jwks.json` — the latter pair is standards-driven and
correct).

**Decision.**

- **operationId scheme:** `<feature><Action>` noun-first for feature endpoints
  (`orgList`, `apiKeyCreate`, `multiFactorEnable` are canonical), with the single
  exception of the cross-feature `signIn<Method>` family, which is verb-first
  because "sign in" _is_ the feature. Top-level session/user endpoints keep
  their short verb forms (`signUp`, `signIn`, `signOut`, `getSession`).
- **Path scheme:** paths stay as-is (kebab-case, `/sign-in/<method>`,
  `/oauth2/*` and `/.well-known/*` where standards dictate). Paths are wire
  compatibility; operationIds are SDK naming — when the two conflict, paths win
  on the wire and operationIds follow the scheme above.
- **Proposed (breaking, 1.0):** rename `ssoSignIn` → `signInSso`,
  `requestPasswordReset` → `passwordResetRequest`, `resetPassword` →
  `passwordResetConfirm`, `adminListUsers` → `adminUsersList` _(or keep — see
  ranked list)_, `orgListInvitations` → `orgInvitationsList`. These rename
  methods on the generated Effect client (`client.auth.<operationId>`) and
  OpenAPI operationIds. `siweNonce`/`signInSiwe` resolve with the SIWE scope
  decision (D9).
- **Kept as settled conventions:** the single flat `auth` group (splitting into
  per-feature groups would break every `client.auth.*` call for cosmetic gain —
  revisit only if a 2.0 happens); `404-until-configured` via
  `Effect.serviceOption` (`http/HTTPServer.ts`, then flat `HttpServer.ts:251–500`) — documented as the official
  behavior for optional features; the trusted-origin CSRF gate
  (`http/HTTPServer.ts`, then flat `HttpServer.ts:2387–2437`) — no-Origin requests pass (server-to-server),
  browser requests must match request origin or `trustedOrigins`, enforced
  before any handler.

**Risk.** operationId renames are the most consumer-visible proposal here;
they're batched for one 0.x minor with a rename table.

## D8. Client API & framework parity

**Status quo.** Two clients: the generated Effect client
(`http/HTTPClient.ts`, then flat `HttpClient.ts:26`, full parity by construction) and the hand-written
zero-dependency browser client (`packages/client/src/Client.ts:136`) covering
23/84 endpoints (core flows + magicLink/emailOTP/multiFactor namespaces). No
dead methods; the missing 61 are the optional/advanced surface. Framework
bindings: React has `useSession` + `useListSessions` (`react.ts:24,37`); Svelte
has only `sessionStore` (`svelte.ts:27`); Vue has only `useSession`
(`vue.ts:23`).

**Decision.**

- The browser client's scope rule is settled as: **cookie-authenticated,
  browser-initiated end-user flows**. Org/admin/OIDC-provider/device/JWKS
  surfaces are server or machine flows and stay out; the Effect client covers
  them. Within that rule the current gaps that _do_ qualify (account
  management: change-email/delete-user; multi-session; username/anonymous/
  phone sign-ins) are tracked as additive roadmap items, not blockers.
- **Framework parity rule:** every binding exposes the same capability set over
  the observable `client.session` store; naming follows each framework's idiom
  (`useSession` React/Vue, `sessionStore` Svelte — settled as intentional).
- **Applied now (additive):** `listSessions` parity for Svelte
  (`listSessionsStore`) and Vue (`useListSessions`), closing the one concrete
  capability gap.

**Risk.** None (additive).

## D9. Barrel & module boundaries

> **Superseded** by `docs/refactor-plan.md` §6: `effect-auth` now also
> publishes per-cluster subpath exports (`effect-auth/email`, `/http`,
> `/oauth`, `/session`, `/password`, `/plugins`, `/authz`) alongside the root
> barrel, with matching `Auth.Email` / `Auth.HTTP` / `Auth.OAuth` / ...
> namespace re-exports from the root. The status quo/decision below reflects
> the pre-refactor state.

**Status quo.** `effect-auth` exports **only the root barrel** (package.json
`exports: {"."}`), with HTTP under `Auth.Http`. The barrel flattens in
`Types`, `Errors`, all feature modules, all plugins, `Requests`/`Resolvers`,
and re-exports `Effect`, `Context`, `Layer`, `RequestResolver` from `effect`
(`index.ts:137–146`). SIWE — contrary to earlier planning notes — is still fully
present (core `Siwe.ts`, `@effect-auth/siwe`, HTTP endpoints in `http/HTTPApi.ts`, then flat `HttpApi.ts:462–472`).

**Decision.**

- **Single root barrel stays** (plus `Auth.Http` namespace). Optional heavy
  features are already tree-shakeable via unused-layer elision and
  404-until-configured; subpath exports are reconsidered only if bundle-size
  evidence appears. `@effect-auth/client` keeps its subpaths (framework entry
  points genuinely need them).
- **Applied now:** `@deprecated` on the `Effect`/`Context`/`Layer`/
  `RequestResolver` re-exports (users should import from `effect`; the aliases
  invite version skew) and on `Requests`/`Resolvers` (D6).
- **Proposed (maintainer call):**
  1. **SIWE**: remove from core (module + endpoints) leaving
     `@effect-auth/siwe` as the home, or keep as-is. The verifier is already
     externalized; core carries the store/service/HTTP surface.
  2. **OIDC provider** (5 stores + ~1,000-line module + 10 endpoints): keep in
     core (it reuses JWT/Session and the 404-pattern makes it invisible when
     unconfigured) — recommended — or extract to `@effect-auth/oidc-provider`.
  3. Remove the `effect` re-exports at 1.0.

**Rationale.** The barrel _is_ the product's ergonomic thesis (`import * as
Auth`); boundaries should be enforced by layers-you-don't-provide, not by
import paths. The re-exported `effect` namespace is the one part that actively
harms (skew + docs pollution).

## D10. Cross-package consistency

**Status quo & decision per package** (drift evidence:
`sql/Stores.ts:1005–1085`, `alchemy/Stores.ts:860–892`, `argon2/Argon2.ts:52,101`,
`siwe/SiweVerifier.ts:71–80`, `workos/WorkOS.ts:246–271`):

| Package   | Today                                                                                                         | Settled                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `sql`     | 20 `XStoreLayer` values + lowercase aggregate `layer`                                                         | Keep; `layer` as the aggregate name matches Effect convention for a package's primary layer                              |
| `alchemy` | `XStoreLayer(db)` functions + `layer(db)`                                                                     | Keep shape (D1 binding is a required argument); document that `XStoreLayer` may be value _or_ function per package needs |
| `argon2`  | `makeArgon2Hasher(opts?)` plain + `Argon2HasherLayer(opts?)` function                                         | Keep; matches hasher family style                                                                                        |
| `siwe`    | curried `Layer.succeed(Tag)(value)`                                                                           | Keep — the curried form is also used throughout core tests; both `Layer.succeed` call forms are acceptable               |
| `workos`  | `Context.Service` class + `static layer/layerOptions/layerClient`, own `WorkOSError`, effect `Config` for env | **This is the reference implementation** of the settled idiom                                                            |
| `client`  | `createAuthClient` factory, plain `AuthClientError extends Error`                                             | Keep — deliberately Effect-free for the browser bundle; the plain Error is intentional and documented                    |

Shared rules applied to all: config = plain `XConfig`/`XOptions` interfaces;
errors reuse core tags unless the package wraps a foreign SDK (workos);
`effect`-only runtime deps in core, native/SDK deps isolated in their packages.

**Dependency & platform rule (maintainer directive, 2026-07-04):** the core
package aims to be platform-neutral and takes dependencies only where strictly
necessary. Concretely: `effect` is the only runtime dependency; the only
platform API used is `node:crypto` (the incidental `node:util` import was
removed); anything platform-specific or natively-built lives in a companion
package. A future migration of `node:crypto` usage to WebCrypto would complete
platform neutrality and is recorded here as a candidate 1.x goal.

## D11. Docs as source of truth

**Status quo.** `ARCHITECTURE.md` predates ~40 modules (lowercase `src/types.ts`,
Request/Resolver framing, WebAuthn as "future"); `CONTRIBUTING.md` shows a
single-package flat layout and references a nonexistent `AGENT_GUIDELINES.md`;
`HOOKS_DESIGN.md` says "Status: Proposed … effect v3.21.2" about a shipped
system; README omits `@effect-auth/alchemy`/`@effect-auth/workos` from its
package table and headlines the Request/Resolver pattern.

**Decision (applied now).** `ARCHITECTURE.md` rewritten to describe the settled
design (services/layers/hooks/stores/HTTP, security invariants, this
document as the decision record). README package table completed and
Request/Resolver framing replaced with the service idiom. `CONTRIBUTING.md`
structure/paths corrected. `HOOKS_DESIGN.md` gets a status header marking it
historical (implemented; kept as design rationale).

**Generated-reference churn, diagnosed:** `@effect/docgen` emits unformatted
signatures while the checked-in reference had been reformatted by the
pre-commit `vp check --fix` hook, so every regeneration appeared to churn all
~45 pages. Fix applied: `docs:api` now runs
`vp check --fix site/src/content/docs/reference/api` after syncing, making
regeneration idempotent (verified: a full regen produces zero spurious diffs).

## D12. Surrogate-keyed identity (identifiers, not `user.email`)

**Status quo (pre-2026-08).** `User` carried `email`/`emailVerified` as a
natural key: `auth_users.email` was globally unique, every flow resolved
accounts via `getUserByEmail`, usernames lived in a parallel `UsernameStore`,
and phone numbers hid in `attributes`. One email per user, renames were
UPDATEs on the primary record, and each new handle type grew its own store.

**Decision (applied, breaking).** `User` is purely surrogate-keyed:
`{ id, name?, image?, createdAt, updatedAt, attributes }`. Login handles are
`Identifier` records — `(type: "email" | "username" | "phone", value)` with
global uniqueness on the pair, a `verified`/`verifiedAt` promotion state, and
`createdAt` ordering — behind the single `IdentifierStore` contract
(`Identifier.ts`; KV, sql and alchemy implementations). Consequences:

- **Resolution**: every "who owns this handle" goes through
  `IdentifierStore.getByValue` (helper: `resolveUserByIdentifier`). The
  removed members: `User.email`/`emailVerified`, `UserServiceStore.getByEmail`,
  `UserService.getUserByEmail`/`markEmailVerified`, every feature store's
  `getUserByEmail`, and `UsernameStore` outright.
- **Claiming**: creation-time uniqueness rides the store's unique index;
  `claimIdentifier` adds the check-first + race re-check pattern and a typed
  `IdentifierTakenError`. Flows map it to their own conflict error
  (`EmailInUseError`, `UsernameError`, ...).
- **Verification is proof-of-ownership**: completing an email verification,
  magic link, email OTP, phone OTP, or a trusted OAuth/SSO assertion promotes
  the identifier via `setVerified`. `requireEmailVerification`-style gates
  read `identifier.verified`, never a user field.
- **Email-of-record** for delivery/display is derived: `primaryEmail`
  (earliest verified) falling back to `anyEmail` (earliest of any state).
  The HTTP `UserView` exposes derived optional `email`/`emailVerified`
  (omitted on cookie-cache-served responses) plus `GET /identifiers` /
  `DELETE /identifiers/:identifierId`; the wire shape stays compatible for
  clients that read `user.email` from store-served responses.
- **Storage**: `auth_users` drops `email`/`email_verified` and
  `auth_users_email_idx`; `auth_identifiers` (unique `(type, value)`) is the
  handle table. Upgrade path: `docs/migration.md` § "Surrogate-keyed identity".

**Rationale.** Multiple emails per account, username renames, phone-as-handle
and future handle types (door open: passkey handles, wallet addresses) all
become row operations on one table instead of schema surgery; verification
state finally attaches to the handle it belongs to.

## D13. Effect-native authorization (the `authz/` kernel)

**Status quo (pre-M3).** `authz/` held an RBAC seed: `PermissionRef` wildcard
matching, `RoleStore`, and an `AuthorizationPolicy` service whose checks were
method calls — no reusable policy value, no resource/attribute model, no
policies-as-data.

**Decision (applied; owner decisions 2026-08-30, recorded in
`better-auth-parity.md` §2.5).** Authorization is a first-class pillar built
around the `Policy` **value** — Effect-native-first; Cedar contributes
semantics adopted on merit and, at most, an interop serialization (door-open
`packages/cedar`). The load-bearing choices:

- **Two policy kinds, difference visible in types.** `DeclarativePolicy` is
  pure data (permit/forbid + PARC scopes `any/eq/in/is` + a serializable
  condition AST) and earns data powers: Schema-validated, storable,
  tenant-editable, model-checkable. `Policy.custom` (arbitrary Effect
  predicate) is first-class everywhere policies are accepted, but opaque —
  its `E`/`R` surface in `Policy<E, R>` and it cannot be stored.
- **Pure core, Effect shell.** Decisions are a pure, total function over a
  pre-fetched `EntitySlice` (`decidePure`); services (`EntityResolver`,
  `PolicyStore`, `CurrentPrincipal`) live in the `Authorizer` shell. Every
  decision is deterministic and replayable from the logged `(request, slice)`.
- **Semantics:** default deny; forbid overrides permit; order-independent;
  the `Decision` carries determining policies + per-policy outcomes.
  **Fail-closed both ways** (deliberate Cedar deviation): an erroring permit
  cannot grant, an erroring forbid denies; errors land in the trace.
- **Entities everywhere:** principals, resources, actions and roles are typed
  entities in one hierarchy, so RBAC (`principal in Role::"admin"`), ReBAC
  and action groups are the same data check. The declared `Model` doubles as
  Cedar-style policy validation at `Authorizer` layer construction.
- **Templates in v1:** `?principal`/`?resource` slots + link records;
  instantiation is fail-closed (missing _or superfluous_ slot values error —
  a link may never broaden its template); a broken link fails
  `effectivePolicies` loudly rather than letting a forbid vanish.
- **Schema-embedded enforcement:** `protectedField` runs the same policies at
  the data boundary via v4 Schema effectful getters — decode denial fails
  (write guard), encode denial redacts (viewer projection) — with
  `CurrentPrincipal` flowing through the struct's Requirements channel, and
  `AuthMiddleware` providing the principal per request.

The M0-era `AuthorizationPolicy`/`RoleStore` API remains during the
transition; M4 migrates Organization/Admin/APIKey onto `Policy` and decides
its retirement.

---

## Maintainer decisions (2026-07-03)

Asked via review: **1** yes (all three parts), **2** yes, **3** yes, **4+5**
yes (error-status fixes and the three operationId renames; `orgListInvitations`
and `adminListUsers` keep their names), **6** — _remove SIWE entirely_, going
beyond the proposal (core module + endpoints + `@effect-auth/siwe` package all
deleted), **8** yes. **7** (hasher consolidation) and **9** (OIDC extraction)
were not put to a vote at the time; 7 was subsequently approved and applied
(2026-07-04), 9 stays "keep in core" as recommended.
All approved items are applied and changeset-backed.

## Ranked breaking-change proposals (as asked)

| #   | Proposal                                                                                                                                                                                                                   | Blast radius                                                          | Recommendation                                                                 |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 1   | **Drop `XServiceTag` names + standalone `XServiceLayer` consts at 1.0**; class takes the bare name, `X.layer()` is the only constructor (D1/D2)                                                                            | Every consumer, mechanical codemod                                    | **Yes** — this is the 1.0 identity                                             |
| 2   | **Delete `Requests.ts`/`Resolvers.ts`** (D6)                                                                                                                                                                               | Consumers of a pattern with zero observed usage                       | **Yes**                                                                        |
| 3   | **Store contract outliers → nullable convention** (D3): 6 stores, incl. sql/alchemy updates                                                                                                                                | Store implementors only                                               | **Yes**                                                                        |
| 4   | **HTTP error-mapping fixes + 429** (D4): signUp 409 via typed `EmailInUseError`, uniform `AuthError`→500, `RateLimitError`→429                                                                                             | API consumers matching status codes; OpenAPI; generated client unions | **Yes**, one minor with migration notes                                        |
| 5   | **operationId renames** (D7): `ssoSignIn`→`signInSso`, `requestPasswordReset`→`passwordResetRequest`, `resetPassword`→`passwordResetConfirm`, `orgListInvitations`→`orgInvitationsList`, `adminListUsers`→`adminUsersList` | Generated-client method names; OpenAPI                                | **Yes** except the last two (defensible as-is) — maintainer taste              |
| 6   | **SIWE out of core** (D9): delete `Siwe.ts` + `/siwe/*`,`/sign-in/siwe` endpoints; `@effect-auth/siwe` becomes self-contained (would need its own service/store/HTTP recipe)                                               | SIWE users (niche); shrinks core by 4 tags + 2 endpoints              | **Yes** if the scope-trimming signal is real; the tree still contains it fully |
| 7   | **Hasher consolidation** (D2): statics on `PasswordHasher`, drop `*Live` exports                                                                                                                                           | Anyone providing hashers explicitly                                   | **Yes**                                                                        |
| 8   | **Remove `effect` re-exports from the barrel** (D9)                                                                                                                                                                        | Consumers using `Auth.Effect`                                         | **Yes** at 1.0                                                                 |
| 9   | **OIDC provider extraction** to its own package (D9)                                                                                                                                                                       | OIDC users; new package to maintain                                   | **No** — keep in core; 404-pattern already scopes it                           |

## Applied normalizations (this pass, all non-breaking)

1. `static readonly layer` on all 26 primary service classes (+ tests) — D1.
2. Optional-config signature normalization to `config: XConfig = {}` — D5.
3. `@deprecated` markers: `Requests.ts`/`Resolvers.ts` exports, barrel `effect`
   re-exports — D6/D9.
4. Svelte/Vue `listSessions` parity in `@effect-auth/client` — D8.
5. Docs reconciliation: `ARCHITECTURE.md` rewrite, README package
   table + framing + quick-start (the old §2 example never provided `Hooks`
   and would not have type-checked), `CONTRIBUTING.md` structure/paths,
   `HOOKS_DESIGN.md` status header — D11.
6. Error-model overhaul (D4): specific flow-outcome tags, stable `code` field on all domain errors, `ErrorCode` const, `Messages` service + English catalog, HTTP status fixes — D4.

Changesets accompany 1 (minor: effect-auth), 3 (patch: effect-auth), 4 (minor: @effect-auth/client), 6 (minor: effect-auth).
