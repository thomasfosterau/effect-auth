# effect-auth — Settled Design & Public API (pre-1.0 decision record)

Status: **Adopted** for everything marked _Applied_; everything marked _Proposed
(breaking)_ awaits maintainer sign-off and ships behind a Changeset.
Date: 2026-07-03. Supersedes the architectural framing in `ARCHITECTURE.md`
(rewritten alongside this document) and the status header of `HOOKS_DESIGN.md`.

This document records, per design dimension: **status quo → problem → decision →
rationale → migration & blast radius → risk**. Evidence lines reference the tree at
the time of writing. The yardstick throughout is the Effect v4 service idiom
(`effect-solutions show services-and-layers error-handling`): `Context.Service`
classes named after the service, layers as camelCase `static` members (`layer`,
`layerConfig`, `testLayer`), `R = never` on service methods, tagged errors.

---

## The settled surface in one screen

```ts
import * as Auth from "effect-auth";

// Canonical: the service name IS the export; layers are statics on it.
const app = Effect.gen(function* () {
  const sessions = yield* Auth.SessionManager;
  const session = yield* sessions.createSession(userId);
}).pipe(
  Effect.provide(Auth.SessionManager.layer({ sessionExpiresIn })),
  Effect.provide(Auth.EmailPasswordService.layer()),
  Effect.provide(Auth.Hooks.Default),
);
```

- **Service access:** `yield* Auth.X` where `X` is the service name
  (`SessionManager`, `EmailPasswordService`, `WebAuthnService`, …).
- **Layer construction:** `Auth.X.layer(config)` — a `static` on the service class,
  mirroring `Hooks.Default` (core) and `WorkOS.layer/layerOptions/layerClient`
  (`packages/workos/src/WorkOS.ts:246`), which already follow the Effect v4 idiom.
- **Stores:** you implement `interface XStore` and provide it with
  `Layer.succeed(Auth.XStore, impl)` or a first-party layer from
  `@effect-auth/sql`, `@effect-auth/alchemy`, or the KV layers in core.
- **Errors:** tagged errors, `AuthError` for infrastructure failure, specific tags
  for flow outcomes; lookups that can legitimately miss return `X | null` from
  stores and surface typed errors from services.
- **HTTP:** the `AuthApi` contract under `Auth.Http`, one flat `auth` group,
  404-until-configured for optional features, trusted-origin CSRF gate.

---

## D1. The Tag–Service–Layer quartet (highest leverage)

**Status quo.** Every module ships four things (e.g. `Session.ts:12–54,147–152,167,311`):

1. `interface SessionManager` — the service shape;
2. `class SessionManagerTag extends Context.Service<SessionManagerTag, SessionManager>()("@effect-auth/SessionManager")`;
3. `export const SessionManager = SessionManagerTag` — bare ergonomic alias
   (**68** such dual exports, one per tag; only `Hooks` has none);
4. `makeSessionManager(config)` (Effect) + `export const SessionManagerLayer =
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
- `interface X` (the service shape) stays exported so users can type
  implementations; the interface and the alias const merge under one name today
  and continue to after the 1.0 rename.
- `makeX(config)` stays exported as the low-level constructor (it is what the
  static composes) — useful for embedding a service in a custom layer.
- **Applied now (additive):** `static readonly layer` added to all 26 primary
  service classes, delegating to the existing layer constructors. Nothing removed.
- **Proposed (breaking, 1.0):** rename the classes so the bare name is the class
  itself (`class SessionManager extends Context.Service<SessionManager, …>`),
  drop the `XServiceTag` exports, and remove the standalone `XServiceLayer`
  consts. Until approved, both spellings work and `XServiceLayer` is documented
  as legacy.

**Rationale.** Matches `effect-solutions` services-and-layers exactly ("Layer
naming: camelCase with `Layer` suffix [as statics]: `layer`, `testLayer`,
`postgresLayer`"), matches the two in-repo modules that were written most
recently (Hooks, WorkOS) — i.e. the library was already converging on this — and
is achievable additively today because the alias const exposes class statics.

**Migration & blast radius.** Additive step: zero user impact. 1.0 step: every
consumer referencing `XServiceTag` or `XServiceLayer` renames mechanically
(`XServiceTag` → `X`, `XServiceLayer(cfg)` → `X.layer(cfg)`); a codemod-friendly,
error-at-compile-time change.

**Risk.** Low. Statics are lazily-bound arrows so no TDZ/ordering hazards; the
existing test suite plus a new static-layer test guard behavior.

### Static-layer coverage rule

A service class carries only the layers defined in its own module. Layers that
implement a tag from _another_ module keep their standalone names to avoid
import cycles: `TwoFactorGateLayer` (`TwoFactor.ts:631`, provides
`SecondFactorGateTag` from EmailPassword), `RateLimiterPersistenceLayer`
(`RateLimitPersistence.ts:114`, provides `RateLimiterTag` from RateLimit), and
the KV store layers (`KeyValueStores.ts`, provide store tags from many modules).

## D2. Layer constructor naming

**Status quo.** 31 `*Layer` exports: 24 `XServiceLayer(config)` functions; 3
no-config functions (`RateLimiterLayer()` `RateLimit.ts:212`,
`AuthorizationPolicyLayer()` `Authorization.ts:90`, `UserServiceLayer()`
`User.ts:153`); 4 bare Layer values (`RateLimiterPersistenceLayer`,
`ScryptHasherLayer`, `PasswordHasherLayer`, `TwoFactorGateLayer`); one
`make`-prefixed (`makeMultiAlgorithmVerifierLayer` `Password.ts:136`); one
lowercase two-arg (`authGroupLayer(config?, multiSession?)` `HttpServer.ts:596`);
plus `PasswordHasherLive`/`PBKDF2HasherLive` (`Password.ts:408,418`) which are
**`Context.make` values, not Layers**, wearing a `Live` suffix used nowhere else.

**Decision.**

- Canonical construction is `X.layer(...)` per D1. Where a module offers several
  implementations, statics are named `layer<Variant>` (`layerOptions`,
  `layerClient` — the WorkOS precedent).
- Standalone cross-module layers (see coverage rule above) keep the
  `<What>Layer` PascalCase-value convention; a **function** returning a layer is
  named `<What>Layer(args)` too (the call site reads identically).
- **Proposed (breaking, 1.0):** rename `authGroupLayer` → `AuthGroupLayer` (or
  fold into an `AuthHttp.layer` static), `makeMultiAlgorithmVerifierLayer` →
  `MultiAlgorithmVerifierLayer`, and remove `PasswordHasherLive`/
  `PBKDF2HasherLive` (a `Context` value duplicating `PasswordHasherLayer`).
  The hasher family (`PasswordHasherLayer`, `ScryptHasherLayer`,
  `Argon2HasherLayer`) consolidates as statics on `PasswordHasher`
  (`PasswordHasher.layerPbkdf2()`, `.layerScrypt()`; argon2 stays a package
  export for dependency reasons).

**Rationale.** One construction verb (`X.layer`) beats four spellings; the
`Live` suffix is an Effect-v2-era habit; a `Context.make` in a layer's clothing
is a footgun (it type-checks in `Effect.provide` but skips lifecycle).

**Migration.** Mechanical renames, compile-time errors; hasher consolidation
needs a short migration note in the changeset.

**Risk.** Low.

## D3. Store contracts

**Status quo.** 38 store interfaces. 30+ return `X | null` for lookups with an
`AuthError` channel; 4 fail typed not-found errors (`SessionStore.get` →
`SessionNotFoundError` `Session.ts:21`; `UserStore.get`/`UserServiceStore.get` →
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
   `CredentialStore.getByUserId` → `listByUserId`; `ApiKeyStore.getById` → `get`.
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

### First-party implementation coverage (documented gap, no action now)

`@effect-auth/sql` implements 20 stores; `@effect-auth/alchemy` 14 (missing
MagicLink, MagicLinkUser, EmailOtp, EmailOtpUser, TwoFactor, PendingTwoFactor).
Neither implements the advanced-feature stores (Organization, ApiKey, Sso,
Oidc\*, DeviceAuthorization, …). Tracked as a feature gap, not an API question.

## D4. Error taxonomy

**Status quo.** 37 domain errors, all `Data.TaggedError` — 20 central
(`Errors.ts`) + 17 module-local. `AuthError` is a nominal base **nothing
subclasses**; it composes via unions. 6 HTTP boundary errors use
`Schema.TaggedErrorClass` + `HttpApiSchema.status`
(`HttpApiSchemas.ts:703–739`). Domain→HTTP mapping happens per-endpoint in ~40
`Effect.catchTags` blocks in `HttpServer.ts`, with real inconsistencies:
`AuthError` → 409 in `signUp` (`HttpServer.ts:606`) but → 500 in `signIn`
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
   is fine when only that module raises it (the current 17 all qualify). New
   modules follow the `XError { cause? }` + specific tags pattern.
3. **HTTP mapping:** target state is a single documented table (tag → status)
   applied uniformly. `RateLimitError` maps to **429** via a new
   `TooManyRequests` schema; `AuthError` maps to **500** everywhere (signUp's
   duplicate-email case gets a typed `EmailInUseError` instead of overloading
   `AuthError` → 409).
4. **Honest unions:** public service methods keep precise unions (already
   largely true); `HookError` remains a type alias, not a class.

**Applied now:** rules documented here + ARCHITECTURE.md. **Proposed
(breaking):** the 429 addition and the signUp/signIn mapping fixes change
observable HTTP behavior and the OpenAPI document — staged behind Changesets.

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
`EmailPassword.ts:191–195` resolves defaults upfront; `OAuthClientConfig` uses
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
  (the `EmailPassword.ts:191` style) so the rest of the code reads resolved
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

- **Applied now:** `@deprecated` JSDoc on both modules' exports; all docs
  rewritten to stop advertising the pattern (README, ARCHITECTURE.md).
- **Proposed (breaking, 1.0):** delete both modules. If a batching/caching story
  is ever wanted, it returns as a documented recipe over the service API, not a
  parallel surface.

**Rationale.** A second, incomplete, untested-in-anger way to do everything the
services do is pure API surface cost; Effect v4 guidance builds libraries on
services/layers, with `Request`/`RequestResolver` reserved for
batching/caching data access — a need this library's own code never exhibited.

**Risk.** Low; deprecation is reversible, deletion is compile-visible.

## D7. HTTP contract conventions

**Status quo.** One flat `auth` group with ~84 endpoints (`HttpApi.ts:21,576`).
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
  (`orgList`, `apiKeyCreate`, `twoFactorEnable` are canonical), with the single
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
  `Effect.serviceOption` (`HttpServer.ts:251–500`) — documented as the official
  behavior for optional features; the trusted-origin CSRF gate
  (`HttpServer.ts:2387–2437`) — no-Origin requests pass (server-to-server),
  browser requests must match request origin or `trustedOrigins`, enforced
  before any handler.

**Risk.** operationId renames are the most consumer-visible proposal here;
they're batched for one 0.x minor with a rename table.

## D8. Client API & framework parity

**Status quo.** Two clients: the generated Effect client
(`HttpClient.ts:26`, full parity by construction) and the hand-written
zero-dependency browser client (`packages/client/src/Client.ts:136`) covering
23/84 endpoints (core flows + magicLink/emailOtp/twoFactor namespaces). No
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

**Status quo.** `effect-auth` exports **only the root barrel** (package.json
`exports: {"."}`), with HTTP under `Auth.Http`. The barrel flattens in
`Types`, `Errors`, all feature modules, all plugins, `Requests`/`Resolvers`,
and re-exports `Effect`, `Context`, `Layer`, `RequestResolver` from `effect`
(`index.ts:137–146`). SIWE — contrary to earlier planning notes — is still fully
present (core `Siwe.ts`, `@effect-auth/siwe`, HTTP endpoints `HttpApi.ts:462–472`).

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
     core (it reuses Jwt/Session and the 404-pattern makes it invisible when
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
| `siwe`    | curried `Layer.succeed(Tag)(value)`                                                                           | **Applied now:** normalize to two-arg `Layer.succeed(Tag, value)` (style-only)                                           |
| `workos`  | `Context.Service` class + `static layer/layerOptions/layerClient`, own `WorkOSError`, effect `Config` for env | **This is the reference implementation** of the settled idiom                                                            |
| `client`  | `createAuthClient` factory, plain `AuthClientError extends Error`                                             | Keep — deliberately Effect-free for the browser bundle; the plain Error is intentional and documented                    |

Shared rules applied to all: config = plain `XConfig`/`XOptions` interfaces;
errors reuse core tags unless the package wraps a foreign SDK (workos);
`effect`-only runtime deps in core, native/SDK deps isolated in their packages.

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
historical (implemented; kept as design rationale). `docs:api` regenerated;
any formatter churn investigated separately.

---

## Ranked breaking-change proposals (each needs a yes/no)

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
5. siwe curried→two-arg `Layer.succeed` — D10.
6. Docs reconciliation: `ARCHITECTURE.md` rewrite, README package
   table + framing, `CONTRIBUTING.md` paths, `HOOKS_DESIGN.md` status — D11.

Changesets accompany 1 (minor: effect-auth), 3 (patch: effect-auth), 4 (minor:
@effect-auth/client).
