# Hooks / Plugin Architecture — Design Document

**Status:** Proposed — awaiting review (Phase 1)
**Target package:** `packages/effect-auth`
**Effect version:** v3.21.2 (resolved from `effect@^3.19.15`)

---

## 0. TL;DR

We add a single new service, `Hooks`, defined with `Effect.Service` (the v3
class-based API). It exposes a typed set of **hook points** that fire at every
significant moment in the auth lifecycle. Two flavours:

- **Transform hooks** — receive a value, return a (possibly modified) value of
  the same type. They sit in the critical path and may **short-circuit** by
  failing in the Effect error channel.
- **Tap hooks** — observe a value, return `void`. Side-effect only.

Plugins are authored with `makePlugin`, which produces a _decorator layer_
`Layer<Hooks, never, Hooks | PluginDeps>`. The helper threads the previous
(inner) implementation automatically, so plugin authors never touch `inner`.
Plugins stack via `Layer.provide`; `composePlugins` makes that call site clean.

```ts
const runtime = composePlugins([
  RateLimitPlugin, // beforeSignIn: short-circuits with RateLimitError
  EmailNormalizePlugin, // beforeSignUp: lowercases email
  AuditPlugin, // afterSignIn / afterSignUp / afterSignOut: logs
]).pipe(Layer.provide(Hooks.Default)); // no-op base
```

---

## 1. Audit of the existing auth surface

All methods are `Context.Tag`-based services built by `make*Service` factories
and `*Layer` helpers. Errors are `Data.TaggedError` (in `Errors.ts`). Domain
types (`User`, `Session`, `SessionWithUser`, `Credentials`) live in `Types.ts`.

Relevant operations, where a hook could fire, and the services involved:

| Module (`src/…`)       | Operation                                                   | Input                          | Output (success)                    | Deps in scope                                                               |
| ---------------------- | ----------------------------------------------------------- | ------------------------------ | ----------------------------------- | --------------------------------------------------------------------------- |
| `EmailPassword.ts`     | `signUp`                                                    | `SignUpInput`                  | `AuthResult` `{user, session?}`     | `EmailPasswordStore`, `PasswordHasher`, `SessionManager`                    |
| `EmailPassword.ts`     | `signIn`                                                    | `SignInInput`                  | `AuthResult`                        | same                                                                        |
| `AuthLifecycle.ts`     | `signUp`                                                    | `SignUpInput`                  | `AuthLifecycleResult`               | + `EmailVerificationService/Store`                                          |
| `AuthLifecycle.ts`     | `signIn`                                                    | `SignInInput`                  | `AuthLifecycleResult`               | same                                                                        |
| `AuthLifecycle.ts`     | `verifyEmail`                                               | `VerifyEmailInput` `{token,…}` | `AuthLifecycleResult`               | `UserService(+Store)`, `SessionManager`, `EmailVerificationService(+Store)` |
| `Session.ts`           | `createSession`                                             | `(userId, attributes?)`        | `Session`                           | `SessionStore`, `UserStore`                                                 |
| `Session.ts`           | `validateSession`                                           | `(sessionId)`                  | `SessionWithUser`                   | same                                                                        |
| `Session.ts`           | `invalidateSession`                                         | `(sessionId)`                  | `void`                              | `SessionStore`                                                              |
| `Session.ts`           | `invalidateUserSessions`                                    | `(userId)`                     | `void`                              | `SessionStore`                                                              |
| `PasswordReset.ts`     | `requestPasswordReset`                                      | `(email)`                      | `void`                              | `PasswordResetStore`, `PasswordResetUserStore`                              |
| `PasswordReset.ts`     | `resetPassword`                                             | `(token, newPassword)`         | `PasswordResetResult`               | + `PasswordHasher`, `SessionManager`                                        |
| `EmailVerification.ts` | `createVerification`                                        | `(userId, email)`              | `{token, expiresAt}`                | `EmailVerificationStore`                                                    |
| `EmailVerification.ts` | `verifyToken`                                               | `(token)`                      | `EmailVerificationResult`           | same                                                                        |
| `OAuth.ts`             | `generateAuthorizationUrl` / `exchangeCode` / `getUserInfo` | various                        | `OAuthResult`/`OAuthAccount`        | `OAuthStateStore`, `OAuthAccountStore`                                      |
| `WebAuthn.ts`          | `verifyRegistration` / `verifyAuthentication`               | challenge + response           | `Registration/AuthenticationResult` | `ChallengeStore`, `CredentialStore`                                         |
| `Authorization.ts`     | `checkPermission`                                           | `(userId, resource, action)`   | `boolean`/`Permission`              | `RoleStore`                                                                 |

> **Note on "token refresh":** the library has **no separate refresh-token
> endpoint**. `Session.validateSession` implements _sliding_ expiry (it extends
> `expiresAt` on each successful validation). The closest hook to "token
> refresh" is therefore `afterValidateSession` (a session was re-validated and
> its lifetime extended). We model it there rather than inventing a new flow.

### 1.1 Integration scope

There are far more _possible_ hook points than are worth wiring on day one.
We define the **full** `HookDefs` (so the type is stable), but propose to
**wire** only the core lifecycle in Phase 2b:

- **Wired now:** sign-up, sign-in, sign-out (= session invalidation), session
  create, session validate, password-reset request/perform, email-verification
  create/verify.
- **Defined but not yet wired (Phase 2b stretch / future):** OAuth callback,
  WebAuthn authentication, permission checks. They are included in `HookDefs`
  but their call sites are deferred so the PR stays reviewable. _(Flag for
  review: wire all of them now, or defer? Recommendation: defer.)_

---

## 2. Hook points: kind, input, output

Convention: `before*` hooks are **transforms** (they pre-process / validate /
short-circuit the input). `after*` hooks are **taps** (they observe the
result). A few `before*` hooks that only gate (never modify) are still modelled
as transforms returning the input unchanged, so the short-circuit channel is
available uniformly.

| Hook                                       | Kind      | Input → Output                          | Typical use                                                 |
| ------------------------------------------ | --------- | --------------------------------------- | ----------------------------------------------------------- |
| `beforeSignUp`                             | transform | `SignUpInput → SignUpInput`             | normalise email, enrich attributes, registration rate-limit |
| `afterSignUp`                              | tap       | `AuthResult → void`                     | audit, welcome email, analytics                             |
| `beforeSignIn`                             | transform | `SignInInput → SignInInput`             | **rate-limit short-circuit**, normalise email               |
| `afterSignIn`                              | tap       | `AuthResult → void`                     | audit, "new device" notification                            |
| `beforeSignOut`                            | transform | `{ sessionId } → { sessionId }`         | gate / log intent                                           |
| `afterSignOut`                             | tap       | `{ sessionId } → void`                  | audit, cache invalidation                                   |
| `beforeCreateSession`                      | transform | `CreateSessionArgs → CreateSessionArgs` | inject session attributes (device, ip)                      |
| `afterCreateSession`                       | tap       | `Session → void`                        | audit, session metrics                                      |
| `beforeValidateSession`                    | transform | `{ sessionId } → { sessionId }`         | (rare) pre-checks                                           |
| `afterValidateSession`                     | tap       | `SessionWithUser → void`                | "session refreshed" / sliding-expiry audit                  |
| `beforeRequestPasswordReset`               | transform | `{ email } → { email }`                 | rate-limit short-circuit, normalise                         |
| `afterRequestPasswordReset`                | tap       | `{ email } → void`                      | audit (note: existence not revealed)                        |
| `beforeResetPassword`                      | transform | `ResetPasswordArgs → ResetPasswordArgs` | extra password policy                                       |
| `afterResetPassword`                       | tap       | `PasswordResetResult → void`            | audit, "password changed" email                             |
| `beforeCreateVerification`                 | transform | `{ userId, email } → { userId, email }` | rate-limit short-circuit                                    |
| `afterCreateVerification`                  | tap       | `{ userId, email } → void`              | audit                                                       |
| `beforeVerifyEmail`                        | transform | `{ token } → { token }`                 | —                                                           |
| `afterVerifyEmail`                         | tap       | `EmailVerificationResult → void`        | audit, post-verify enrichment                               |
| _(deferred)_ `afterOAuthCallback`          | tap       | `OAuthResult → void`                    | audit social login                                          |
| _(deferred)_ `afterWebAuthnAuthentication` | tap       | `AuthenticationResult → void`           | audit passkey login                                         |
| _(deferred)_ `beforePermissionCheck`       | transform | `PermissionQuery → PermissionQuery`     | policy augmentation                                         |

`CreateSessionArgs`, `ResetPasswordArgs`, etc. are small new record types
introduced alongside the hook defs (they wrap the existing positional
arguments so a hook receives a single named value).

---

## 3. Short-circuit / "deny" semantics

A `before*` transform that wants to **halt** the flow simply **fails** in the
Effect error channel with a typed error. This is the natural Effect idiom and
needs no `Option`:

```ts
beforeSignIn: (input) =>
  rateLimiter.consumeToken(`signin:${input.email}`, RateLimitPresets.login).pipe(Effect.as(input)); // success → pass input through; fail → RateLimitError short-circuits
```

The failure type is added to the hook's `E` channel and therefore to the auth
operation's error channel (see §5).

**Rejected alternative:** returning `Option<Input>` / a `Decision` union to
signal deny. It forces every caller to branch on `None`, duplicates what the
error channel already does, and loses the typed reason. Failing is cleaner and
composes with `Effect.catchTag`.

---

## 4. Error handling for **tap** hooks (decision required — recommendation inside)

The task explicitly asks: _should a failing tap hook abort the operation or just
log? configurable per-hook?_ Decision:

- **Transform hooks: errors ALWAYS propagate.** They are in the critical path
  and are the short-circuit mechanism. Non-negotiable.
- **Tap hooks: propagate by default, with an opt-in `isolate` mode.**
  - _Default `propagate`_: a failing tap fails the operation. Honest and
    type-safe — the failure shows up in `E`. Good for taps that represent real
    invariants (e.g. "must record audit row before returning").
  - _Opt-in `isolate`_: the tap's failure is caught, logged via
    `Effect.logError`, and swallowed (the hook returns the value unchanged).
    Good for best-effort side effects (analytics, non-critical notifications).
    Configured per-plugin via a `makePlugin(impl, { isolateTaps: true })` option
    (or per-hook — see open question O3).

This gives us both test scenarios the task asks for: "all taps fire even if one
fails" (isolate) **and** "operation aborts when a strict tap fails" (propagate).

> **Recommendation:** default = `propagate`. An auth library should not silently
> swallow failures unless the author opts in. The example **audit** plugin will
> use `isolate` (logging must never break login); a second strict-tap test will
> exercise `propagate`.

---

## 5. Layer & dependency graph

`Hooks` is an `Effect.Service`. Its `Default` layer provides the no-op base:

```ts
export class Hooks extends Effect.Service<Hooks>()("@effect-auth/Hooks", {
  // identity for transforms, Effect.void-equivalent (identity) for taps
  succeed: makeNoopHooks(),
}) {}
// Hooks.Default : Layer<Hooks, never, never>
```

`makePlugin` returns a **decorator layer** that _requires_ `Hooks` (the inner
impl) and _provides_ `Hooks` (the wrapped impl), plus whatever services the
plugin's own hook bodies use:

```ts
makePlugin(impl): Layer<Hooks, never, Hooks>                       // zero-dep plugin
makePlugin(impl): Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore> // with deps
```

Composition (`composePlugins`) folds an array with `Layer.provide` so each
plugin is built on top of the previous one. The final layer still _requires_
the base `Hooks` plus the union of all plugin deps:

```
composePlugins([A, B, C]) : Layer<Hooks, never, Hooks | DepsA | DepsB | DepsC>
        .pipe(Layer.provide(Hooks.Default))         // satisfy base Hooks
        .pipe(Layer.provide(rateLimiterLayer, …))   // satisfy plugin deps
```

**Ordering guarantee (proposed):** _array order = execution order for transforms_
— `plugins[0]`'s transform runs **first** (closest to `Hooks.Default`), then
`plugins[1]`, etc.; the caller sees the last plugin's output. Taps fire in the
same order (`plugins[0]` first). The swap-order test in §8 relies on this.

### 5.1 How the wrapping works (the core trick)

Each generated hook is `(value) => innerThenPlugin`:

- **Transform:** `(v) => inner.hook(v).pipe(Effect.flatMap(pluginFn))`
  — inner transforms first, plugin transforms the result.
- **Tap:** `(v) => inner.hook(v).pipe(Effect.zipRight(pluginFn(v)))`
  — inner observes first, then the plugin observes the **original** value; both
  return `void` (or the threaded value — see §6).

The plugin author writes only `pluginFn`; `inner` is captured by `makePlugin`
from `yield* Hooks` inside the decorator layer.

---

## 6. The one real constraint tension (decision required)

The constraints say **(a)** "transform vs tap derived from type signatures, not
a manual annotation" **and** **(b)** "no runtime type reflection." These two
cannot both hold _literally_ for `void`-returning taps, and it's worth being
explicit about why before we commit:

- A transform's wrapper uses `flatMap` (thread inner's output into the plugin).
- A tap's wrapper uses `zipRight` and re-supplies the _original_ value (inner
  returns `void`, so there's nothing to thread).
- These are **different runtime combinators**. To pick between them per hook,
  `makePlugin` needs _some_ runtime signal of each hook's kind. TypeScript types
  are erased at runtime, so "derive purely from the type, with zero runtime
  data, and no reflection" is impossible the moment a tap returns `void`.

Three ways to resolve it:

**Option R1 — canonical value-threading + `tap()` constructor (recommended).**
Make _every_ hook canonically `(v: V) => Effect<V, E, R>` at the service
boundary. Defaults are `Effect.succeed` (identity) for all. The wrapper is then
**uniformly `flatMap`** — one combinator, **no reflection, no per-hook branch**.
Tap authors keep writing `void`-returning bodies and wrap them with a tiny
constructor `Hooks.tap(fn)` = `(v) => fn(v).pipe(Effect.as(v))`. Transforms use
`Hooks.transform(fn)` (or a bare fn). The transform/tap intent is still encoded
in `HookDefs` via `Transform<V>` / `Tap<V>` type aliases, so the _types_ enforce
correct author signatures. _Trade-off:_ using `Hooks.tap(...)` is arguably a
light "annotation," but it's a **value constructor**, not a config flag, and it
buys us a genuinely reflection-free, branch-free runtime.

**Option R2 — single hook spec (one-time, central).** Declare the hook registry
once as data that carries each hook's kind, and _derive_ the `HookDefs` type
from it. `makePlugin` reads the spec at layer-build time to choose `flatMap` vs
`zipRight`. Plugin authors annotate **nothing**. _Trade-off:_ the kind lives in
a central value rather than being inferred from each function's return type —
defensible as "the kind is part of `HookDefs`," but a stricter reading of
constraint (a) might object.

**Option R3 — per-key combinator map passed to `makePlugin`.** Rejected: that
_is_ the per-plugin manual annotation the task forbids.

> **Recommendation:** **R1.** It satisfies (b) exactly (uniform `flatMap`, no
> reflection), keeps the type-level transform/tap distinction in `HookDefs`,
> and the only cost is a one-token `Hooks.tap(...)` wrapper at authoring time.
> If you prefer _zero_ author-side tokens, choose **R2** and we accept the
> looser reading of (a). **Please pick R1 or R2 in review.**

---

## 7. Proposed `HookDefs` interface

Shown in the **R1** form (canonical `Effect<V>` everywhere; `Tap<V>` is an alias
for a value-threading transform whose author writes `void`). Under R2 the
`Tap<V>` entries would be `(v: V) => Effect<void, …>` and the kind comes from the
spec.

```ts
import { Effect } from "effect";
import type * as Types from "./Types.js";
import type * as Errors from "./Errors.js";
import type { SignUpInput, SignInInput, AuthResult } from "./EmailPassword.js";
import type { EmailVerificationResult } from "./EmailVerification.js";
import type { PasswordResetResult } from "./PasswordReset.js";

/** A transform hook: maps a value to a new value of the same type. */
export type Transform<V, E = never, R = never> = (value: V) => Effect.Effect<V, E, R>;

/**
 * A tap hook: observes a value, returns void. Canonically stored as a
 * value-threading transform (R1); authored via `Hooks.tap`.
 */
export type Tap<V, E = never, R = never> = (value: V) => Effect.Effect<void, E, R>;

// Small named-argument wrappers around existing positional calls:
export interface CreateSessionArgs {
  readonly userId: string;
  readonly attributes?: Record<string, unknown>;
}
export interface SessionRef {
  readonly sessionId: string;
}
export interface ResetPasswordArgs {
  readonly token: string;
  readonly newPassword: string;
}
export interface CreateVerificationArgs {
  readonly userId: string;
  readonly email: string;
}
export interface VerifyEmailArgs {
  readonly token: string;
}
export interface EmailRef {
  readonly email: string;
}

export interface HookDefs {
  readonly beforeSignUp: Transform<SignUpInput>;
  readonly afterSignUp: Tap<AuthResult>;
  readonly beforeSignIn: Transform<SignInInput>;
  readonly afterSignIn: Tap<AuthResult>;
  readonly beforeSignOut: Transform<SessionRef>;
  readonly afterSignOut: Tap<SessionRef>;
  readonly beforeCreateSession: Transform<CreateSessionArgs>;
  readonly afterCreateSession: Tap<Types.Session>;
  readonly beforeValidateSession: Transform<SessionRef>;
  readonly afterValidateSession: Tap<Types.SessionWithUser>;
  readonly beforeRequestPasswordReset: Transform<EmailRef>;
  readonly afterRequestPasswordReset: Tap<EmailRef>;
  readonly beforeResetPassword: Transform<ResetPasswordArgs>;
  readonly afterResetPassword: Tap<PasswordResetResult>;
  readonly beforeCreateVerification: Transform<CreateVerificationArgs>;
  readonly afterCreateVerification: Tap<CreateVerificationArgs>;
  readonly beforeVerifyEmail: Transform<VerifyEmailArgs>;
  readonly afterVerifyEmail: Tap<EmailVerificationResult>;
}
```

The `E` and `R` of each hook are intentionally left at the defaults in
`HookDefs`; concrete plugins widen them (e.g. `RateLimitError` in `E`,
`RateLimiter` in `R`) and `makePlugin` surfaces those into the layer's `RIn` /
the operation's error channel.

### 7.1 `makePlugin` signature (sketch)

```ts
export interface MakePluginOptions {
  readonly isolateTaps?: boolean; // default false → propagate (see §4)
}

export const makePlugin: <Impl extends Partial<HookDefs>>(
  impl: Impl,
  options?: MakePluginOptions,
) => Layer.Layer<Hooks, never, Hooks | Effect.Effect.Context<ReturnType<Impl[keyof Impl] & {}>>>; // R = Hooks ∪ union of every hook body's R
```

(The exact `R` extraction is a mapped/conditional type over `Impl`; final form
lands in implementation. Key property: a plugin that uses `RateLimiter` yields
`Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore>`.)

### 7.2 `composePlugins` signature

```ts
export const composePlugins: <Layers extends ReadonlyArray<Layer.Layer<Hooks, never, any>>>(
  plugins: Layers,
) => Layer.Layer<Hooks, never, Hooks | /* union of all RIn minus Hooks */ any>;
```

---

## 8. Integration plan (Phase 2b)

`Hooks` is consumed by the orchestration layer. Two integration styles were
considered:

- **(i)** thread `Hooks` into the existing `make*Service` factories (they gain
  `Hooks` in their `R`), or
- **(ii)** add hook calls only in `AuthLifecycle` (the orchestrator) and in
  `SessionManager` (for create/validate/invalidate).

**Recommendation: (ii) + EmailPassword.** Wire hooks where the operation is
_owned_:

- `EmailPassword.signUp/signIn` gain `beforeSignUp/afterSignUp`,
  `beforeSignIn/afterSignIn`.
- `SessionManager.createSession/validateSession/invalidateSession` gain the
  session hooks (this also covers "sign-out" via `invalidateSession` and
  "token refresh" via `validateSession`).
- `PasswordReset` and `EmailVerification` services gain their respective hooks.
- `AuthLifecycle` inherits everything transitively (it calls the above), so it
  needs no direct hook calls except where it owns a step the children don't
  (none currently).

Each integrated method gains `Hooks` in its `R` channel and the plugin error
types in its `E` channel. Because `Hooks.Default` requires nothing, existing
callers that don't install plugins only need to add `Hooks.Default` to their
layer set (or we re-export a convenience default).

**Per-request scoping:** plugins that hold per-request state (e.g. a rate-limit
key derived from the current IP) are provided as a `Layer.fresh(plugin)` at the
request boundary so each request gets an isolated instance. The library code
does not assume this; it's a documented pattern for app authors. Stateless
plugins (audit, normalise) need no `fresh`.

---

## 9. Example plugins (Phase 2c)

1. **Audit** (taps, `isolateTaps: true`): `afterSignUp`, `afterSignIn`,
   `afterSignOut` → `Effect.logInfo`. Zero extra deps (uses built-in logging).
   Demonstrates the `Layer<Hooks, never, Hooks>` (no-dep) case and isolation.
2. **EmailNormalize** (transform): `beforeSignUp` lowercases/trims
   `input.email`. Zero deps. Demonstrates value transformation + chaining.
3. **RateLimit** (transform, short-circuit): `beforeSignIn` calls
   `RateLimiter.consumeToken` and fails with `RateLimitError` when exceeded.
   Demonstrates a plugin that **declares its own deps**
   (`Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore>`) and the
   short-circuit pattern from §3.

---

## 10. Test plan (Phase 2d)

Using `vite-plus/test` + `Effect.provide` (matching the existing test style):

1. **Transform chaining** — plugin A appends `"-a"`, plugin B appends `"-b"` to
   an email; assert caller sees `"…-a-b"` (A ran before B).
2. **Tap firing under failure** — three audit taps with `isolateTaps`; the
   middle one fails; assert all three side effects recorded and the op succeeds.
3. **Strict tap aborts** — one `propagate` tap fails; assert the operation fails
   with that error (the §4 default).
4. **Ordering** — swap `[A, B]` → `[B, A]`; assert different output (`-b-a`).
5. **Defaults untouched** — a plugin specifying only `beforeSignUp` leaves
   `afterSignIn` etc. as no-ops (assert an un-hooked op behaves identically to
   no plugin installed).
6. **Error propagation / short-circuit** — RateLimit plugin: first N sign-ins
   pass, next fails with `RateLimitError` in the error channel, and `afterSignIn`
   never fires (short-circuited before the operation completed).

---

## 11. Public API surface (final)

From `packages/effect-auth/src/Hooks.ts`, re-exported via `index.ts`:

- `class Hooks` (the `Effect.Service`) + `Hooks.Default`
- `Hooks.tap`, `Hooks.transform` (R1 constructors)
- `makePlugin`
- `composePlugins`
- `type HookDefs`, `Transform`, `Tap`, and the small arg record types

Everything else (wrapping internals) stays module-private.

---

## 12. Open questions for review

- **O1.** Resolve §6: **R1** (recommended — `tap()`/`transform()` constructors,
  reflection-free runtime) or **R2** (central spec, zero author tokens)?
- **O2.** §4 default tap behaviour: confirm **`propagate` by default**, opt-in
  `isolate`. (Alternative: isolate by default.)
- **O3.** Is `isolateTaps` a **per-plugin** option (simpler) or **per-hook**
  (more flexible)? Recommendation: per-plugin now, per-hook later if needed.
- **O4.** §1.1 scope: wire **only core lifecycle** now and defer
  OAuth/WebAuthn/permission hooks (recommended), or wire everything?
- **O5.** §8 integration style: confirm **(ii) at the owning service** rather
  than threading `Hooks` through every factory.
- **O6.** Adding `Hooks` to existing methods' `R`/`E` is technically a
  **breaking change** to those signatures. Acceptable (pre-1.0, `0.0.0`), or do
  we want a non-breaking opt-in wrapper? Recommendation: acceptable pre-1.0.

```

```
