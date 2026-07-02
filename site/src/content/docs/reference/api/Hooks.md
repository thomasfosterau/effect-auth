---
title: "Hooks"
description: "API reference for the Hooks module."
---

## Hooks overview

Hooks - a typed, composable plugin system for the auth lifecycle.

The {@link Hooks} service exposes a fixed set of _hook points_ that fire at
every significant moment in the auth flow. Plugins are authored with
{@link makePlugin}, which produces a _decorator_ Layer: it requires the
previous (inner) `Hooks` implementation and provides a wrapped one, threading
the inner call automatically so plugin authors never deal with `inner`.

Two flavours of hook:

- **Transform** ({@link Transform}) - receives a value and returns a
  (possibly modified) value of the same type. Sits in the critical path and
  may _short-circuit_ by failing in the Effect error channel.
- **Tap** ({@link Tap}) - observes a value and performs a side effect. Tap
  functions are authored as `void`-returning Effects via {@link Hooks.tap},
  which adapts them to the canonical value-threading shape.

Plugins stack with `Layer.provide`; {@link composePlugins} makes that clean.

**Example**

```ts
import { Layer } from "effect";
import { AuditPlugin, composePlugins, Hooks, NormalizeEmailPlugin } from "effect-auth";

const layer = composePlugins([
  NormalizeEmailPlugin, // beforeSignUp/beforeSignIn: lowercases email
  AuditPlugin, // afterSignIn/afterSignUp/afterSignOut: logs
]).pipe(Layer.provide(Hooks.Default));
```

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [CreateSessionArgs (interface)](#createsessionargs-interface)
  - [CreateVerificationArgs (interface)](#createverificationargs-interface)
  - [EmailRef (interface)](#emailref-interface)
  - [HookDefs (interface)](#hookdefs-interface)
  - [HookError (type alias)](#hookerror-type-alias)
  - [Hooks (class)](#hooks-class)
  - [MakePluginOptions (interface)](#makepluginoptions-interface)
  - [PluginImpls (type alias)](#pluginimpls-type-alias)
  - [ResetPasswordArgs (interface)](#resetpasswordargs-interface)
  - [SessionRef (interface)](#sessionref-interface)
  - [Tap (type alias)](#tap-type-alias)
  - [Transform (type alias)](#transform-type-alias)
  - [VerifyEmailArgs (interface)](#verifyemailargs-interface)
  - [composePlugins](#composeplugins)
  - [makePlugin](#makeplugin)

---

# utils

## CreateSessionArgs (interface)

Named arguments for the `beforeCreateSession` hook.

**Signature**

```ts
export interface CreateSessionArgs {
  readonly userId: string;
  readonly attributes?: Record<string, unknown>;
}
```

## CreateVerificationArgs (interface)

Named arguments for the email-verification creation hooks.

**Signature**

```ts
export interface CreateVerificationArgs {
  readonly userId: string;
  readonly email: string;
}
```

## EmailRef (interface)

A reference to an email address, used by password-reset hooks.

**Signature**

```ts
export interface EmailRef {
  readonly email: string;
}
```

## HookDefs (interface)

The full set of hook points and their (canonical) signatures.

`before*` hooks are transforms (pre-process, validate, or short-circuit the
input); `after*` hooks are taps (observe the result). A plugin supplies a
`Partial<HookDefs>` - only the hooks it cares about - via {@link makePlugin};
everything else falls through to the no-op default.

**Signature**

```ts
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

## HookError (type alias)

The error channel permitted for every hook. Hooks participate in the existing
auth error channel; a transform that fails with one of these short-circuits
the operation. Kept intentionally small (the realistic set a plugin raises)
so integrated method signatures don't balloon.

**Signature**

```ts
export type HookError = Errors.AuthError | Errors.RateLimitError;
```

## Hooks (class)

The `Hooks` service. Every auth operation that fires hooks reads the current
`Hooks` from context, so the active plugin stack can be swapped per request.

`Hooks.Default` provides the no-op base (identity for every hook).

**Signature**

```ts
export declare class Hooks
```

## MakePluginOptions (interface)

Options controlling how a plugin's hooks behave.

**Signature**

```ts
export interface MakePluginOptions {
  /**
   * When `true`, failures from this plugin's hooks are caught, logged via
   * `Effect.logError`, and swallowed (the value flows on unchanged). Intended
   * for best-effort, tap-only plugins (e.g. audit logging) where a logging
   * failure must never break the auth operation.
   *
   * Defaults to `false`: hook failures propagate through the error channel.
   * Transform hooks rely on propagation for their short-circuit semantics, so
   * `isolateTaps` should only be enabled for tap-only plugins.
   */
  readonly isolateTaps?: boolean;
}
```

## PluginImpls (type alias)

A plugin's hook implementations - any subset of the hook points.

**Signature**

```ts
export type PluginImpls = Partial<HookDefs>;
```

## ResetPasswordArgs (interface)

Named arguments for the `beforeResetPassword` hook.

**Signature**

```ts
export interface ResetPasswordArgs {
  readonly token: string;
  readonly newPassword: string;
}
```

## SessionRef (interface)

A reference to a session, used by sign-out / validation hooks.

**Signature**

```ts
export interface SessionRef {
  readonly sessionId: string;
}
```

## Tap (type alias)

A **tap** hook: observes a value (side-effect only).

Structurally identical to {@link Transform} - in the canonical runtime every
hook threads its value through unchanged - but the name documents intent.
Author tap implementations with {@link Hooks.tap}, which lets you write a
`void`-returning Effect and adapts it to thread the value automatically.

**Signature**

```ts
export type Tap<V> = (value: V) => Effect.Effect<V, HookError, never>;
```

## Transform (type alias)

A **transform** hook: maps a value to a new value of the same type.

Returning a modified value mutates what flows downstream; failing in the
error channel short-circuits the operation (this is how a "deny" - e.g. a
rate-limit rejection - is expressed).

**Signature**

```ts
export type Transform<V> = (value: V) => Effect.Effect<V, HookError, never>;
```

## VerifyEmailArgs (interface)

Named arguments for the `beforeVerifyEmail` hook.

**Signature**

```ts
export interface VerifyEmailArgs {
  readonly token: string;
}
```

## composePlugins

Compose an ordered array of plugin Layers into a single Layer, folding them
with `Layer.provide`.

**Ordering:** array order is execution order for transforms - `plugins[0]`
runs first (closest to the base `Hooks.Default`), `plugins[length - 1]` last;
the caller observes the last plugin's output. Taps fire in the same order.

The result still _requires_ the base `Hooks` (provide `Hooks.Default`) plus
the union of every plugin's own dependencies.

**Signature**

```ts
export declare const composePlugins: <RIn = never>(
  plugins: ReadonlyArray<Layer.Layer<Hooks, never, RIn | Hooks>>,
) => Layer.Layer<Hooks, never, RIn | Hooks>;
```

**Example**

```ts
import { Layer } from "effect";
import { AuditPlugin, composePlugins, Hooks, NormalizeEmailPlugin } from "effect-auth";

const layer = composePlugins([NormalizeEmailPlugin, AuditPlugin]).pipe(
  Layer.provide(Hooks.Default),
);
```

## makePlugin

Build a plugin as a wrapping Layer.

A plugin only specifies the hooks it cares about. The returned Layer
_requires_ `Hooks` (the previous implementation in the stack) and _provides_
`Hooks` (the wrapped one), so plugins compose by `Layer.provide` stacking.

Two forms:

- **Static** - pass the implementations directly. The plugin's hook functions
  must be self-contained (`R = never`), so this form is for zero-dependency
  plugins. Returns `Layer<Hooks, never, Hooks>`.
- **Effectful** - pass an `Effect` that acquires the plugin's own service
  dependencies (`yield* SomeService`) and returns the implementations. Those
  dependencies surface in the Layer's requirements:
  `Layer<Hooks, never, Hooks | SomeService>`.

**Signature**

```ts
export declare function makePlugin<R>(
  build: Effect.Effect<PluginImpls, never, R>,
  options?: MakePluginOptions,
): Layer.Layer<Hooks, never, Hooks | R>;
export declare function makePlugin(
  impls: PluginImpls,
  options?: MakePluginOptions,
): Layer.Layer<Hooks, never, Hooks>;
```

**Example**

```ts
import { Effect } from "effect";
import { makePlugin, type PluginImpls, type SignInInput } from "effect-auth";

// Zero-dependency: pass the hook implementations directly.
const NormalizeEmail = makePlugin({
  beforeSignUp: (input) => Effect.succeed({ ...input, email: input.email.toLowerCase() }),
});

// Effectful: acquire the plugin's own services first (they surface in the
// Layer's requirements).
const Logged = makePlugin(
  Effect.gen(function* () {
    yield* Effect.logInfo("plugin initialized");
    return {
      beforeSignIn: (input: SignInInput) => Effect.succeed(input),
    } satisfies PluginImpls;
  }),
);
```
