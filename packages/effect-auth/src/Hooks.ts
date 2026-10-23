/**
 * Hooks - a typed, composable plugin system for the auth lifecycle.
 *
 * The {@link Hooks} service exposes a fixed set of *hook points* that fire at
 * every significant moment in the auth flow. Plugins are authored with
 * {@link makePlugin}, which produces a *decorator* Layer: it requires the
 * previous (inner) `Hooks` implementation and provides a wrapped one, threading
 * the inner call automatically so plugin authors never deal with `inner`.
 *
 * Two flavours of hook:
 *
 * - **Transform** ({@link Transform}) - receives a value and returns a
 *   (possibly modified) value of the same type. Sits in the critical path and
 *   may *short-circuit* by failing in the Effect error channel.
 * - **Tap** ({@link Tap}) - observes a value and performs a side effect. Tap
 *   functions are authored as `void`-returning Effects via {@link Hooks.tap},
 *   which adapts them to the canonical value-threading shape.
 *
 * Plugins stack with `Layer.provide`; {@link composePlugins} makes that clean.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { composePlugins, Hooks } from "@thomasfosterau/effect-auth"
 * import { AuditPlugin, NormalizeEmailPlugin } from "@thomasfosterau/effect-auth/plugins"
 *
 * const layer = composePlugins([
 *   NormalizeEmailPlugin, // beforeSignUp/beforeSignIn: lowercases email
 *   AuditPlugin, // afterSignIn/afterSignUp/afterSignOut: logs
 * ]).pipe(Layer.provide(Hooks.Default))
 *
 * const program = Effect.gen(function* () {
 *   const hooks = yield* Hooks
 *   const input = yield* hooks.beforeSignIn({ email: "  Ada@Example.com ", password: "correct horse" })
 *   assert.equal(input.email, "ada@example.com")
 *   yield* hooks.afterSignIn({ user: { id: "u-1", createdAt: new Date(), updatedAt: new Date(), attributes: {} } })
 * }).pipe(Effect.provide(layer))
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module hooks
 */
import { Array as Arr, Context, Effect, Layer } from "effect";
import type * as Errors from "./Errors.ts";
import type { AuthResult, SignInInput, SignUpInput } from "./email/EmailPassword.ts";
import type { EntityRef } from "./Entity.ts";
import type { EmailVerificationResult } from "./email/EmailVerification.ts";
import type { PasswordResetResult } from "./password/PasswordReset.ts";
import type * as Types from "./Types.ts";

/**
 * The error channel permitted for every hook. Hooks participate in the existing
 * auth error channel; a transform that fails with one of these short-circuits
 * the operation.
 *
 * Flow-outcome errors are included so plugins can raise specific tags (e.g.
 * `AccountLockedError`, `CaptchaError`) and the HTTP layer can map them to the
 * correct status codes. `AuthError` covers any remaining infrastructure/
 * unexpected failures.
 */
export type HookError =
  | Errors.AuthError
  | Errors.RateLimitError
  | Errors.AccountLockedError
  | Errors.UserBannedError
  | Errors.CaptchaError
  | Errors.PwnedPasswordError;

/** A reference to a session, used by sign-out / validation hooks. */
export interface SessionRef {
  readonly sessionId: string;
}

/** Named arguments for the `beforeCreateSession` hook. */
export interface CreateSessionArgs {
  readonly userId: string;
  readonly attributes?: Record<string, unknown>;
}

/** Named arguments for the `beforeResetPassword` hook. */
export interface ResetPasswordArgs {
  readonly token: string;
  readonly newPassword: string;
}

/** Named arguments for the email-verification creation hooks. */
export interface CreateVerificationArgs {
  readonly userId: string;
  readonly email: string;
}

/** Named arguments for the `beforeVerifyEmail` hook. */
export interface VerifyEmailArgs {
  readonly token: string;
}

/** A reference to an email address, used by password-reset hooks. */
export interface EmailRef {
  readonly email: string;
}

/**
 * Named arguments for the `afterWrite` hook: a write the application made, and
 * the principal that made it. The application fires it with
 * {@link recordWrite} after the write commits, so an audit plugin records
 * unattended writes as well as a person's: a background job never signs in,
 * so the sign-in, sign-up and sign-out events never name it.
 */
export interface WriteEvent {
  /**
   * The acting principal: the viewer's entity (`User::"<id>"`, as
   * `Guard.Guards.principal` builds it) or a system principal
   * (`System::"<name>"`, as `Guard.requireSystem` yields it).
   */
  readonly principal: EntityRef;
  /** The action performed, as the `Action::"<action>"` id the gate decided. */
  readonly action: string;
  /** The resource written. */
  readonly resource: EntityRef;
}

/**
 * Named arguments for the `afterDeliveryFailure` hook: a send run off the
 * response path failed (see `Delivery.makeDetachedSend`). It never reaches the
 * caller, so this hook and the delivery metric are where it is seen. The
 * message's parameters (its token or code) are not included.
 */
export interface DeliveryFailure {
  /** The message's purpose tag (`Delivery.DeliveryPurpose`). */
  readonly purpose: string;
  /** What the send failed with: the sender's error, as it reported it. */
  readonly cause: unknown;
}

/**
 * A **transform** hook: maps a value to a new value of the same type.
 *
 * Returning a modified value mutates what flows downstream; failing in the
 * error channel short-circuits the operation (this is how a "deny" - e.g. a
 * rate-limit rejection - is expressed).
 */
export type Transform<V> = (value: V) => Effect.Effect<V, HookError, never>;

/**
 * A **tap** hook: observes a value (side-effect only).
 *
 * Structurally identical to {@link Transform} - in the canonical runtime every
 * hook threads its value through unchanged - but the name documents intent.
 * Author tap implementations with {@link Hooks.tap}, which lets you write a
 * `void`-returning Effect and adapts it to thread the value automatically.
 */
export type Tap<V> = (value: V) => Effect.Effect<V, HookError, never>;

/** Identity hook - passes the value through unchanged (the no-op default). */
const identity = <V>(value: V): Effect.Effect<V, HookError, never> => Effect.succeed(value);

/** Build the no-op default implementation: identity for every hook point. */
const makeNoopHooks = (): typeof Hooks.Service => ({
  beforeSignUp: identity,
  afterSignUp: identity,
  beforeSignIn: identity,
  afterSignIn: identity,
  beforeSignOut: identity,
  afterSignOut: identity,
  beforeCreateSession: identity,
  afterCreateSession: identity,
  beforeValidateSession: identity,
  afterValidateSession: identity,
  beforeRequestPasswordReset: identity,
  afterRequestPasswordReset: identity,
  beforeResetPassword: identity,
  afterResetPassword: identity,
  beforeCreateVerification: identity,
  afterCreateVerification: identity,
  beforeVerifyEmail: identity,
  afterVerifyEmail: identity,
  afterWrite: identity,
  afterDeliveryFailure: identity,
});

/**
 * The full set of hook points and their (canonical) signatures.
 *
 * `before*` hooks are transforms (pre-process, validate, or short-circuit the
 * input); `after*` hooks are taps (observe the result). A plugin supplies a
 * `Partial<typeof Hooks.Service>` - only the hooks it cares about - via
 * {@link makePlugin}; everything else falls through to the no-op default.
 *
 * The `Hooks` service. Every auth operation that fires hooks reads the current
 * `Hooks` from context, so the active plugin stack can be swapped per request.
 *
 * `Hooks.Default` provides the no-op base (identity for every hook).
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { Hooks } from "@thomasfosterau/effect-auth"
 * import type { AuthResult } from "@thomasfosterau/effect-auth/email"
 *
 * // `Hooks.tap` adapts a void-returning observer into an after* tap.
 * const seen: Array<string> = []
 * const afterSignIn = Hooks.tap((result: AuthResult) =>
 *   Effect.sync(() => {
 *     seen.push(result.user.id)
 *   }),
 * )
 *
 * const result: AuthResult = {
 *   user: { id: "u-1", createdAt: new Date(), updatedAt: new Date(), attributes: {} },
 * }
 * // A tap observes the value and hands it on unchanged.
 * const passedThrough = await Effect.runPromise(afterSignIn(result))
 * assert.equal(passedThrough, result)
 * assert.deepEqual(seen, ["u-1"])
 * ```
 */
export class Hooks extends Context.Service<
  Hooks,
  {
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
    /** A write the application made, fired by {@link recordWrite}. */
    readonly afterWrite: Tap<WriteEvent>;
    /** A send run off the response path failed; see {@link DeliveryFailure}. */
    readonly afterDeliveryFailure: Tap<DeliveryFailure>;
  }
>()("@effect-auth/Hooks") {
  /** No-op base layer: identity for every hook point. */
  static readonly Default = Layer.succeed(Hooks, makeNoopHooks());

  /**
   * Adapt a `void`-returning observer into a canonical {@link Tap} that threads
   * the observed value through unchanged. Use this for `after*` hook points.
   * The example is on the {@link Hooks} class.
   */
  static readonly tap =
    <V>(fn: (value: V) => Effect.Effect<void, HookError, never>): Tap<V> =>
    (value: V): Effect.Effect<V, HookError, never> =>
      fn(value).pipe(Effect.as(value));

  /**
   * Identity helper for authoring {@link Transform} hooks. Purely for symmetry
   * with {@link Hooks.tap}; a bare `(value) => Effect<value>` works just as well.
   */
  static readonly transform = <V>(fn: Transform<V>): Transform<V> => fn;
}

/** A plugin's hook implementations - any subset of the hook points. */
export type PluginImpls = Partial<typeof Hooks.Service>;

/** Options controlling how a plugin's hooks behave. */
export interface MakePluginOptions {
  /**
   * When `true`, failures from this plugin's **`after*` tap hooks** are caught,
   * logged via `Effect.logError`, and swallowed (the value flows on unchanged).
   * Intended for best-effort, tap-only plugins (e.g. audit logging) where a
   * logging failure must never break the auth operation.
   *
   * Defaults to `false`: after-hook failures propagate through the error
   * channel.
   *
   * **`before*` transforms are never isolated regardless of this flag.**
   * Transform failures are the short-circuit / deny mechanism (captcha,
   * geo-block, lockout, etc.); silencing them would silently allow operations
   * that should be denied.
   */
  readonly isolateTaps?: boolean;
}

/**
 * Wrap one hook point: when the plugin provides `pluginFn`, call `innerFn`
 * first and pipe its output into the plugin's function; otherwise keep
 * `innerFn` as is. When `isolate` is set, the plugin's failures are logged and
 * swallowed and the inner output flows on unchanged.
 */
const wrapHook = <V>(
  key: keyof typeof Hooks.Service,
  innerFn: Transform<V>,
  pluginFn: Transform<V> | undefined,
  isolate: boolean,
): Transform<V> => {
  if (pluginFn === undefined) {
    return innerFn;
  }
  return (value) =>
    innerFn(value).pipe(
      Effect.flatMap((innerOut) => {
        const ran = pluginFn(innerOut);
        // before* transforms: failures are the deny mechanism — never swallow
        // them, even when isolateTaps is set.
        if (!isolate) {
          return ran;
        }
        // after* taps with isolateTaps: true — log and swallow errors so a
        // tap failure doesn't abort the auth operation.
        return ran.pipe(
          Effect.catch((error) =>
            Effect.logError(`[effect-auth/hooks] '${key}' failed (isolated)`, error).pipe(
              Effect.as(innerOut),
            ),
          ),
        );
      }),
    );
};

/**
 * Wrap an inner implementation with a plugin's hooks. For each hook the plugin
 * provides, the result calls `inner` first and pipes its output into the
 * plugin's function.
 *
 * Isolation is per-hook-kind, not per-plugin:
 * - `before*` transforms: **never** isolated — failures propagate (this is the
 *   deny / short-circuit mechanism). `isolateTaps: true` has no effect here.
 * - `after*` taps: isolated only when `options.isolateTaps === true`.
 */
const wrapHooks = (
  inner: typeof Hooks.Service,
  impls: PluginImpls,
  options: MakePluginOptions,
): typeof Hooks.Service => {
  const isolateTaps = Boolean(options.isolateTaps);
  // The spread keeps `inner`'s symbol-keyed records (`HooksClientAddress.ts`).
  return {
    ...inner,
    beforeSignUp: wrapHook("beforeSignUp", inner.beforeSignUp, impls.beforeSignUp, false),
    afterSignUp: wrapHook("afterSignUp", inner.afterSignUp, impls.afterSignUp, isolateTaps),
    beforeSignIn: wrapHook("beforeSignIn", inner.beforeSignIn, impls.beforeSignIn, false),
    afterSignIn: wrapHook("afterSignIn", inner.afterSignIn, impls.afterSignIn, isolateTaps),
    beforeSignOut: wrapHook("beforeSignOut", inner.beforeSignOut, impls.beforeSignOut, false),
    afterSignOut: wrapHook("afterSignOut", inner.afterSignOut, impls.afterSignOut, isolateTaps),
    beforeCreateSession: wrapHook(
      "beforeCreateSession",
      inner.beforeCreateSession,
      impls.beforeCreateSession,
      false,
    ),
    afterCreateSession: wrapHook(
      "afterCreateSession",
      inner.afterCreateSession,
      impls.afterCreateSession,
      isolateTaps,
    ),
    beforeValidateSession: wrapHook(
      "beforeValidateSession",
      inner.beforeValidateSession,
      impls.beforeValidateSession,
      false,
    ),
    afterValidateSession: wrapHook(
      "afterValidateSession",
      inner.afterValidateSession,
      impls.afterValidateSession,
      isolateTaps,
    ),
    beforeRequestPasswordReset: wrapHook(
      "beforeRequestPasswordReset",
      inner.beforeRequestPasswordReset,
      impls.beforeRequestPasswordReset,
      false,
    ),
    afterRequestPasswordReset: wrapHook(
      "afterRequestPasswordReset",
      inner.afterRequestPasswordReset,
      impls.afterRequestPasswordReset,
      isolateTaps,
    ),
    beforeResetPassword: wrapHook(
      "beforeResetPassword",
      inner.beforeResetPassword,
      impls.beforeResetPassword,
      false,
    ),
    afterResetPassword: wrapHook(
      "afterResetPassword",
      inner.afterResetPassword,
      impls.afterResetPassword,
      isolateTaps,
    ),
    beforeCreateVerification: wrapHook(
      "beforeCreateVerification",
      inner.beforeCreateVerification,
      impls.beforeCreateVerification,
      false,
    ),
    afterCreateVerification: wrapHook(
      "afterCreateVerification",
      inner.afterCreateVerification,
      impls.afterCreateVerification,
      isolateTaps,
    ),
    beforeVerifyEmail: wrapHook(
      "beforeVerifyEmail",
      inner.beforeVerifyEmail,
      impls.beforeVerifyEmail,
      false,
    ),
    afterVerifyEmail: wrapHook(
      "afterVerifyEmail",
      inner.afterVerifyEmail,
      impls.afterVerifyEmail,
      isolateTaps,
    ),
    afterWrite: wrapHook("afterWrite", inner.afterWrite, impls.afterWrite, isolateTaps),
    afterDeliveryFailure: wrapHook(
      "afterDeliveryFailure",
      inner.afterDeliveryFailure,
      impls.afterDeliveryFailure,
      isolateTaps,
    ),
  };
};

/**
 * Build a plugin as a wrapping Layer.
 *
 * A plugin only specifies the hooks it cares about. The returned Layer
 * *requires* `Hooks` (the previous implementation in the stack) and *provides*
 * `Hooks` (the wrapped one), so plugins compose by `Layer.provide` stacking.
 *
 * Two forms:
 *
 * - **Static** - pass the implementations directly. The plugin's hook functions
 *   must be self-contained (`R = never`), so this form is for zero-dependency
 *   plugins. Returns `Layer<Hooks, never, Hooks>`.
 * - **Effectful** - pass an `Effect` that acquires the plugin's own service
 *   dependencies (`yield* SomeService`) and returns the implementations. Those
 *   dependencies surface in the Layer's requirements:
 *   `Layer<Hooks, never, Hooks | SomeService>`.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { composePlugins, Hooks, makePlugin, type PluginImpls } from "@thomasfosterau/effect-auth"
 * import type { SignInInput } from "@thomasfosterau/effect-auth/email"
 *
 * // Zero-dependency: pass the hook implementations directly.
 * const NormalizeEmail = makePlugin({
 *   beforeSignUp: (input) => Effect.succeed({ ...input, email: input.email.toLowerCase() }),
 * })
 *
 * // Effectful: acquire the plugin's own services first (they surface in the
 * // Layer's requirements).
 * const Logged = makePlugin(
 *   Effect.gen(function* () {
 *     yield* Effect.logInfo("plugin initialized")
 *     return {
 *       beforeSignIn: (input: SignInInput) => Effect.succeed(input),
 *     } satisfies PluginImpls
 *   }),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const hooks = yield* Hooks
 *   const input = yield* hooks.beforeSignUp({ email: "Ada@Example.com", password: "correct horse" })
 *   assert.equal(input.email, "ada@example.com")
 * }).pipe(Effect.provide(composePlugins([NormalizeEmail, Logged]).pipe(Layer.provide(Hooks.Default))))
 *
 * await Effect.runPromise(program)
 * ```
 */
export function makePlugin<R>(
  build: Effect.Effect<PluginImpls, never, R>,
  options?: MakePluginOptions,
): Layer.Layer<Hooks, never, Hooks | R>;
export function makePlugin(
  impls: PluginImpls,
  options?: MakePluginOptions,
): Layer.Layer<Hooks, never, Hooks>;
export function makePlugin(
  source: PluginImpls | Effect.Effect<PluginImpls, never, unknown>,
  options: MakePluginOptions = {},
): Layer.Layer<Hooks, never, unknown> {
  return Layer.effect(
    Hooks,
    Effect.gen(function* () {
      const inner = yield* Hooks;
      const impls = Effect.isEffect(source) ? yield* source : source;
      return wrapHooks(inner, impls, options);
    }),
  );
}

/**
 * Compose an ordered array of plugin Layers into a single Layer, folding them
 * with `Layer.provide`.
 *
 * **Ordering:** array order is execution order for transforms - `plugins[0]`
 * runs first (closest to the base `Hooks.Default`), `plugins[length - 1]` last;
 * the caller observes the last plugin's output. Taps fire in the same order.
 *
 * The result still *requires* the base `Hooks` (provide `Hooks.Default`) plus
 * the union of every plugin's own dependencies.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { composePlugins, Hooks } from "@thomasfosterau/effect-auth"
 * import { AuditPlugin, NormalizeEmailPlugin } from "@thomasfosterau/effect-auth/plugins"
 *
 * const layer = composePlugins([NormalizeEmailPlugin, AuditPlugin]).pipe(
 *   Layer.provide(Hooks.Default),
 * )
 *
 * // Transforms run in array order: the caller observes the last plugin's output.
 * const program = Effect.gen(function* () {
 *   const hooks = yield* Hooks
 *   const input = yield* hooks.beforeSignUp({ email: " Ada@Example.com ", password: "correct horse" })
 *   assert.equal(input.email, "ada@example.com")
 * }).pipe(Effect.provide(layer))
 *
 * await Effect.runPromise(program)
 * ```
 */
export const composePlugins = <RIn = never>(
  plugins: ReadonlyArray<Layer.Layer<Hooks, never, RIn | Hooks>>,
): Layer.Layer<Hooks, never, RIn | Hooks> =>
  Arr.match(plugins, {
    // Identity passthrough: requires Hooks, provides Hooks unchanged.
    onEmpty: () => Layer.effect(Hooks, Hooks),
    onNonEmpty: (nonEmpty) =>
      Arr.reduce(
        Arr.tailNonEmpty(nonEmpty),
        Arr.headNonEmpty(nonEmpty),
        (acc, plugin): Layer.Layer<Hooks, never, RIn | Hooks> => plugin.pipe(Layer.provide(acc)),
      ),
  });

/**
 * Fire the `afterWrite` hook for a write the application made: call it after
 * the write commits, naming the principal that made it. Effect-auth makes no
 * application writes itself, so this is the one place the event comes from.
 * `AuditPlugin` logs it as `auth.write`.
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import { AuditPlugin } from "@thomasfosterau/effect-auth/plugins"
 *
 * const chargeInvoice = (id: string) =>
 *   Effect.gen(function* () {
 *     // ...the write itself...
 *     yield* Auth.recordWrite({
 *       principal: Auth.System.ref("billing-cron"),
 *       action: "invoice:charge",
 *       resource: Auth.Entity.ref("Invoice", id),
 *     })
 *   })
 *
 * await Effect.runPromise(
 *   chargeInvoice("inv-1").pipe(Effect.provide(AuditPlugin.pipe(Layer.provide(Auth.Hooks.Default)))),
 * )
 * ```
 */
export const recordWrite = (event: WriteEvent): Effect.Effect<void, HookError, Hooks> =>
  Effect.gen(function* () {
    const hooks = yield* Hooks;
    yield* hooks.afterWrite(event);
  });
