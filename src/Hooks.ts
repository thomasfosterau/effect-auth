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
 * import { Layer } from "effect"
 * import { AuditPlugin, composePlugins, Hooks, NormalizeEmailPlugin } from "effect-auth"
 *
 * const layer = composePlugins([
 *   NormalizeEmailPlugin, // beforeSignUp/beforeSignIn: lowercases email
 *   AuditPlugin,          // afterSignIn/afterSignUp/afterSignOut: logs
 * ]).pipe(Layer.provide(Hooks.Default))
 * ```
 *
 * @module hooks
 */
import { Context, Effect, Layer } from "effect";
import type * as Errors from "./Errors.ts";
import type { AuthResult, SignInInput, SignUpInput } from "./EmailPassword.ts";
import type { EmailVerificationResult } from "./EmailVerification.ts";
import type { PasswordResetResult } from "./PasswordReset.ts";
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

/**
 * The full set of hook points and their (canonical) signatures.
 *
 * `before*` hooks are transforms (pre-process, validate, or short-circuit the
 * input); `after*` hooks are taps (observe the result). A plugin supplies a
 * `Partial<HookDefs>` - only the hooks it cares about - via {@link makePlugin};
 * everything else falls through to the no-op default.
 */
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

/** Identity hook - passes the value through unchanged (the no-op default). */
const identity = <V>(value: V): Effect.Effect<V, HookError, never> => Effect.succeed(value);

/** Build the no-op default implementation: identity for every hook point. */
const makeNoopHooks = (): HookDefs => ({
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
});

/**
 * The `Hooks` service. Every auth operation that fires hooks reads the current
 * `Hooks` from context, so the active plugin stack can be swapped per request.
 *
 * `Hooks.Default` provides the no-op base (identity for every hook).
 */
export class Hooks extends Context.Service<Hooks, HookDefs>()("@effect-auth/Hooks") {
  /** No-op base layer: identity for every hook point. */
  static readonly Default = Layer.succeed(Hooks, makeNoopHooks());

  /**
   * Adapt a `void`-returning observer into a canonical {@link Tap} that threads
   * the observed value through unchanged. Use this for `after*` hook points.
   *
   * @example
   * ```ts
   * import { Effect } from "effect"
   * import { Hooks, type AuthResult } from "effect-auth"
   *
   * const afterSignIn = Hooks.tap((result: AuthResult) =>
   *   Effect.logInfo("signed in", { userId: result.user.id }),
   * )
   * ```
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
export type PluginImpls = Partial<HookDefs>;

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
 * The set of hook keys that are `after*` taps. Isolation (`isolateTaps: true`)
 * applies exclusively to these — `before*` transforms are never eligible for
 * isolation regardless of plugin options.
 */
const AFTER_HOOK_KEYS: ReadonlySet<string> = new Set([
  "afterSignUp",
  "afterSignIn",
  "afterSignOut",
  "afterCreateSession",
  "afterValidateSession",
  "afterRequestPasswordReset",
  "afterResetPassword",
  "afterCreateVerification",
  "afterVerifyEmail",
]);

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
const wrapHooks = (inner: HookDefs, impls: PluginImpls, options: MakePluginOptions): HookDefs => {
  const innerRecord = inner as unknown as Record<string, Transform<unknown>>;
  const result: Record<string, Transform<unknown>> = { ...innerRecord };

  for (const key of Object.keys(impls) as Array<keyof HookDefs>) {
    const pluginFn = impls[key] as Transform<unknown> | undefined;
    if (pluginFn === undefined) {
      continue;
    }
    const innerFn = innerRecord[key as string]!;
    const isTap = AFTER_HOOK_KEYS.has(key as string);

    result[key as string] = (value: unknown) =>
      innerFn(value).pipe(
        Effect.flatMap((innerOut: unknown) => {
          const ran = pluginFn(innerOut);
          // before* transforms: failures are the deny mechanism — never swallow
          // them, even when isolateTaps is set.
          if (!isTap || !options.isolateTaps) {
            return ran;
          }
          // after* taps with isolateTaps: true — log and swallow errors so a
          // tap failure doesn't abort the auth operation.
          return ran.pipe(
            Effect.catch((error) =>
              Effect.logError(`[effect-auth/hooks] '${String(key)}' failed (isolated)`, error).pipe(
                Effect.as(innerOut),
              ),
            ),
          );
        }),
      );
  }

  return result as unknown as HookDefs;
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
 * import { Effect } from "effect"
 * import { makePlugin, type PluginImpls, type SignInInput } from "effect-auth"
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
 * import { Layer } from "effect"
 * import { AuditPlugin, composePlugins, Hooks, NormalizeEmailPlugin } from "effect-auth"
 *
 * const layer = composePlugins([NormalizeEmailPlugin, AuditPlugin]).pipe(
 *   Layer.provide(Hooks.Default),
 * )
 * ```
 */
export const composePlugins = <RIn = never>(
  plugins: ReadonlyArray<Layer.Layer<Hooks, never, RIn | Hooks>>,
): Layer.Layer<Hooks, never, RIn | Hooks> => {
  if (plugins.length === 0) {
    // Identity passthrough: requires Hooks, provides Hooks unchanged.
    return Layer.effect(
      Hooks,
      Effect.gen(function* () {
        return yield* Hooks;
      }),
    );
  }
  return plugins.reduce((acc, plugin) => plugin.pipe(Layer.provide(acc))) as Layer.Layer<
    Hooks,
    never,
    RIn | Hooks
  >;
};
