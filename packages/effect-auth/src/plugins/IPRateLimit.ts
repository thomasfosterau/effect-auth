/**
 * IP-keyed rate limiting plugin.
 *
 * Applies per-operation rate limits keyed by the resolved client IP (from the
 * {@link ClientIP} service). When the {@link ClientIP} service is absent (e.g.
 * running outside an HTTP context) the plugin is a no-op.
 *
 * Composes with the existing {@link RateLimiter} / {@link RateLimitStore}
 * infrastructure, so in-memory, SQL, and Redis backends all work.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Result } from "effect"
 * import { KeyValueStore } from "effect/persistence"
 * import {
 *   ClientIP,
 *   composePlugins,
 *   Hooks,
 *   layerKV,
 *   RateLimiter,
 *   RateLimitPresets,
 * } from "@thomasfosterau/effect-auth"
 * import { IPRateLimitPlugin } from "@thomasfosterau/effect-auth/plugins"
 *
 * // The rate-limit store: the in-memory KeyValueStore behind the ephemeral stores.
 * const rateLimitStore = layerKV.pipe(Layer.provide(KeyValueStore.layerMemory))
 *
 * const layer = composePlugins([IPRateLimitPlugin()])
 *   .pipe(Layer.provide(Hooks.Default))
 *   .pipe(Layer.provide(RateLimiter.layer()))
 *   .pipe(Layer.provide(rateLimitStore))
 *
 * const signIn = { email: "ada@example.com", password: "correct horse" }
 *
 * const program = Effect.gen(function* () {
 *   const hooks = yield* Hooks
 *   // Every sign-in from one address draws on the same budget. Spend the whole
 *   // preset budget, then the next attempt is refused.
 *   for (let i = 0; i < RateLimitPresets.login.maxRequests; i++) {
 *     yield* hooks.beforeSignIn(signIn)
 *   }
 *   const refused = yield* Effect.result(hooks.beforeSignIn(signIn))
 *   assert.ok(Result.isFailure(refused))
 * }).pipe(
 *   Effect.provide(layer),
 *   Effect.provideService(ClientIP, { ip: "203.0.113.7" }),
 * )
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module plugins/ip-rate-limit
 */
import { Effect, Option } from "effect";
import { ClientIP } from "../ClientIP.ts";
import type { SignInInput, SignUpInput } from "../email/EmailPassword.ts";
import { makePlugin } from "../Hooks.ts";
import {
  type RateLimitConfig,
  RateLimitPresets,
  RateLimitStore,
  RateLimiter,
} from "../RateLimit.ts";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Per-operation rate limit overrides. Omit an operation to use the
 * corresponding {@link RateLimitPresets} default.
 */
export interface IPRateLimitPluginConfig {
  /** IP-keyed rate limit for sign-in. Default: {@link RateLimitPresets.login}. */
  readonly signIn?: RateLimitConfig;
  /** IP-keyed rate limit for sign-up. Default: {@link RateLimitPresets.registration}. */
  readonly signUp?: RateLimitConfig;
  /** IP-keyed rate limit for password-reset requests. Default: {@link RateLimitPresets.passwordReset}. */
  readonly passwordResetRequest?: RateLimitConfig;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/**
 * Hook-level IP rate limiter.
 *
 * Hooks `beforeSignIn`, `beforeSignUp`, and `beforeRequestPasswordReset`.
 * Keys are `ip:<operation>:<ip>` so they are separate from the per-email keys
 * used by {@link RateLimitPlugin}.
 *
 * Requires `RateLimiter` and `RateLimitStore` in the Layer graph.
 * Uses `Effect.serviceOption(ClientIP)` — no-op when the service is absent.
 */
export const IPRateLimitPlugin = (config?: IPRateLimitPluginConfig) =>
  makePlugin(
    Effect.gen(function* () {
      const rateLimiter = yield* RateLimiter;
      const store = yield* RateLimitStore;

      const check = (operation: string, limitConfig: RateLimitConfig) =>
        Effect.gen(function* () {
          const ipOpt = yield* Effect.serviceOption(ClientIP);
          if (Option.isNone(ipOpt) || ipOpt.value.ip === undefined) return;
          const key = `ip:${operation}:${ipOpt.value.ip}`;
          yield* rateLimiter
            .consumeToken(key, limitConfig)
            .pipe(Effect.provideService(RateLimitStore, store));
        });

      return {
        beforeSignIn: (input: SignInInput) =>
          check("signin", config?.signIn ?? RateLimitPresets.login).pipe(Effect.as(input)),

        beforeSignUp: (input: SignUpInput) =>
          check("signup", config?.signUp ?? RateLimitPresets.registration).pipe(Effect.as(input)),

        beforeRequestPasswordReset: (ref: { readonly email: string }) =>
          check(
            "password-reset",
            config?.passwordResetRequest ?? RateLimitPresets.passwordReset,
          ).pipe(Effect.as(ref)),
      };
    }),
  );
