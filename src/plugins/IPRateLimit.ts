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
 * import { Layer } from "effect"
 * import { composePlugins, Hooks, RateLimiter, RateLimitStore } from "effect-auth"
 * import { IPRateLimitPlugin } from "effect-auth/plugins"
 *
 * const layer = composePlugins([IPRateLimitPlugin()])
 *   .pipe(Layer.provide(Hooks.Default))
 *   .pipe(Layer.provide(RateLimiter.layer()))
 *   .pipe(Layer.provide(myRateLimitStore))
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
