/**
 * IP-keyed rate limiting plugin.
 *
 * Applies per-operation rate limits keyed by the resolved client IP (from the
 * {@link ClientIP} service).
 *
 * **A request with no client address is refused.** When the {@link ClientIP}
 * service is absent (a hook run outside an HTTP request, for example a direct
 * `EmailPasswordService.signIn` call from server code), or present but carrying
 * no address, the hook fails with a {@link RateLimitError} (`429` under the HTTP
 * layer). Such a request is never let through unlimited and never counted under
 * a bucket shared with other callers (#389). With this plugin installed, every
 * sign-in, sign-up and password-reset request therefore needs an address.
 *
 * **`Http.make` needs an address source for it.** A Web `Request` carries no
 * socket address, so under `Http.make` the address comes only from
 * `trustedProxy` (for example `ClientIP.cloudflare`). When the `Hooks` in
 * `services` include this plugin and `make` is given neither `trustedProxy` nor
 * `allowMissingClientIp: true`, `make` throws `ClientAddressConfigError` (#389).
 * `allowMissingClientIp: true` accepts that every request without a resolvable
 * address is refused with `429` on these three hooks.
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
import { Effect, Layer, Option } from "effect";
import { ClientIP } from "../ClientIP.ts";
import type { SignInInput, SignUpInput } from "../email/EmailPassword.ts";
import { Hooks, makePlugin } from "../Hooks.ts";
import { recordClientAddressKeyed } from "../HooksClientAddress.ts";
import { RateLimitError } from "../Errors.ts";
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

/** The plugin's hooks, before {@link IPRateLimitPlugin} records it on `Hooks`. */
const ipRateLimitHooks = (config: IPRateLimitPluginConfig | undefined) =>
  makePlugin(
    Effect.gen(function* () {
      const rateLimiter = yield* RateLimiter;
      const store = yield* RateLimitStore;

      const check = (operation: string, limitConfig: RateLimitConfig) =>
        Effect.gen(function* () {
          const ipOpt = yield* Effect.serviceOption(ClientIP);
          const ip = Option.isSome(ipOpt) ? ipOpt.value.ip : undefined;
          // A request with no resolvable address cannot be keyed, and with no
          // ClientIP service there is no address to resolve. Refuse it rather than
          // skip the limit or count it under a bucket other callers share (#389).
          if (ip === undefined) {
            return yield* new RateLimitError({
              message: Option.isNone(ipOpt)
                ? "No ClientIP service in scope; this request cannot be rate limited"
                : "Client address unavailable; this request cannot be rate limited",
              key: `ip:${operation}`,
            });
          }
          const key = `ip:${operation}:${ip}`;
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

/**
 * Hook-level IP rate limiter.
 *
 * Hooks `beforeSignIn`, `beforeSignUp`, and `beforeRequestPasswordReset`.
 * Keys are `ip:<operation>:<ip>` so they are separate from the per-email keys
 * used by {@link RateLimitPlugin}.
 *
 * Requires `RateLimiter` and `RateLimitStore` in the Layer graph.
 *
 * A request with no client address is refused with a {@link RateLimitError}:
 * both when the {@link ClientIP} service is absent and when it carries no
 * address. Under `Http.make`, give the handler a `trustedProxy`, or `make`
 * throws `ClientAddressConfigError` unless `allowMissingClientIp: true` is set.
 * The module documentation has the details.
 */
export const IPRateLimitPlugin = (config?: IPRateLimitPluginConfig) =>
  Layer.effect(
    Hooks,
    // Record the plugin on the Hooks it builds, so Http.make can refuse it at
    // build when the handler has no client-address source (#389).
    Effect.gen(function* () {
      return recordClientAddressKeyed(yield* Hooks, "IPRateLimitPlugin");
    }),
  ).pipe(Layer.provide(ipRateLimitHooks(config)));
