/**
 * IP-keyed rate limiting plugin.
 *
 * Applies per-operation rate limits keyed by the resolved client IP (from the
 * {@link ClientIP} service): every first-factor authentication attempt
 * (`beforeAuthenticate`: email and password, username, email and phone OTP,
 * magic link, passkey) draws on one `signin` bucket per address, second-factor
 * redemptions on a `second-factor` bucket, and sign-up and password-reset
 * requests on their own.
 *
 * **Unkeyed attempts count too**. An unknown or expired second-factor
 * challenge, magic-link token or passkey challenge names no account, so the
 * per-account plugins let it through; the flow still fires
 * `beforeAuthenticate` for it, and this plugin draws it from the same bucket
 * as a keyed attempt of that method, so guessing tokens costs the guesser's
 * address its budget.
 *
 * **A request with no client address is refused.** When the {@link ClientIP}
 * service is absent (a hook run outside an HTTP request, for example a direct
 * `EmailPasswordService.signIn` call from server code), or present but carrying
 * no address, the hook fails with a {@link RateLimitError} (`429` under the HTTP
 * layer). Such a request is never let through unlimited and never counted under
 * a bucket shared with other callers. With this plugin installed, every
 * authentication attempt, sign-up and password-reset request therefore needs
 * an address.
 *
 * **`Http.make` needs an address source for it.** A Web `Request` carries no
 * socket address, so under `Http.make` the address comes only from
 * `trustedProxy` (for example `ClientIP.cloudflare`). When the `Hooks` in
 * `services` include this plugin and `make` is given no `trustedProxy`, `make`
 * throws `ClientAddressConfigError`: with no proxy no request has an
 * address, so the plugin would refuse every one of them.
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
 *   RateLimiter,
 *   RateLimitPresets,
 *   RateLimitStoreKV,
 * } from "@thomasfosterau/effect-auth"
 * import { IPRateLimitPlugin } from "@thomasfosterau/effect-auth/plugins"
 *
 * // A single-process rate-limit store; in production use effect-auth/sql's.
 * const rateLimitStore = RateLimitStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory))
 *
 * const layer = composePlugins([IPRateLimitPlugin()])
 *   .pipe(Layer.provide(Hooks.Default))
 *   .pipe(Layer.provide(RateLimiter.layer()))
 *   .pipe(Layer.provide(rateLimitStore))
 *
 * const signIn = {
 *   method: "email-password",
 *   identifier: { type: "email", value: "ada@example.com" },
 * } as const
 *
 * const program = Effect.gen(function* () {
 *   const hooks = yield* Hooks
 *   // Every sign-in from one address draws on the same budget. Spend the whole
 *   // preset budget, then the next attempt is refused.
 *   for (let i = 0; i < RateLimitPresets.login.maxRequests; i++) {
 *     yield* hooks.beforeAuthenticate(signIn)
 *   }
 *   const refused = yield* Effect.result(hooks.beforeAuthenticate(signIn))
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
import { Effect, Layer } from "effect";
import * as Option from "effect/Option";
import {
  ClientIP,
  DEFAULT_IPV6_RATE_LIMIT_PREFIX,
  isIpv6RateLimitPrefix,
  rateLimitAddressKey,
} from "../ClientIP.ts";
import type { SignUpInput } from "../email/EmailPassword.ts";
import { type AuthenticateAttempt, Hooks, makePlugin } from "../Hooks.ts";
import { recordClientAddressKeyed } from "../HooksClientAddress.ts";
import { RateLimitError, RateLimiterConfigError } from "../Errors.ts";
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
  /**
   * IP-keyed rate limit for first-factor authentication attempts, every
   * method sharing one bucket. Default: {@link RateLimitPresets.login}.
   */
  readonly signIn?: RateLimitConfig;
  /**
   * IP-keyed rate limit for second-factor redemptions. Default:
   * {@link RateLimitPresets.totpVerification}.
   */
  readonly secondFactor?: RateLimitConfig | undefined;
  /** IP-keyed rate limit for sign-up. Default: {@link RateLimitPresets.registration}. */
  readonly signUp?: RateLimitConfig;
  /** IP-keyed rate limit for password-reset requests. Default: {@link RateLimitPresets.passwordReset}. */
  readonly passwordResetRequest?: RateLimitConfig;
  /**
   * How many leading bits of an IPv6 address make one client: every address
   * in that prefix draws on one budget. An integer from 1 to 128; `128` keys
   * each address on its own. IPv4 addresses are keyed as they are. Default:
   * `64` ({@link DEFAULT_IPV6_RATE_LIMIT_PREFIX}). Any other value makes the
   * layer build die with `RateLimiterConfigError`.
   */
  readonly ipv6PrefixLength?: number | undefined;
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
      const ipv6PrefixLength = config?.ipv6PrefixLength ?? DEFAULT_IPV6_RATE_LIMIT_PREFIX;
      if (!isIpv6RateLimitPrefix(ipv6PrefixLength)) {
        return yield* Effect.die(
          new RateLimiterConfigError({
            message: `IPRateLimitPlugin: ipv6PrefixLength must be an integer from 1 to 128, got ${String(ipv6PrefixLength)}`,
          }),
        );
      }

      const check = (operation: string, limitConfig: RateLimitConfig) =>
        Effect.gen(function* () {
          const ipOpt = yield* Effect.serviceOption(ClientIP);
          const ip = Option.isSome(ipOpt) ? ipOpt.value.ip : undefined;
          // A request with no resolvable address cannot be keyed, and with no
          // ClientIP service there is no address to resolve. Refuse it rather than
          // skip the limit or count it under a bucket other callers share.
          if (ip === undefined) {
            return yield* new RateLimitError({
              message: Option.isNone(ipOpt)
                ? "No ClientIP service in scope; this request cannot be rate limited"
                : "Client address unavailable; this request cannot be rate limited",
              key: `ip:${operation}`,
            });
          }
          const key = `ip:${operation}:${rateLimitAddressKey(ip, ipv6PrefixLength)}`;
          return yield* rateLimiter
            .consumeToken(key, limitConfig)
            .pipe(Effect.provideService(RateLimitStore, store));
        });

      return {
        beforeAuthenticate: (attempt: AuthenticateAttempt) =>
          (attempt.method === "second-factor"
            ? check("second-factor", config?.secondFactor ?? RateLimitPresets.totpVerification)
            : check("signin", config?.signIn ?? RateLimitPresets.login)
          ).pipe(Effect.as(attempt)),

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
 * Hooks `beforeAuthenticate`, `beforeSignUp`, and `beforeRequestPasswordReset`.
 * Keys are `ip:<operation>:<address>` so they are separate from the per-email
 * keys used by {@link RateLimitPlugin}. An IPv6 client is keyed on its /64
 * (`ipv6PrefixLength`), so one customer's block cannot mint fresh budgets.
 *
 * Requires `RateLimiter` and `RateLimitStore` in the Layer graph.
 *
 * A request with no client address is refused with a {@link RateLimitError}:
 * both when the {@link ClientIP} service is absent and when it carries no
 * address. Under `Http.make`, give the handler a `trustedProxy`, or `make`
 * throws `ClientAddressConfigError`.
 * The module documentation has the details.
 */
export const IPRateLimitPlugin = (config?: IPRateLimitPluginConfig) =>
  Layer.effect(
    Hooks,
    // Record the plugin on the Hooks it builds, so Http.make can refuse it at
    // build when the handler has no client-address source.
    Effect.gen(function* () {
      return recordClientAddressKeyed(yield* Hooks, "IPRateLimitPlugin");
    }),
  ).pipe(Layer.provide(ipRateLimitHooks(config)));
