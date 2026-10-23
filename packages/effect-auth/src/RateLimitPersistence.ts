/**
 * A {@link RateLimiter} implementation backed by
 * `effect/persistence`'s `RateLimiter`, so consumers keep the existing
 * `consumeToken`/`checkLimit` facade but gain the library's tested fixed-window
 * algorithm and pluggable storage backends (in-memory or Redis for
 * multi-instance deployments).
 *
 * Usage (in-memory):
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Result } from "effect"
 * import { RateLimiter as PersistenceRateLimiter } from "effect/persistence"
 * import { RateLimiter, rateLimiterPersistenceLayer } from "@thomasfosterau/effect-auth"
 *
 * const RateLimiterLive = rateLimiterPersistenceLayer.pipe(
 *   Layer.provide(PersistenceRateLimiter.layer),
 *   Layer.provide(PersistenceRateLimiter.layerStoreMemory),
 * )
 *
 * // The facade keeps the RateLimiter contract: two attempts pass, the third is refused.
 * const limit = { maxRequests: 2, windowMs: 60_000 }
 *
 * const program = Effect.gen(function* () {
 *   const limiter = yield* RateLimiter
 *   yield* limiter.consumeToken("login:ada", limit)
 *   yield* limiter.consumeToken("login:ada", limit)
 *   const refused = yield* Effect.result(limiter.consumeToken("login:ada", limit))
 *   assert.ok(Result.isFailure(refused))
 * }).pipe(Effect.provide(RateLimiterLive))
 *
 * await Effect.runPromise(program)
 * ```
 *
 * Redis (multi-instance; atomic increments avoid the read-modify-write race of
 * the KV-backed stores):
 *
 * ```ts
 * import { Layer } from "effect"
 * import { RateLimiter as PersistenceRateLimiter, Redis } from "effect/persistence"
 * import { rateLimiterPersistenceLayer } from "@thomasfosterau/effect-auth"
 *
 * // The app's Redis client layer (for example, a node-redis adapter) is supplied
 * // by the app. Building this layer connects to Redis, so it is composed here and
 * // not run.
 * export const makeRateLimiterRedis = (redisLayer: Layer.Layer<Redis.Redis>) =>
 *   rateLimiterPersistenceLayer.pipe(
 *     Layer.provide(PersistenceRateLimiter.layer),
 *     Layer.provide(PersistenceRateLimiter.layerStoreRedis()),
 *     Layer.provide(redisLayer),
 *   )
 * ```
 *
 * @module rate-limit-persistence
 */
import { Duration, Effect, Layer, Predicate } from "effect";
import { RateLimiter as PersistenceRateLimiter } from "effect/persistence";
import { AuthError, RateLimitError } from "./Errors.ts";
import { RateLimiter, type RateLimitConfig } from "./RateLimit.ts";

/** Map the persistence limiter's error onto effect-auth's error channel. */
const toError = (error: PersistenceRateLimiter.RateLimiterError): RateLimitError | AuthError => {
  const reason = error.reason;
  if (Predicate.isTagged(reason, "RateLimitExceeded")) {
    return new RateLimitError({
      message: "Rate limit exceeded",
      key: reason.key,
      retryAfter: reason.retryAfter,
    });
  }
  return new AuthError({ message: reason.message });
};

const consumeOptions = (key: string, config: RateLimitConfig) =>
  ({
    key,
    limit: config.maxRequests,
    window: Duration.millis(config.windowMs),
    algorithm: "fixed-window",
  }) as const;

/**
 * Build the facade over the persistence limiter. The persistence `RateLimiter`
 * service is captured here so the returned methods keep the interface's
 * (`RateLimitStoreTag`) requirement satisfiable without touching the legacy
 * store.
 */
export const rateLimiterPersistence: Effect.Effect<
  typeof RateLimiter.Service,
  never,
  PersistenceRateLimiter.RateLimiter
> = PersistenceRateLimiter.RateLimiter.useSync((limiter) => {
  const impl: typeof RateLimiter.Service = {
    consumeToken: (key, config) =>
      limiter
        .consume({ ...consumeOptions(key, config), onExceeded: "fail" })
        .pipe(Effect.mapError(toError), Effect.asVoid),

    checkLimit: (key, config) =>
      limiter.consume({ ...consumeOptions(key, config), tokens: 0 }).pipe(
        Effect.map((result) => result.remaining > 0),
        Effect.mapError(toError),
      ),

    // The persistence backend exposes no explicit reset; fixed-window entries
    // expire at the end of their window, so an early reset is a no-op here.
    // (The account-lockout plugin manages its own reset-on-success via its own
    // store, so this limitation does not affect that flow.)
    resetLimit: () => Effect.void,

    getRemainingTokens: (key, config) =>
      limiter.consume({ ...consumeOptions(key, config), tokens: 0 }).pipe(
        Effect.map((result) => result.remaining),
        Effect.orElseSucceed(() => 0),
      ),
  };

  return impl;
});

/**
 * A `Layer<RateLimiterTag, never, PersistenceRateLimiter.RateLimiter>`. Provide
 * `PersistenceRateLimiter.layer` plus a store (`layerStoreMemory` or a Redis
 * store) to obtain a runnable limiter (see the module docs for examples).
 */
export const rateLimiterPersistenceLayer = Layer.effect(RateLimiter, rateLimiterPersistence);
