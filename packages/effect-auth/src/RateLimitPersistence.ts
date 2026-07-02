/**
 * A {@link RateLimiterTag} implementation backed by
 * `effect/unstable/persistence`'s `RateLimiter`, so consumers keep the existing
 * `consumeToken`/`checkLimit` facade but gain the library's tested fixed-window
 * algorithm and pluggable storage backends (in-memory or Redis for
 * multi-instance deployments).
 *
 * Usage (in-memory):
 *
 * ```ts
 * import { Layer } from "effect";
 * import { RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";
 * import { RateLimiterPersistenceLayer } from "effect-auth";
 *
 * const RateLimiterLive = RateLimiterPersistenceLayer.pipe(
 *   Layer.provide(PersistenceRateLimiter.layer),
 *   Layer.provide(PersistenceRateLimiter.layerStoreMemory),
 * );
 * ```
 *
 * Redis (multi-instance; atomic increments avoid the read-modify-write race of
 * the KV-backed stores):
 *
 * ```ts
 * import { Layer } from "effect";
 * import { Redis, RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";
 *
 * const RateLimiterRedis = RateLimiterPersistenceLayer.pipe(
 *   Layer.provide(PersistenceRateLimiter.layer),
 *   Layer.provide(
 *     Layer.effect(
 *       PersistenceRateLimiter.RateLimiterStore,
 *       PersistenceRateLimiter.makeStoreRedis(),
 *     ),
 *   ),
 *   Layer.provide(Redis.layer({ url: process.env.REDIS_URL! })),
 * );
 * ```
 *
 * @module rate-limit-persistence
 */
import { Duration, Effect, Layer } from "effect";
import { RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";
import { AuthError, RateLimitError } from "./Errors.js";
import { RateLimiterTag, type RateLimitConfig, type RateLimiter } from "./RateLimit.js";

/** Map the persistence limiter's error onto effect-auth's error channel. */
const toError = (error: PersistenceRateLimiter.RateLimiterError): RateLimitError | AuthError => {
  const reason = error.reason;
  if (reason._tag === "RateLimitExceeded") {
    return new RateLimitError({
      message: "Rate limit exceeded",
      key: reason.key,
      retryAfter: Duration.toMillis(reason.retryAfter),
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
export const makeRateLimiterPersistence: Effect.Effect<
  RateLimiter,
  never,
  PersistenceRateLimiter.RateLimiter
> = Effect.gen(function* () {
  const limiter = yield* PersistenceRateLimiter.RateLimiter;

  const impl: RateLimiter = {
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
export const RateLimiterPersistenceLayer = Layer.effect(RateLimiterTag, makeRateLimiterPersistence);
