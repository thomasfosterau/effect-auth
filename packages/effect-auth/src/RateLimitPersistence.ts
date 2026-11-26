/**
 * A {@link RateLimiter} over `effect/persistence`'s `RateLimiter`, in memory or
 * on Redis for several instances. A rule's `blockDurationMs` is a second fixed
 * window under `<key>:blocked`, and `resetLimit` is a no-op.
 *
 * @example In memory
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
 * @example On Redis, for several instances
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
import { Duration, Effect, Layer } from "effect";
import * as P from "effect/Predicate";
import { RateLimiter as PersistenceRateLimiter } from "effect/persistence";
import { AuthError, RateLimitError } from "./Errors.ts";
import { RATE_LIMIT_EXCEEDED_MESSAGE, RateLimiter, type RateLimitConfig } from "./RateLimit.ts";

/** Map the persistence limiter's error onto effect-auth's error channel. */
const toError = (error: PersistenceRateLimiter.RateLimiterError): RateLimitError | AuthError => {
  const reason = error.reason;
  if (P.isTagged(reason, "RateLimitExceeded")) {
    return new RateLimitError({
      message: RATE_LIMIT_EXCEEDED_MESSAGE,
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
 * A block is a second fixed window beside the key's: one admission of
 * `blockDurationMs`, opened when the key's window is exceeded and read with
 * a zero-token consume, so it lasts its own duration however the key's
 * window turns over.
 */
const blockOptions = (key: string, blockDurationMs: number) =>
  ({
    key: `${key}:blocked`,
    limit: 1,
    window: Duration.millis(blockDurationMs),
    algorithm: "fixed-window",
  }) as const;

/** The block duration a rule carries, or `undefined` when it sets none. */
const blockDuration = (config: RateLimitConfig): number | undefined =>
  config.blockDurationMs !== undefined && config.blockDurationMs > 0
    ? config.blockDurationMs
    : undefined;

const exceeded = (key: string, retryAfter: Duration.Duration): RateLimitError =>
  new RateLimitError({ message: RATE_LIMIT_EXCEEDED_MESSAGE, key, retryAfter });

/**
 * Build the facade over the persistence limiter. The persistence `RateLimiter`
 * service is captured here so the returned methods keep the interface's
 * (`RateLimitStoreTag`) requirement satisfiable without touching the legacy
 * store.
 *
 * A rule's `blockDurationMs` is applied: once a key exceeds its window it is
 * refused for the whole block, even after its window has reset.
 */
export const rateLimiterPersistence: Effect.Effect<
  typeof RateLimiter.Service,
  never,
  PersistenceRateLimiter.RateLimiter
> = PersistenceRateLimiter.RateLimiter.useSync((limiter) => {
  /** The time left on the key's block, or `undefined` when it is not blocked. */
  const blockedFor = (
    key: string,
    config: RateLimitConfig,
  ): Effect.Effect<Duration.Duration | undefined, AuthError | RateLimitError> => {
    const duration = blockDuration(config);
    if (duration === undefined) return Effect.undefined;
    return limiter.consume({ ...blockOptions(key, duration), tokens: 0 }).pipe(
      Effect.map((result) => (result.remaining <= 0 ? result.resetAfter : undefined)),
      Effect.mapError(toError),
    );
  };

  /** Open the key's block, when its rule sets one, and answer the refusal. */
  const refuse = (
    key: string,
    config: RateLimitConfig,
    retryAfter: Duration.Duration,
  ): Effect.Effect<never, AuthError | RateLimitError> => {
    const duration = blockDuration(config);
    if (duration === undefined) return Effect.fail(exceeded(key, retryAfter));
    return limiter.consume({ ...blockOptions(key, duration), onExceeded: "fail" }).pipe(
      Effect.mapError(toError),
      // A block already open stands; the refusal is the same either way.
      Effect.catchTag("RateLimitError", () => Effect.void),
      Effect.andThen(Effect.fail(exceeded(key, Duration.millis(duration)))),
    );
  };

  const impl: typeof RateLimiter.Service = {
    consumeToken: (key, config) =>
      Effect.gen(function* () {
        const blocked = yield* blockedFor(key, config);
        if (blocked !== undefined) return yield* exceeded(key, blocked);
        return yield* limiter.consume({ ...consumeOptions(key, config), onExceeded: "fail" }).pipe(
          Effect.mapError(toError),
          Effect.asVoid,
          Effect.catchTag("RateLimitError", (error) =>
            refuse(key, config, error.retryAfter ?? Duration.millis(config.windowMs)),
          ),
        );
      }),

    checkLimit: (key, config) =>
      Effect.gen(function* () {
        const blocked = yield* blockedFor(key, config);
        if (blocked !== undefined) return yield* exceeded(key, blocked);
        const result = yield* limiter
          .consume({ ...consumeOptions(key, config), tokens: 0 })
          .pipe(Effect.mapError(toError));
        return result.remaining > 0;
      }),

    // The persistence backend exposes no explicit reset: window and block
    // entries expire on their own, so an early reset is a no-op here. (The
    // account-lockout plugin keeps its own store and its own reset, so this
    // does not affect that flow.)
    resetLimit: () => Effect.void,

    getRemainingTokens: (key, config) =>
      Effect.gen(function* () {
        const blocked = yield* blockedFor(key, config);
        if (blocked !== undefined) return 0;
        const result = yield* limiter.consume({ ...consumeOptions(key, config), tokens: 0 });
        return result.remaining;
      }).pipe(Effect.orElseSucceed(() => 0)),
  };

  return impl;
});

/**
 * A `Layer<RateLimiterTag, never, PersistenceRateLimiter.RateLimiter>`. Provide
 * `PersistenceRateLimiter.layer` plus a store (`layerStoreMemory` or a Redis
 * store) to obtain a runnable limiter (the module examples show both).
 */
export const rateLimiterPersistenceLayer = Layer.effect(RateLimiter, rateLimiterPersistence);
