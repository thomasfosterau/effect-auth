/**
 * Rate limiting types for effect-auth
 */

import { Clock, Context, Duration, Effect, Layer, Predicate } from "effect";
import { RateLimitError, type AuthError } from "./Errors.ts";
import * as Obs from "./Observability.ts";

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  readonly maxRequests: number;
  readonly windowMs: number;
  readonly blockDurationMs?: number;
}

/**
 * Rate limit entry
 */
export interface RateLimitEntry {
  readonly key: string;
  readonly count: number;
  readonly resetAt: number;
  readonly blockedUntil?: number;
}

/**
 * Rate limiting implementation
 *
 * Provides fixed-window counter-based rate limiting with configurable
 * block durations.
 *
 * @module rate-limit
 */

/**
 * Storage interface for rate limiting
 *
 * Rate limit store context tag
 */
export class RateLimitStore extends Context.Service<
  RateLimitStore,
  {
    readonly get: (key: string) => Effect.Effect<RateLimitEntry | null, AuthError>;
    readonly set: (
      key: string,
      entry: RateLimitEntry,
      ttl: number,
    ) => Effect.Effect<void, AuthError>;
    /**
     * Count one request against `key` and return the new count, in one atomic
     * step: when `key` has no entry, or its window has expired (`resetAt` is
     * not after now), start a new window with a count of 1 and a `resetAt`
     * `ttl` seconds from now; otherwise add 1 to the open window's count.
     * `RateLimiter.consumeToken` decides from the count this returns, so an
     * increment that two concurrent callers can interleave lets them
     * overshoot the limit.
     */
    readonly increment: (key: string, ttl: number) => Effect.Effect<number, AuthError>;
    readonly delete: (key: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/RateLimitStore") {}

/**
 * Rate limiter service
 */
export class RateLimiter extends Context.Service<
  RateLimiter,
  {
    readonly checkLimit: (
      key: string,
      config: RateLimitConfig,
    ) => Effect.Effect<boolean, RateLimitError | AuthError>;

    readonly consumeToken: (
      key: string,
      config: RateLimitConfig,
    ) => Effect.Effect<void, RateLimitError | AuthError>;

    readonly resetLimit: (key: string) => Effect.Effect<void, AuthError>;

    readonly getRemainingTokens: (
      key: string,
      config: RateLimitConfig,
    ) => Effect.Effect<number, AuthError>;
  }
>()("@effect-auth/RateLimiter") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = () => Layer.effect(RateLimiter, make());
}

/**
 * Record a rate-limit hit, labelled by the key's prefix, when `self` fails
 * with `RateLimitError`.
 */
const recordRateLimitHit =
  (key: string) =>
  <A, E, R>(self: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
    self.pipe(
      Effect.tapError((e) =>
        Predicate.isTagged(e, "RateLimitError")
          ? Obs.recordRateLimitHit(key.split(":")[0] ?? key)
          : Effect.void,
      ),
    );

/** The time from `now` until `until` (both epoch milliseconds), never negative. */
const retryAfter = (until: number, now: number): Duration.Duration =>
  Duration.millis(Math.max(0, until - now));

/**
 * Create a rate limiter service
 */
export const make = (): Effect.Effect<typeof RateLimiter.Service, never, RateLimitStore> =>
  Effect.gen(function* () {
    const store = yield* RateLimitStore;

    return {
      checkLimit: Effect.fn("RateLimiter.checkLimit")((key: string, config: RateLimitConfig) =>
        Effect.gen(function* () {
          const entry = yield* store.get(key);

          const now = yield* Clock.currentTimeMillis;

          // Check if blocked
          if (entry?.blockedUntil && now < entry.blockedUntil) {
            return yield* new RateLimitError({
              message: `Rate limit exceeded for ${key}`,
              key,
              retryAfter: retryAfter(entry.blockedUntil, now),
            });
          }

          // Check if window expired
          if (!entry || now >= entry.resetAt) {
            // Window expired or no entry, allow request
            return true;
          }

          // Check if limit exceeded
          if (entry.count >= config.maxRequests) {
            // Block if configured
            if (config.blockDurationMs) {
              const blockedEntry: RateLimitEntry = {
                ...entry,
                blockedUntil: now + config.blockDurationMs,
              };
              yield* store.set(key, blockedEntry, Math.ceil(config.blockDurationMs / 1000));
            }

            return yield* new RateLimitError({
              message: `Rate limit exceeded for ${key}`,
              key,
              retryAfter: retryAfter(entry.resetAt, now),
            });
          }

          return true;
        }).pipe(recordRateLimitHit(key)),
      ),

      consumeToken: Effect.fn("RateLimiter.consumeToken")((key: string, config: RateLimitConfig) =>
        Effect.gen(function* () {
          const now = yield* Clock.currentTimeMillis;

          // A block outlives the window it was set in, so it is checked
          // before the window is.
          const entry = yield* store.get(key);
          if (entry?.blockedUntil && now < entry.blockedUntil) {
            return yield* new RateLimitError({
              message: `Rate limit exceeded for ${key}`,
              key,
              retryAfter: retryAfter(entry.blockedUntil, now),
            });
          }

          // Count first, then decide from the count the store returns: the
          // increment is the one step a concurrent request cannot interleave
          // with (#455). The store starts a new window when there is none or
          // the current one has expired.
          const count = yield* store.increment(key, Math.ceil(config.windowMs / 1000));
          if (count <= config.maxRequests) return;

          const current = yield* store.get(key);
          const resetAt = current?.resetAt ?? now + config.windowMs;

          // Apply block if configured
          if (config.blockDurationMs) {
            const blockedEntry: RateLimitEntry = {
              key,
              count,
              resetAt,
              blockedUntil: now + config.blockDurationMs,
            };
            yield* store.set(key, blockedEntry, Math.ceil(config.blockDurationMs / 1000));
          }

          return yield* new RateLimitError({
            message: `Rate limit exceeded for ${key}`,
            key,
            retryAfter: retryAfter(resetAt, now),
          });
        }).pipe(recordRateLimitHit(key)),
      ),

      resetLimit: Effect.fn("RateLimiter.resetLimit")(function* (key: string) {
        yield* store.delete(key);
      }),

      getRemainingTokens: Effect.fn("RateLimiter.getRemainingTokens")(function* (
        key: string,
        config: RateLimitConfig,
      ) {
        const entry = yield* store.get(key);

        if (!entry || (yield* Clock.currentTimeMillis) >= entry.resetAt) {
          return config.maxRequests;
        }

        return Math.max(0, config.maxRequests - entry.count);
      }),
    };
  });

/**
 * Common rate limit configurations
 */
export const RateLimitPresets = {
  /**
   * Login attempts: 5 per 15 minutes
   */
  login: {
    maxRequests: 5,
    windowMs: 15 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  } satisfies RateLimitConfig,

  /**
   * Password reset: 3 per hour
   */
  passwordReset: {
    maxRequests: 3,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 2 * 60 * 60 * 1000,
  } satisfies RateLimitConfig,

  /**
   * Email verification: 3 per 10 minutes
   */
  emailVerification: {
    maxRequests: 3,
    windowMs: 10 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  } satisfies RateLimitConfig,

  /**
   * Registration: 3 per hour per IP
   */
  registration: {
    maxRequests: 3,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 24 * 60 * 60 * 1000,
  } satisfies RateLimitConfig,

  /**
   * OAuth: 10 per 5 minutes
   */
  oauth: {
    maxRequests: 10,
    windowMs: 5 * 60 * 1000,
    blockDurationMs: 15 * 60 * 1000,
  } satisfies RateLimitConfig,

  /**
   * TOTP verification: 5 per 5 minutes
   */
  totpVerification: {
    maxRequests: 5,
    windowMs: 5 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  } satisfies RateLimitConfig,
} as const;
