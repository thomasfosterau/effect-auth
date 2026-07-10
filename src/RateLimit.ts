/**
 * Rate limiting types for effect-auth
 */

import { Context, Effect, Layer } from "effect";
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
 * Create a rate limiter service
 */
export const make = (): Effect.Effect<typeof RateLimiter.Service, never, RateLimitStore> =>
  Effect.gen(function* () {
    const store = yield* RateLimitStore;

    return {
      checkLimit: Effect.fn("RateLimiter.checkLimit")((key: string, config: RateLimitConfig) =>
        Effect.gen(function* () {
          const entry = yield* store.get(key);

          const now = Date.now();

          // Check if blocked
          if (entry?.blockedUntil && now < entry.blockedUntil) {
            return yield* Effect.fail(
              new RateLimitError({
                message: `Rate limit exceeded for ${key}`,
                key,
                retryAfter: Math.ceil((entry.blockedUntil - now) / 1000),
              }),
            );
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

            return yield* Effect.fail(
              new RateLimitError({
                message: `Rate limit exceeded for ${key}`,
                key,
                retryAfter: Math.ceil((entry.resetAt - now) / 1000),
              }),
            );
          }

          return true;
        }).pipe(
          Effect.tapError((e) =>
            e._tag === "RateLimitError"
              ? Obs.recordRateLimitHit(key.split(":")[0] ?? key)
              : Effect.void,
          ),
        ),
      ),

      consumeToken: Effect.fn("RateLimiter.consumeToken")((key: string, config: RateLimitConfig) =>
        Effect.gen(function* () {
          const now = Date.now();

          const entry = yield* store.get(key);

          // Check if window expired or no entry
          if (!entry || now >= entry.resetAt) {
            // Start new window
            const newEntry: RateLimitEntry = {
              key,
              count: 1,
              resetAt: now + config.windowMs,
            };
            yield* store.set(key, newEntry, Math.ceil(config.windowMs / 1000));
            return;
          }

          // Check if blocked
          if (entry.blockedUntil && now < entry.blockedUntil) {
            return yield* Effect.fail(
              new RateLimitError({
                message: `Rate limit exceeded for ${key}`,
                key,
                retryAfter: Math.ceil((entry.blockedUntil - now) / 1000),
              }),
            );
          }

          // Increment counter
          if (entry.count >= config.maxRequests) {
            // Apply block if configured
            if (config.blockDurationMs) {
              const blockedEntry: RateLimitEntry = {
                ...entry,
                blockedUntil: now + config.blockDurationMs,
              };
              yield* store.set(key, blockedEntry, Math.ceil(config.blockDurationMs / 1000));
            }

            return yield* Effect.fail(
              new RateLimitError({
                message: `Rate limit exceeded for ${key}`,
                key,
                retryAfter: Math.ceil((entry.resetAt - now) / 1000),
              }),
            );
          }

          // Increment
          yield* store.increment(key, Math.ceil(config.windowMs / 1000));
        }).pipe(
          Effect.tapError((e) =>
            e._tag === "RateLimitError"
              ? Obs.recordRateLimitHit(key.split(":")[0] ?? key)
              : Effect.void,
          ),
        ),
      ),

      resetLimit: Effect.fn("RateLimiter.resetLimit")(function* (key: string) {
        yield* store.delete(key);
      }),

      getRemainingTokens: Effect.fn("RateLimiter.getRemainingTokens")(function* (
        key: string,
        config: RateLimitConfig,
      ) {
        const entry = yield* store.get(key);

        if (!entry || Date.now() >= entry.resetAt) {
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
