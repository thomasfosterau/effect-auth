/**
 * Rate limiting types for effect-auth
 */

import type { Effect as EffectType } from "effect/Effect"
import type { AuthError, RateLimitError } from "./errors.js"

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  readonly maxRequests: number
  readonly windowMs: number
  readonly blockDurationMs?: number
}

/**
 * Rate limit entry
 */
export interface RateLimitEntry {
  readonly key: string
  readonly count: number
  readonly resetAt: number
  readonly blockedUntil?: number
}

/**
 * Storage interface for rate limiting
 */
export interface RateLimitStore {
  readonly get: (key: string) => EffectType<RateLimitEntry | null, never>
  readonly set: (
    key: string,
    entry: RateLimitEntry,
    ttl: number
  ) => EffectType<void, AuthError>
  readonly increment: (key: string, ttl: number) => EffectType<number, AuthError>
  readonly delete: (key: string) => EffectType<void, AuthError>
}

/**
 * Rate limiter service
 */
export interface RateLimiter {
  readonly checkLimit: (
    key: string,
    config: RateLimitConfig
  ) => EffectType<boolean, RateLimitError>

  readonly consumeToken: (
    key: string,
    config: RateLimitConfig
  ) => EffectType<void, RateLimitError>

  readonly resetLimit: (key: string) => EffectType<void, AuthError>

  readonly getRemainingTokens: (
    key: string,
    config: RateLimitConfig
  ) => EffectType<number, never>
}
