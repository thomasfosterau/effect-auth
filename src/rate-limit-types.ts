/**
 * Rate limiting types for effect-auth
 */

import * as Effect from "effect/Effect"
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
  readonly get: (key: string) => Effect.Effect<RateLimitEntry | null, never>
  readonly set: (
    key: string,
    entry: RateLimitEntry,
    ttl: number
  ) => Effect.Effect<void, AuthError>
  readonly increment: (key: string, ttl: number) => Effect.Effect<number, AuthError>
  readonly delete: (key: string) => Effect.Effect<void, AuthError>
}

/**
 * Rate limiter service
 */
export interface RateLimiter {
  readonly checkLimit: (
    key: string,
    config: RateLimitConfig
  ) => Effect.Effect<boolean, RateLimitError>

  readonly consumeToken: (
    key: string,
    config: RateLimitConfig
  ) => Effect.Effect<void, RateLimitError>

  readonly resetLimit: (key: string) => Effect.Effect<void, AuthError>

  readonly getRemainingTokens: (
    key: string,
    config: RateLimitConfig
  ) => Effect.Effect<number, never>
}
