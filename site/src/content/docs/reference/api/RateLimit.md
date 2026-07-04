---
title: "RateLimit"
description: "API reference for the RateLimit module."
---

## RateLimit overview

Rate limiting types for effect-auth

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [RateLimitConfig (interface)](#ratelimitconfig-interface)
  - [RateLimitEntry (interface)](#ratelimitentry-interface)
  - [RateLimitPresets](#ratelimitpresets)
  - [RateLimitStore (class)](#ratelimitstore-class)
  - [RateLimitStoreShape (interface)](#ratelimitstoreshape-interface)
  - [RateLimiter (class)](#ratelimiter-class)
  - [RateLimiterShape (interface)](#ratelimitershape-interface)
  - [makeRateLimiter](#makeratelimiter)

---

# utils

## RateLimitConfig (interface)

Rate limit configuration

**Signature**

```ts
export interface RateLimitConfig {
  readonly maxRequests: number;
  readonly windowMs: number;
  readonly blockDurationMs?: number;
}
```

## RateLimitEntry (interface)

Rate limit entry

**Signature**

```ts
export interface RateLimitEntry {
  readonly key: string;
  readonly count: number;
  readonly resetAt: number;
  readonly blockedUntil?: number;
}
```

## RateLimitPresets

Common rate limit configurations

**Signature**

```ts
export declare const RateLimitPresets: {
  readonly login: { maxRequests: number; windowMs: number; blockDurationMs: number };
  readonly passwordReset: { maxRequests: number; windowMs: number; blockDurationMs: number };
  readonly emailVerification: { maxRequests: number; windowMs: number; blockDurationMs: number };
  readonly registration: { maxRequests: number; windowMs: number; blockDurationMs: number };
  readonly oauth: { maxRequests: number; windowMs: number; blockDurationMs: number };
  readonly totpVerification: { maxRequests: number; windowMs: number; blockDurationMs: number };
};
```

## RateLimitStore (class)

Rate limit store context tag

**Signature**

```ts
export declare class RateLimitStore
```

## RateLimitStoreShape (interface)

Storage interface for rate limiting

**Signature**

```ts
export interface RateLimitStoreShape {
  readonly get: (key: string) => Effect.Effect<RateLimitEntry | null, never>;
  readonly set: (key: string, entry: RateLimitEntry, ttl: number) => Effect.Effect<void, AuthError>;
  readonly increment: (key: string, ttl: number) => Effect.Effect<number, AuthError>;
  readonly delete: (key: string) => Effect.Effect<void, AuthError>;
}
```

## RateLimiter (class)

**Signature**

```ts
export declare class RateLimiter
```

## RateLimiterShape (interface)

Rate limiter service

**Signature**

```ts
export interface RateLimiterShape {
  readonly checkLimit: (
    key: string,
    config: RateLimitConfig,
  ) => Effect.Effect<boolean, RateLimitError | AuthError, RateLimitStore>;

  readonly consumeToken: (
    key: string,
    config: RateLimitConfig,
  ) => Effect.Effect<void, RateLimitError | AuthError, RateLimitStore>;

  readonly resetLimit: (key: string) => Effect.Effect<void, AuthError, RateLimitStore>;

  readonly getRemainingTokens: (
    key: string,
    config: RateLimitConfig,
  ) => Effect.Effect<number, never, RateLimitStore>;
}
```

## makeRateLimiter

Create a rate limiter service

**Signature**

```ts
export declare const makeRateLimiter: () => Effect.Effect<RateLimiterShape, never>;
```
