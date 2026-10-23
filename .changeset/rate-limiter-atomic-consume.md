---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": patch
---

`RateLimiter.consumeToken` now decides from the count `RateLimitStore.increment` returns instead of a count it read before incrementing, so concurrent requests at the limit no longer all pass, and concurrent first requests in a window no longer overwrite each other's count (#455). It also checks a block before the window, so a `blockDurationMs` longer than `windowMs` is no longer lifted when the window expires.

**Breaking: the `RateLimitStore.increment` contract is now stated and relied on.** It must start a new window (count 1, `resetAt` `ttl` seconds away) when the key has no entry or its window has expired, and return the new count atomically. effect-auth-sql's store and the `KeyValueStore`-backed store already do. A custom store whose `increment` only bumps an existing entry (relying on `consumeToken` to `set` a new window) must be updated, or `consumeToken` never refuses. The client's in-memory testing fixture is updated to match.

**Breaking: `RateLimitError.retryAfter` is now an `effect/Duration`** instead of a bare number, which was seconds from `RateLimiter.make()` but milliseconds from `rateLimiterPersistenceLayer`. Both now report the same `Duration`. Read it with `Duration.toMillis` / `Duration.toSeconds`. The HTTP IP rate limit (`ipRateLimit`) sends it as a `Retry-After` header in whole seconds, rounded up, and keeps the 429 body's `retryAfter` as the same whole seconds.
