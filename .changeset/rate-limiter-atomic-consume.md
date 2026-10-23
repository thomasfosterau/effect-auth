---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": patch
---

`RateLimiter.consumeToken` now decides from the count `RateLimitStore.increment` returns instead of a count it read before incrementing, so concurrent requests at the limit no longer all pass, and concurrent first requests in a window no longer overwrite each other's count (#455). It also checks a block before the window, so a `blockDurationMs` longer than `windowMs` is no longer lifted when the window expires.

The `RateLimitStore.increment` contract is now stated and relied on: it must start a new window (count 1, `resetAt` `ttl` seconds away) when the key has no entry or its window has expired, and return the new count atomically. effect-auth-sql's store and the `KeyValueStore`-backed store already do; a custom store whose `increment` only bumps an existing entry (and relied on `consumeToken` calling `set` for a new window) must be updated, or `consumeToken` never refuses. The client's in-memory testing fixture is updated to match.
