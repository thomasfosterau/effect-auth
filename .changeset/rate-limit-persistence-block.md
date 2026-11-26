---
"@thomasfosterau/effect-auth": patch
---

`rateLimiterPersistenceLayer` now applies a rule's `blockDurationMs`: the first refusal opens a block under `<key>:blocked` in the same `effect/persistence` store, and the key is refused (with `retryAfter` the time left on the block) until it ends, even after its window resets. Before, every documented block, the `Http.make` defaults and `RateLimitPresets` included, was silently dropped and callers were only limited to N per window. Every `RateLimitError` a limiter raises now carries the fixed message `RATE_LIMIT_EXCEEDED_MESSAGE` ("Rate limit exceeded"), so a `429` no longer names the internal key, the client address or a device user code; the key stays on the error's `key`. The README's rate-limit example now counts.
