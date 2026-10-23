---
"@thomasfosterau/effect-auth": minor
---

**Breaking: `AccountLockedError.retryAfter` and `ResendTooSoonError.retryAfter` are now an `effect/Duration`** instead of a bare number of milliseconds, matching `RateLimitError.retryAfter`. Read them with `Duration.toMillis` / `Duration.toSeconds`. `AccountLockoutPlugin` now also sets `retryAfter` to the time left on the lock, where before it left it unset.
