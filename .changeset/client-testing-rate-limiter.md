---
"@thomasfosterau/effect-auth-client": patch
---

The `./testing` in-memory server's feature set (`features: true`) includes an in-memory `RateLimiter`, because the core requires one for device authorization (`Http.make` throws `RateLimiterConfigError` without it, #389). Device approve and deny on the fixture are therefore rate limited as in production: 5 attempts per user code per 15 minutes, then `429`. No API change.
