---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
---

Purge expired rate-limit rows (#686). `./sql`'s `purgeExpired` (and so the Alchemy packages' `purgeExpired`) now also deletes the `auth_rate_limits` rows whose window and block have both passed, in one `DELETE`, and `PurgeExpiredResult` gains `rateLimits`, the count it deleted. The drizzle package adds `RateLimitStore.purgeExpired(tables)`, one `DELETE` of the same rows from its rate-limit table. A row inside its window or still blocked stays.
