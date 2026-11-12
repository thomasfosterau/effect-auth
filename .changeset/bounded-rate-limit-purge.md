---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Bounded purges for a cron with a CPU budget (#729). `@thomasfosterau/effect-auth/sql` adds `purgeExpiredWith({ limit })`: `purgeExpired` with each table's `DELETE` capped at `limit` rows (magic links, email OTPs and rate-limit rows alike), reporting the counts so a caller can loop until they are `0`. `RateLimitStore.purgeExpired(tables, { limit })` in `@thomasfosterau/effect-auth-drizzle` caps its `DELETE` the same way on PostgreSQL, SQLite and MySQL (through a derived table, which MySQL accepts inside `IN`) and still returns nothing. Omitting `limit` keeps the unbounded purge; a `limit` that is not a positive integer fails with `AuthError`.
