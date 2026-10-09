---
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-alchemy": patch
---

Document the supported dialects. `@thomasfosterau/effect-auth-sql` supports SQLite and Cloudflare D1 today. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). PostgreSQL is pending #348, because `rateLimit.increment` and `accountLockout.registerAttempt` fail there on ambiguous column references. `@thomasfosterau/effect-auth-alchemy`'s module docs no longer claim that the sql DDL is valid on MySQL.
