---
"@thomasfosterau/effect-auth-sql": patch
---

Document the supported dialects. `@thomasfosterau/effect-auth-sql` supports SQLite and Cloudflare D1 today. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). PostgreSQL is pending #348, because `rateLimit.increment` and `accountLockout.registerAttempt` fail there on ambiguous column references.
