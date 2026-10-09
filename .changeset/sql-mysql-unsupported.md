---
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-alchemy": patch
---

Document the supported dialects. `@thomasfosterau/effect-auth-sql` supports SQLite, Cloudflare D1 and PostgreSQL. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). `@thomasfosterau/effect-auth-alchemy`'s module docs say the sql DDL is valid on SQLite, D1 and PostgreSQL, not MySQL.
