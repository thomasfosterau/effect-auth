---
"@thomasfosterau/effect-auth-sql": patch
---

Fix `rateLimit.increment` and `accountLockout.registerAttempt` on PostgreSQL. Their `ON CONFLICT … DO UPDATE SET` right-hand sides now qualify the target table's columns, which PostgreSQL rejected as ambiguous (`column reference "reset_at" is ambiguous`). SQLite behaviour is unchanged. The store suite now also runs over PostgreSQL (PGlite), and the README, module docs and TSDoc list PostgreSQL as a supported dialect.
