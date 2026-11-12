---
"@thomasfosterau/effect-auth-drizzle": minor
---

Add Drizzle implementations of `EmailPasswordStore` (with `PasswordResetUserStore`), `ApiKeyStore`, `RateLimitStore`, and the email-verification and password-reset token stores (#675), so sign-up, sign-in, password reset, email verification, API keys and rate limiting run on Drizzle alone.

- New store namespaces: `EmailPasswordStore` (`layer`, `passwordResetUserLayer`, `make`), `ApiKeyStore` (`layer`, `make`), `RateLimitStore` (`layer`, `make`) and `TokenStore` (`emailVerificationLayer`, `passwordResetLayer`, `layer` for both, `makeEmailVerificationStore`, `makePasswordResetStore`). Each takes a dialect's `tables` and defaults to `Pg.tables`; `EmailPasswordStore` also takes a `defineSchema` mapping.
- Three new default tables in every dialect, built by `defineTables` and covered by `migrationStatements` / `migrationSql`: `effect_auth_api_keys` (unique on `key_hash`), `effect_auth_rate_limits` and `effect_auth_tokens` (one table for both token kinds, by `purpose`). `Pg` / `Sqlite` / `MySql` export them as `apiKeysTable`, `rateLimitsTable` and `tokensTable`. `TableNames` gains `apiKeys`, `rateLimits` and `tokens`, and `Tables` the three tables; re-run `migrationSql()` (or drizzle-kit) to create them.
- `RateLimitStore.increment` is atomic per statement: it re-opens an expired window, then upserts the count (`ON CONFLICT ... RETURNING` on PostgreSQL and SQLite, `ON DUPLICATE KEY UPDATE` and a read-back on MySQL).
- `defineSchema`'s users entry takes an optional `passwordHash` column for `EmailPasswordStore`; `UserStore` still never selects it. `EmailPasswordStore.createUser` writes promoted attributes to their columns.
- `AuthDatabase`'s `insert().values()` now returns `DrizzleInsertValues`, which describes the two upsert spellings.
