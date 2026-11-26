---
"@thomasfosterau/effect-auth-drizzle": minor
---

`ApiKeyStore`, `TokenStore` and `RateLimitStore` can run over an application's own tables. `defineApiKeyTable`, `defineTokenTable` and `defineRateLimitTable` map one table each, field by field and checked at the type level like `defineSchema`, and each store's `make` / `layer` (and `RateLimitStore.purgeExpired`) accepts the result in place of a dialect's `Tables`. An application can then give `user_id` its own key type and a foreign key into its `users` table, so deleting a user cascades to their API keys and pending tokens in the database.
