---
"@thomasfosterau/effect-auth": minor
---

Add `Testing.sessionServiceLayer({ users, config? })`, `Testing.apiKeyServiceLayer({ keys?, config? })` and `Testing.memoryApiKeyStore` (also part of `Testing.memoryStores`) to `./testing`: `SessionService` and `ApiKeyService` over seeded in-memory stores, so tests need not assemble them by hand.
