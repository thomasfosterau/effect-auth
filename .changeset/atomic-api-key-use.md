---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Spend API key uses atomically (#595). **Breaking for bring-your-own `ApiKeyStore`s:** the contract gains a required `recordUse(id, use)`, which spends one use in one atomic step and returns the stored record, or `null` when the key is unknown, disabled, expired, exhausted, or its refill baseline moved. It changes only `remaining`, `lastRefillAt`, `lastUsedAt` and `updatedAt`. `ApiKeyService.verify` and `verifyWithRateLimit` now spend through it instead of writing the whole record back from their read. Before this, a verify in flight undid an owner's concurrent disable, permission change or new expiry, and concurrent verifies of a key with one use left all passed. When the spend loses a race, the service re-reads the key and re-checks it.

`./sql` implements `recordUse` as one `UPDATE … WHERE … RETURNING`, and the memory stores through the new `applyApiKeyUse`, which is the contract as a pure function. `apiKeyStoreConformance` gains cases for `recordUse`, a concurrent one included.

effect-auth-drizzle's `ApiKeyStore` implements `recordUse` as one guarded `UPDATE` with `remaining` computed in SQL, then reads the row back when the driver's affected-row count shows a match, so it needs no `RETURNING` on MySQL. On MySQL that count must be the matched rows, which is mysql2's default.
