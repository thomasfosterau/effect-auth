---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": patch
---

`purgeExpiredKV` deletes the magic-link tokens and email OTP records whose `expiresAt` has passed from the `KeyValueStore`-backed stores (`MagicLinkStoreKV`, `EmailOtpStoreKV`, so `layerKV` and `Testing.memoryStores`) and reports how many it deleted from each; a purged magic link also leaves its address's index. A `KeyValueStore` cannot list its keys, so the purge also requires the new `KeyValueStoreKeys` service, whose `list(prefix)` the host implements over its backend (Workers KV `list({ prefix })`, Redis `SCAN`). `layerMemoryKeyValueStore` is an in-memory `KeyValueStore` with that listing over the same map, and `Testing.memoryStores` now runs on it and provides both services, so the purge runs against it. As with effect-auth-sql's `purgeExpired`, the host schedules it; no store deletes these records on its own (#420).

effect-auth-sql's `purgeExpired` now keeps a row whose `expires_at` equals the current time: the services still accept such a code or link, so deleting it changed an outcome.
