---
"@thomasfosterau/effect-auth": minor
---

Purge spent rate-limit entries from the `KeyValueStore` backend (#709). `purgeExpiredKV` now also deletes the `RateLimitStoreKV` entries (and so `layerKV`'s and `Testing.memoryStores`') whose window and block have both passed, and `PurgeExpiredKVResult` gains `rateLimits`, the count it deleted. An entry inside its window or still blocked stays. `KeyValueStore` has no per-entry TTL, so the purge, scheduled by the host, is what keeps these entries bounded.
