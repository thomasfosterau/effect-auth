---
"@thomasfosterau/effect-auth": minor
---

Add `KeyValueStoreTake`, an optional atomic get-and-delete beside the `KeyValueStore` (Redis `GETDEL`, a Durable Object). When it is provided where the `*StoreKV` layers are built, every single-use `consume` (`OAuthStateStoreKV`, `EmailVerificationStoreKV`, `PasswordResetStoreKV`, `MagicLinkStoreKV`, `PendingMultiFactorStoreKV`) takes its record with one `take` call, so two instances sharing one backend can no longer both spend one OAuth state or token. Without it, `consume` keeps its per-process semaphore, and the docs now say those stores are single-instance only. `layerMemoryKeyValueStore`, and so `Testing.memoryStores`, provides one.
