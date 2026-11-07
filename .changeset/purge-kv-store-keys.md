---
"@thomasfosterau/effect-auth": minor
---

`purgeExpiredKV` no longer requires `KeyValueStoreKeys` (#521). Without one, it finds the records through the `KeyValueStore`'s own `keys`, new in Effect 4.1, so it runs over any store, `KeyValueStore.layerMemory` included. `KeyValueStoreKeys` stays as an optional prefix listing for backends that list one prefix more cheaply than they list every key, such as a large or shared Workers KV namespace, or Redis. When it is provided, the purge uses it.
