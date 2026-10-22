---
"@thomasfosterau/effect-auth": patch
---

`IdentifierStoreKV.create` refuses a `(type, value)` another identifier already holds with `AuthError`, as the `IdentifierStore` contract requires and as `claimIdentifier` expects. It used to overwrite the lookup key, which moved the address to the new record. The check is a read before the write, so two concurrent creates can still both succeed on a `KeyValueStore`.
