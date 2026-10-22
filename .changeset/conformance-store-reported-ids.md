---
"@thomasfosterau/effect-auth": patch
---

`identifierStoreConformance` works from each identifier as the store reports it rather than the record it handed in. A store that keeps one email on the user's own row reports the user's id as the identifier's id, which the contract allows; the suite used to fail such a store's `setVerified`, `delete` and `replace` cases. It now also checks that `getByValue` reports the same id `create` returned.
