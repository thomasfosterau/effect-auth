---
"@thomasfosterau/effect-auth": minor
---

The in-memory stores and `EntitySlice` use Effect collections instead of native `Map`s and `Set`s (#443).

Migration (these are test and single-process helpers):

- Every `memory*Store` that took a pre-seeded `Map` now takes a `MutableHashMap` from `effect`: `memorySessionStore`, `memoryMultiFactorStore`, `memoryTrustedDeviceStore`, `memoryOtpSecondFactorStore`, `memoryOAuthAccountStore`, the four `memoryOidc*Store`s, `memoryIdentifierStore`, `memoryAccountLockoutStore`, `memoryOrganizationDomainStore`, `memorySamlReplayStore`, `memoryScimConnectionStore` and `memoryPolicyStore` (its `policies`, `templates` and `links`). `MemoryUserTable`'s `users` and `passwordHashes` are `MutableHashMap`s too. Build one with `MutableHashMap.empty()` or `MutableHashMap.fromIterable(entries)` and read it with `MutableHashMap.get` (an `Option`), `MutableHashMap.values` and `MutableHashMap.size`.
- `EntitySlice.entities` is a `HashMap<string, Entity>`. Build slices with `Entity.slice` and read them with `Entity.getEntity`, as before; code that read `entities` directly uses `HashMap.get`.
- `./client/testing`'s `makeServerFixture` returns `sessions`, `usersById`, `identifierRecords` and `domainRecords` as `MutableHashMap`s and `publishedDnsDomains` as a `MutableHashSet` (`MutableHashSet.add(fixture.publishedDnsDomains, domain)`).
