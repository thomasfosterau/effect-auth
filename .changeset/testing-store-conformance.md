---
"@thomasfosterau/effect-auth": minor
---

`@thomasfosterau/effect-auth/testing` adds store-contract conformance suites for bring-your-own stores: `sessionStoreConformance`, `userStoreConformance`, `identifierStoreConformance` and `apiKeyStoreConformance`. Each suite is a list of cases, and each case is an `Effect` that fails with `ConformanceError` when the store departs from its contract. The suites import no test runner; register the cases with your own (see `docs/guides/byo-stores.md` §7).
