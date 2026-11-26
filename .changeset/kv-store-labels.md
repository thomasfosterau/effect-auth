---
"@thomasfosterau/effect-auth": minor
---

Split the `KeyValueStore` stores by what a `KeyValueStore` can support. `layerKV` now holds only the token and state stores (`OAuthStateStoreKV`, `ChallengeStoreKV`, `EmailVerificationStoreKV`, `PasswordResetStoreKV`, `MagicLinkStoreKV`). The counter stores (`RateLimitStoreKV`, `EmailOtpStoreKV`, `PendingMultiFactorStoreKV`) and `IdentifierStoreKV` are documented as development and single-process only, since their read-modify-write counts and read-then-write uniqueness checks don't hold across processes. The new `layerKVSingleProcess` is `layerKV` plus the three counter stores, and `Testing.memoryStores` uses it.

**Breaking:** a composition that took `RateLimitStore`, `EmailOtpStore` or `PendingMultiFactorStore` from `layerKV` must now provide them: from `effect-auth/sql` in production, or with `layerKVSingleProcess` in development.

The module docs no longer suggest an eventually consistent backend such as Cloudflare KV for any of these stores. `ChallengeStoreKV.get` and `RateLimitStoreKV.get` now fail with `AuthError` when the backend fails, instead of dying. Every KV store's `AuthError` keeps the backend error as its `cause`. `MagicLinkStoreKV.getByEmail` returns the newest token for an address, not the oldest.
