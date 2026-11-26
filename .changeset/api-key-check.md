---
"@thomasfosterau/effect-auth": minor
---

Add `ApiKeyService.check`, a verify that spends nothing. It runs the same lookup and checks as `verify` (the owner exists and is neither banned nor SCIM-deactivated, the key is enabled, unexpired, has a use left and carries the required permissions) and answers the same result, but leaves `remaining`, `lastRefillAt` and `lastUsedAt` alone and takes no rate-limit token. Use it to re-validate a key on every request of a long-lived connection without using up its quota. **Breaking only for a hand-written `ApiKeyService` implementation**, which must now provide `check`.
