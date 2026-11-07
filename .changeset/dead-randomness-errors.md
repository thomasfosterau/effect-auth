---
"@thomasfosterau/effect-auth": minor
---

Drop the error paths for drawing randomness, which cannot fail: Effect 4.1's `SecureRandom` has a `never` error channel (#520). `generateVerificationToken` and `generateMagicLinkToken` now return `Effect<string>` (was `Effect<string, AuthError>`); a `catchTag("AuthError", …)` on either can go. `generateState` and `generateNonce` drop a no-op `Effect.orDie`. The services' own signatures are unchanged; they no longer produce an `AuthError` they could never raise.
