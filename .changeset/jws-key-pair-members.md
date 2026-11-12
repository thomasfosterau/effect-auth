---
"@thomasfosterau/effect-auth": patch
---

`generateJwsKeyPair` now throws an `AuthError` when the exported public JWK lacks a member its key needs (`kty`, `crv`, `x`, and `y` for ES256), rather than return a key no verifier can use; `JwtService` reports it as the `JwtError` it raises for any key-generation failure (#748).
