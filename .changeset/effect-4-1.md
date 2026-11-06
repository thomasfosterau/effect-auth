---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
"@thomasfosterau/effect-auth-alchemy-postgres": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-resend": minor
"@thomasfosterau/effect-auth-sveltekit": minor
"@thomasfosterau/effect-auth-twilio": minor
---

Built for Effect `4.1` (#501, #499).

**Breaking peer ranges:** every package above now requires `effect ^4.1.0`, and the Alchemy packages require `alchemy` `2.0.0-beta.85` (effect-auth-alchemy-postgres also `@effect/sql-pg ^4.1.0`). Effect 4.1 removed the root `Crypto` module in favour of `effect/crypto`; alchemy beta.84 and earlier import that removed module, and beta.85 peers on `effect ^4.1.0` itself.

**Breaking — randomness and digests come from `effect/crypto`.** Services that yielded `Crypto.Crypto` now yield `SecureRandom.SecureRandom`, and the ones that hash (OAuth PKCE, the OIDC provider, WebAuthn, `HaveIBeenPwnedPlugin`) also yield `Digest.Digest`. Every `static layer` still provides both through `PlatformCrypto.layer`, so only code that builds a service from its raw `make` changes: provide `SecureRandom.layerWebCrypto` and `Digest.layerWebCrypto` (or your own implementations) where it provided `Crypto.Crypto`. The OTP primitives that took a `Crypto` instance (`generateBase32Secret` and friends) take a `SecureRandom` service instead. `OAuthProvider.generateAuthorizationUrl`, `generatePKCE` and `SsoService.signIn` add `Digest.Digest` to their requirements.

`layerMemoryKeyValueStore` implements `KeyValueStore.keys`, which Effect 4.1 added to the interface. effect-auth-alchemy-cloudflare's `D1Client` names its driver (`SqlClient.driver` is `"d1"`).
