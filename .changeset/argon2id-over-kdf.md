---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
"@thomasfosterau/effect-auth-alchemy-postgres": minor
---

Add an Argon2id password hasher to the core over `effect/crypto`'s `Password` service: `Password.argon2idHasherLayer(options?)` (a `Layer<PasswordHasher, never, Kdf>`) and `Password.argon2idHasher(passwords, options?)`, with `argon2DefaultProfile`, `argon2ServerProfile` and `argon2DefaultVerifyLimits`. Provide `NodeCrypto.layerKdf` from `@effect/platform-node` or `@effect/platform-bun` (Node.js 24.7+ or Bun 1.4+). Hashes are the same `$argon2id$v=19$…` PHC strings effect-auth-argon2 writes, so stored hashes verify unchanged; a stored hash over the verify ceiling is refused before the KDF runs.

**Breaking:** the core's `effect` peer is now `^4.1.5`, the release that added `effect/crypto`'s `Password` module. effect-auth-alchemy-cloudflare and effect-auth-alchemy-postgres raise their `effect` peer to `^4.1.5` with it.

effect-auth-argon2 stays the Argon2id for Cloudflare Workers and other runtimes whose `Kdf` has no Argon2id; its docs now say so.
