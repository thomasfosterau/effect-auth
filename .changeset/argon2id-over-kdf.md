---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-argon2": patch
---

Add an Argon2id password hasher to the core over Effect's `Kdf` service: `Password.argon2idHasherLayer(options?)` (a `Layer<PasswordHasher, never, Kdf>`) and `Password.argon2idHasher(kdf, random, options?)`, with `argon2DefaultProfile`, `argon2ServerProfile` and `argon2DefaultVerifyLimits`. Provide `NodeCrypto.layerKdf` from `@effect/platform-node` or `@effect/platform-bun` (Node.js 24.7+ or Bun 1.4+). Hashes are the same `$argon2id$v=19$…` PHC strings effect-auth-argon2 writes, so stored hashes verify unchanged. effect-auth-argon2 stays the Argon2id for Cloudflare Workers and other runtimes whose `Kdf` has no Argon2id; its docs now say so.
