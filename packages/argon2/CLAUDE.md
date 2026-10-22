# @thomasfosterau/effect-auth-argon2

Argon2id `PasswordHasher` on WebAssembly (`hash-wasm`), with OWASP cost profiles; runs unchanged on Node, Bun, Deno, Cloudflare Workers and browsers.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Implements the core's `Password.PasswordHasher` seam. Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` and `hash-wasm` (pure WASM, bundled because it is the implementation, not a database or vendor SDK the consumer supplies).

## Invariants

- **Workers-safe**: no native module, no post-install step and no `node:` import anywhere in `src/` (only comments mention `node:`). Randomness for salts is `globalThis.crypto.getRandomValues`; the digest comparison is the module's own constant-time loop, because `node:crypto.timingSafeEqual` is not portable. Don't replace either with a `node:` API.
- **`defaultProfile` stays Workers-sized** (OWASP low-memory: `m=19456` KiB, `t=2`, `p=1`); a Workers isolate has 128 MiB. `serverProfile` (`m=65536`, `t=3`) is opt-in.
- **Output is a standard PHC string** (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`), so hashes interoperate with any Argon2 implementation and `Password.multiAlgorithmVerifier` routes on the algorithm segment (`algorithm: "argon2id"`).
- **`verify` reads every parameter from the stored hash** (variant, `m`/`t`/`p`, salt, digest length), never from the configured options, so raising costs never locks anyone out.
- **An unverifiable hash fails, never returns `false`**: a malformed PHC string, an unknown variant or Argon2 `v=0x10` is a `HashingError`. A wrong password is `false`.
- **Input guards before the KDF**: empty password or hash is a `HashingError`; a password over `MAX_PASSWORD_BYTES` (1024 UTF-8 bytes) is refused by `hash` and reads as `false` in `verify` (anti-DoS).
- Spans keep the core hashers' names (`effect-auth.password.hash` / `.verify`, attribute `algorithm`).

## Terms

- **Cost profile** — an `Argon2Profile` (`memoryCost` KiB, `timeCost`, `parallelism`); `resolveOptions` fills a partial `Argon2Options` from `defaultProfile`.
