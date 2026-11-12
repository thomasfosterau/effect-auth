# @thomasfosterau/effect-auth-argon2

Argon2id `PasswordHasher` on WebAssembly (the RustCrypto `argon2` crate, as built by `@thomasfosterau/argon2`), with OWASP cost profiles; runs unchanged on Node, Bun, Deno, Cloudflare Workers and browsers.

## Boundary

Archetype **Vendor adapter** (`.fallowrc.json` zone `vendor-adapters`, which may import `core` and `ladder`). Implements the core's `Password.PasswordHasher` seam. Peer: `effect` (`catalog:peers`). Depends on `@thomasfosterau/effect-auth` only: the Argon2 wasm of `@thomasfosterau/argon2` 0.1.1 is embedded in `src/WasmBinary.ts` (base64), because that package's exports take no cost parameters; its devDependency at the same exact catalog pin is what `Wasm.test.ts` checks the bytes against and cross-verifies with. On a bump, copy that release's `WASM_BASE64` and check its ABI (`src/lib.rs`: `alloc`, `dealloc`, `hash`, `last_ptr`, `verify`) is unchanged.

## Invariants

- **The wasm is compiled once, at module scope** (`src/Wasm.ts`), never lazily: workerd refuses wasm compilation inside a request (#744), and allows it at startup only from compatibility date 2025-06-01 (`allow_eval_during_startup`). Inside a request the kernel only calls the instance, or instantiates the already-compiled module to recover from a trap. `Workerd.test.ts` runs the hasher in the real `workerd` binary, in `test:unit`. The wasm stays an embedded string, not a `.wasm` import, so consumers need no bundler configuration.
- **Workers-safe**: no native module, no post-install step and no `node:` import anywhere in `src/` (only comments mention `node:`). Randomness for salts is `globalThis.crypto.getRandomValues`; the digest comparison happens inside the kernel, in constant time (RustCrypto's `subtle`). Don't replace either with a `node:` API.
- **`defaultProfile` stays Workers-sized** (OWASP low-memory: `m=19456` KiB, `t=2`, `p=1`); a Workers isolate has 128 MiB. `serverProfile` (`m=65536`, `t=3`) is opt-in.
- **Output is a standard PHC string** (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`), so hashes interoperate with any Argon2 implementation and `Password.multiAlgorithmVerifier` routes on the algorithm segment (`algorithm: "argon2id"`).
- **`verify` reads every parameter from the stored hash** (variant, `m`/`t`/`p`, salt, digest length), never from the configured options, so raising costs never locks anyone out.
- **An unverifiable hash fails, never returns `false`**: a malformed PHC string, an unknown variant, Argon2 `v=0x10` (which the kernel itself would accept) or a hash the kernel reports as unverifiable (`verify` returning `-1`) is a `HashingError`. A wrong password is `false`.
- **Hashes written by `hash-wasm` (0.1.x) verify**: `HashWasm.fixtures.ts` holds them, per variant, and the kernel must derive the argon2id ones byte for byte from the same salt.
- **Input guards before the KDF**: empty password or hash is a `HashingError`; a password over `MAX_PASSWORD_BYTES` (1024 UTF-8 bytes) is refused by `hash` and reads as `false` in `verify` (anti-DoS).
- Spans keep the core hashers' names (`effect-auth.password.hash` / `.verify`, attribute `algorithm`).

## Terms

- **Kernel** — `src/Wasm.ts`: the compiled module, its one instance and the two calls (`hashArgon2id`, `verifyArgon2`) over the wasm's C ABI.
- **Cost profile** — an `Argon2Profile` (`memoryCost` KiB, `timeCost`, `parallelism`); `resolveOptions` fills a partial `Argon2Options` from `defaultProfile`.
