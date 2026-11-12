---
"@thomasfosterau/effect-auth-argon2": patch
---

Hash and verify on Cloudflare Workers (#744). The hasher ran on `hash-wasm`, which compiles its wasm lazily on the first hash; workerd refuses wasm compilation inside a request, so every sign-up and sign-in on a deployed Worker failed with `CompileError: WebAssembly.compile(): Wasm code generation disallowed by embedder`. The backend is now the RustCrypto `argon2` crate as built by `@thomasfosterau/argon2` 0.1.1, embedded as a base64 string and compiled once at module scope, and `hash-wasm` is no longer a dependency. The API, the PHC format and the defaults (`m=19456,t=2,p=1`, 16-byte salt, 32-byte digest) are unchanged, and hashes written by 0.1.x verify.

A Worker needs a compatibility date of 2025-06-01 or later, or the `allow_eval_during_startup` flag on an older one: before that date workerd refuses wasm compilation at startup too, and the Worker fails to start. It needs no bundler configuration, since the wasm is not a `.wasm` import. A stored hash whose salt is longer than 48 bytes or whose digest is longer than 64 bytes, which this package never wrote, is now a `HashingError` instead of verifying.
