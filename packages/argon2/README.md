# @thomasfosterau/effect-auth-argon2

Argon2id `PasswordHasher` for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) — OWASP's first-choice password hashing algorithm, as an Effect `Layer`.

Core effect-auth has its own Argon2id hasher, `Password.argon2idHasherLayer`, over Effect's `Kdf` service. Only `NodeCrypto.layerKdf` (Node.js 24.7+, Bun 1.4+) derives Argon2id there: Web Crypto has no Argon2, and neither has Cloudflare Workers' `node:crypto`. On Node and Bun, prefer the core hasher. This package is for everywhere else, Workers above all, with a WebAssembly backend: the RustCrypto [`argon2`](https://crates.io/crates/argon2) crate as built by [`@thomasfosterau/argon2`](https://www.npmjs.com/package/@thomasfosterau/argon2) (MIT), embedded as a base64 string and compiled once, when the module loads. No native module, no post-install step, no `node:` imports and no `.wasm` asset, so it runs unchanged on Node, Bun, Deno, Cloudflare Workers, and browsers.

Hashes are standard PHC strings (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`), so they're interchangeable with older configurations of this package and with any other Argon2 implementation.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-argon2 @thomasfosterau/effect-auth effect
```

`effect` (`^4.1.0`) is a peer dependency. The wasm ships inside this package, so there is nothing else to install and no bundler configuration: bundlers see plain JavaScript.

## Usage

```ts
import { Layer } from "effect";
import { argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2";

// Make Argon2id the hasher for new passwords, in place of PasswordHasher.layer()
const AuthLayer = Layer.mergeAll(
  argon2HasherLayer(),
  // ...the rest of your effect-auth layers
);
```

## Entry points

Package root (`@thomasfosterau/effect-auth-argon2`):

- `argon2Hasher(options?)` — WASM-backed `PasswordHasher` service, with `needsRehash`.
- `argon2HasherLayer(options?)` — the same as a `Layer`.
- `ARGON2ID` — the `"argon2id"` PHC algorithm identifier.
- `Argon2Options` (costs and verify limits), `Argon2Profile`, `Argon2VerifyLimits` — option types.
- `defaultProfile`, `serverProfile`, `resolveOptions(options?)`.
- `defaultVerifyLimits` (`maxMemoryKiB` 131072, `maxIterations` 10, `maxParallelism` 8), `workerdVerifyLimits` (the same with `maxMemoryKiB` 65536, the default on Workers), `resolveVerifyLimits(options?)`.
- `SALT_LENGTH` (16 bytes), `HASH_LENGTH` (32 bytes), `MAX_PASSWORD_BYTES` (1024 UTF-8 bytes: `hash` refuses a longer password with a `HashingError`, `verify` reads one as `false` without running the KDF).
- Input guards the hasher applies, exported for other hashers to share: `isWithinMaxLength(password)`, `requireNonEmptyPassword(password)`, `requireNonEmptyHash(hash)`, `requireHashablePassword(password)` (the `require*` guards fail with `HashingError`; `isWithinMaxLength` returns a boolean).

## Guide

The [Argon2id guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/argon2.md) covers cost profiles, Cloudflare Workers, the verify ceiling, rehashing and migrating from another hasher.

## License

MIT.

The embedded WebAssembly binary is copied from [`@thomasfosterau/argon2`](https://www.npmjs.com/package/@thomasfosterau/argon2) 0.1.1, MIT, Copyright (c) 2026 Thomas Foster. It is compiled from Rust, not from the Argon2 reference C implementation: the RustCrypto [`argon2`](https://crates.io/crates/argon2) crate and the RustCrypto crates it builds on (`blake2`, `password-hash`, `base64ct`, `subtle`) are dual-licensed MIT OR Apache-2.0, used here under MIT.
