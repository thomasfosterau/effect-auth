# @thomasfosterau/effect-auth-argon2

Argon2id `PasswordHasher` for [`@thomasfosterau/effect-auth`](../effect-auth) — OWASP's first-choice password hashing algorithm, as an Effect `Layer`.

Core effect-auth ships only dependency-free hashers (PBKDF2, scrypt) because neither Node nor the Web Crypto API implements Argon2. This package fills that gap with a pure WebAssembly backend ([`hash-wasm`](https://github.com/Daninet/hash-wasm), MIT): no native module, no post-install step, and no `node:` imports, so it runs unchanged on Node, Bun, Deno, Cloudflare Workers, and browsers.

Hashes are standard PHC strings (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`), so they're interchangeable with older configurations of this package and with any other Argon2 implementation.

## Install

```sh
npm install @thomasfosterau/effect-auth-argon2
```

## Usage

```ts
import { Effect, Layer } from "effect";
import { argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2";

// Make Argon2id the hasher for new passwords, in place of PasswordHasher.layer()
const AuthLayer = Layer.mergeAll(
  argon2HasherLayer(),
  // ...the rest of your effect-auth layers
);
```

Or use the hasher directly:

```ts
import { Effect } from "effect";
import { argon2Hasher } from "@thomasfosterau/effect-auth-argon2";

const hasher = argon2Hasher();

const program = Effect.gen(function* () {
  const { hash } = yield* hasher.hash("correct horse battery staple");
  return yield* hasher.verify("correct horse battery staple", hash);
});
```

## Cost profiles

`argon2Hasher()` defaults to OWASP's **low-memory** Argon2id profile so the defaults are safe on every runtime this package supports, Cloudflare Workers included:

| Profile          | `memoryCost`     | `timeCost` | `parallelism` | Use for                          |
| ---------------- | ---------------- | ---------- | ------------- | -------------------------------- |
| `defaultProfile` | `19456` (19 MiB) | `2`        | `1`           | Workers / constrained runtimes   |
| `serverProfile`  | `65536` (64 MiB) | `3`        | `1`           | Plain Node servers with headroom |

```ts
import { argon2HasherLayer, serverProfile } from "@thomasfosterau/effect-auth-argon2";

const layer = argon2HasherLayer(serverProfile);
// or tune individual parameters
const custom = argon2HasherLayer({ memoryCost: 32768, timeCost: 3 });
```

`serverProfile` costs roughly 5× the work of the default; measure it against your own latency budget before adopting it. Do **not** use it on Cloudflare Workers — a Workers isolate has a 128 MiB memory limit, and Argon2 allocates `memoryCost` KiB for the duration of each hash.

## Cloudflare Workers

This package imports only WebAssembly and the platform Web Crypto API (`globalThis.crypto.getRandomValues`, the same source core effect-auth's `PlatformCrypto` layer uses). It needs no `nodejs_compat` flag and no native module.

Budget: with `defaultProfile`, a single hash costs ~19 MiB of the isolate's 128 MiB and tens of milliseconds of CPU. Hash one password per request.

## Verification and parameter changes

`verify` reads the variant, cost parameters, salt and digest length out of the **stored** hash rather than assuming the configured ones. Raising your cost parameters (or moving from `defaultProfile` to `serverProfile`) therefore never locks anyone out — existing hashes keep verifying under the parameters they were written with.

Hashes that cannot be recomputed (a malformed PHC string, an unsupported variant, Argon2 `v=0x10`) fail with a `HashingError` rather than silently returning `false`.

## Migrating from another hasher

`multiAlgorithmVerifier` routes by the algorithm segment of the stored hash, so Argon2id can be adopted alongside existing PBKDF2/scrypt hashes:

```ts
import { Password } from "@thomasfosterau/effect-auth";
import { argon2Hasher } from "@thomasfosterau/effect-auth-argon2";

const verifier = Password.multiAlgorithmVerifier([argon2Hasher(), Password.pbkdf2Hasher()]);
```

## API

Package root (`@thomasfosterau/effect-auth-argon2`):

- `argon2Hasher(options?)` — WASM-backed `PasswordHasher` service.
- `argon2HasherLayer(options?)` — the same as a `Layer`.
- `ARGON2ID` — the `"argon2id"` PHC algorithm identifier.
- `Argon2Options`, `Argon2Profile` — cost parameter types.
- `defaultProfile`, `serverProfile`, `resolveOptions(options?)`.
- `SALT_LENGTH`, `HASH_LENGTH`, `MAX_PASSWORD_BYTES`.

## License

MIT
