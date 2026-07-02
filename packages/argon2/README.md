# @effect-auth/argon2

Argon2id password hasher for [effect-auth](https://github.com/thomasfosterau/effect-auth), backed by [`@node-rs/argon2`](https://github.com/napi-rs/node-rs) (prebuilt native bindings — no build step).

Core `effect-auth` ships only dependency-free hashers (PBKDF2, scrypt). Argon2id — OWASP's first-choice password-hashing algorithm — needs a native binding, so it lives here. Hashes are standard PHC strings (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`) and interoperate with any other Argon2 implementation.

## Install

```sh
npm install @effect-auth/argon2 effect-auth effect
```

## Usage

```ts
import { makeArgon2Hasher, Argon2HasherLayer } from "@effect-auth/argon2";

// OWASP defaults: m = 19456 KiB (19 MiB), t = 2, p = 1.
const hasher = makeArgon2Hasher();

// Or override the cost parameters:
const strong = makeArgon2Hasher({ memoryCost: 65536, timeCost: 3, parallelism: 1 });

// Provide it as the default password hasher in your service layer:
const PasswordLayer = Argon2HasherLayer();
```

`makeArgon2Hasher` implements effect-auth's `PasswordHasher` trait (`algorithm: "argon2id"`), so it drops into anything that consumes `PasswordHasherTag`.

## Migrating from PBKDF2 / scrypt

Use `makeMultiAlgorithmVerifier` to verify passwords hashed with any registered algorithm, and re-hash with Argon2id on the next successful sign-in:

```ts
import { makeMultiAlgorithmVerifier, makePBKDF2Hasher } from "effect-auth";
import { makeArgon2Hasher } from "@effect-auth/argon2";
import { Effect } from "effect";

const argon2 = makeArgon2Hasher();
const verifier = makeMultiAlgorithmVerifier([argon2, makePBKDF2Hasher()]);

const signIn = (password: string, storedHash: string) =>
  Effect.gen(function* () {
    const ok = yield* verifier.verify(password, storedHash); // routes by algorithm
    if (!ok) return null;
    // Rehash-on-login: upgrade legacy hashes to Argon2id transparently.
    if (!storedHash.startsWith("$argon2id$")) {
      const upgraded = yield* argon2.hash(password);
      // ...persist `upgraded.hash` for this user...
    }
    return true;
  });
```

The verifier detects the algorithm from the stored hash (the library's `algo$…` format for PBKDF2/scrypt, or the leading `$argon2id$…` for PHC strings), so a single verifier handles a mixed-algorithm user table during migration.
