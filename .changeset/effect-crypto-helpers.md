---
"@thomasfosterau/effect-auth": minor
---

Move the core's hashing, HMAC, AES-GCM, PBKDF2 and WebAuthn signature checks onto `effect/crypto`, so the root no longer reaches `node:crypto` for them. **Breaking.**

- `hashToken`, `sha256`, `hmac`, `aes256GcmSeal`, `aes256GcmOpen` and `aes256GcmCipher` now return Effects that require the `effect/crypto` services (`Digest`, `Mac`, `Aead`, `SecureRandom`). The `TokenCipher` that `aes256GcmCipher` yields keeps its Effect `encrypt` / `decrypt`. Provide `Auth.PlatformCrypto.layer` (Web Crypto, now exported from the root), or wrap a call in `Auth.PlatformCrypto.provide`:

  ```ts
  // before: const digest = Auth.hashToken(token)
  const program = Effect.gen(function* () {
    const digest = yield* Auth.hashToken(token);
    const cipher = yield* Auth.aes256GcmCipher(secret);
    return { digest, sealed: yield* cipher.encrypt(digest) };
  }).pipe(Effect.provide(Auth.PlatformCrypto.layer));
  // outside a layer
  const digest = await Effect.runPromise(Auth.PlatformCrypto.provide(Auth.hashToken(token)));
  ```

  The stored formats do not change: digests are the same hex SHA-256, and sealed values keep `base64url(iv ‖ tag ‖ ciphertext)`, so existing rows and cookies still read.

- Services that took these helpers through their layers now list the services in their requirements (`Digest`, and for the encrypting ones `Aead`, `Mac` or `Signature`). `PlatformCrypto.layer` provides all of them.
- `pbkdf2Hasher` derives through `Kdf` (PBKDF2-SHA256 over Web Crypto) and stays the default `PasswordHasher`; its hash format is unchanged. It takes optional `kdf` and `random` overrides.
- scrypt moved to the Node-only subpath `@thomasfosterau/effect-auth/scrypt`, as an opt-in verifier for older hashes. `PasswordHasher.layerScrypt` is removed; use the subpath's `layer(options)` or put `scryptHasher` beside the default in a `multiAlgorithmVerifier`, which rehashes to PBKDF2 on sign-in:

  ```ts
  import { scryptHasher } from "@thomasfosterau/effect-auth/scrypt";
  const verifier = Auth.Password.multiAlgorithmVerifier([
    Auth.Password.pbkdf2Hasher(),
    scryptHasher(),
  ]);
  ```

- WebAuthn signature checks run through `Signature`. `verifyDerSignature` is replaced by `verifySpkiSignature(algorithm, spki, message, signature)` (ES256 takes the authenticator's DER signature, a malformed one verifies `false`), and `jwkToSpkiDer` now takes the algorithm first and returns an Effect. `WebAuthnService` requires `Signature`.
- `hashBackupCode` returns an Effect. The session cache cookie's encode and decode return Effects, and `ResolvedSessionCache.encryptionKey` is replaced by `encrypt: boolean`.
