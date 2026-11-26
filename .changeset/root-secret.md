---
"@thomasfosterau/effect-auth": minor
---

Add one mandatory root secret that keys every server-side primitive, pepper OTPs and backup codes, hash the remaining raw tokens, and always encrypt TOTP secrets, OAuth provider tokens and JWT private keys. **Breaking.**

- New `Auth.RootSecret`: `RootSecret.layerConfig` reads `AUTH_SECRET` (required, at least 32 bytes; `openssl rand -hex 32`), `RootSecret.layer(secret)` takes it directly, and both fail with `RootSecretError` when it is missing or short. HKDF-SHA256 derives one key per purpose from it. `MultiFactorService`, `OtpSecondFactorService`, `EmailOtpService`, `PhoneOtpService`, `OAuthService`, `SsoService` and `JwtService` now require `RootSecret`; provide it beside your stores:

  ```ts
  const services = Layer.mergeAll(MultiFactorService.layer(config), JwtService.layerFromEnv).pipe(
    Layer.provide(Layer.mergeAll(stores, Auth.RootSecret.RootSecret.layerConfig)),
  );
  ```

  `Testing.memoryStores` provides a fixed test secret, and `Testing.testRootSecretLayer` is that secret on its own.

- Email, phone and second-factor OTPs and backup codes are stored as HMAC-SHA256 under the root secret's pepper rather than a bare SHA-256 digest. `EmailOtp.hashOtp` is removed; `hashBackupCode` remains as the legacy digest.
- Change-email and account-deletion tokens, pending second-factor challenges and the OAuth and SSO `state` are stored as their SHA-256 digest. The PKCE `code_verifier` is derived from the `state` under the root secret and no longer stored; `OAuthProvider` gains `usePKCE`.
- TOTP secrets, OAuth provider tokens and JWT private keys are always sealed with AES-256-GCM, with the purpose and row as associated data, as `v2.` + base64url. `TWO_FACTOR_ENCRYPT_SECRET`, `OAUTH_ENCRYPT_TOKENS_SECRET` and `JWT_ENCRYPT_PRIVATE_KEY_SECRET` (`encryptSecret` / `encryptTokens` / `encryptPrivateKey: { secret }`) now override one purpose's key instead of switching encryption on; a custom `{ cipher }` keeps its own format.
- `Cipher.secretSealer`, `Cipher.cipherSealer` and `Cipher.SEALED_PREFIX` are new.

Migration: no schema changes. Set `AUTH_SECRET` before deploying. Existing rows stay readable while they are rewritten: a value without the `v2.` prefix is opened with the override secret's earlier cipher when one is set and is otherwise read as plaintext, and the next write seals it. Backup codes stored under their SHA-256 digest still redeem. OTPs, OAuth states, pending second-factor challenges and change-email and account-deletion links that are live at the upgrade stop verifying; users request new ones.
