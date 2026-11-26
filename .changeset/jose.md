---
"@thomasfosterau/effect-auth": minor
---

Move JWT, JWKS and every JWS onto `effect/jose`, and store JWT private keys as JWE. **Breaking.**

- `JwtKeyPair` holds `effect/jose` shapes: `publicKeyJwk` is now `publicKey` (a `Jwk.PublicJwk`) and `privateKeyPem` is now `privateKey`, the stored private key. `generateKeyPair(algorithm)` takes no crypto argument, requires `SecureRandom` and `Signature`, and returns a `GeneratedJwtKeyPair` whose `privateKey` is a `Redacted<Jwk.PrivateJwk>`, not yet encrypted.
- `JwtService` writes new private keys as a compact JWE (`dir` + `A256GCM`, under the root secret's `jwt-private-key` key or the `{ secret }` override's), with the key id in the authenticated protected header; a JWE moved to another key id does not open. A custom `{ cipher }` encrypts the private JWK's JSON. Keys stored before (`v2.` sealed, the earlier override ciphertext, or plaintext PEM) still sign.
- `getJwks()` returns `{ keys }` of `Jwk.PublicJwk`, each with `kid`, `alg` and `use: "sig"`.
- `RemoteJwksVerifier` verifies RS256 as well as ES256 and EdDSA (`algorithms` narrows the list), requires `exp`, and fetches the JWKS through `effect/jose`'s remote key set: HTTPS only, cached for `cacheTtlMs`, refetched once per cooldown for an unknown `kid`. `RemoteJwksVerifier.layer(config)` uses the platform `fetch`; `RemoteJwksVerifier.layerHttpClient(config)` takes the `HttpClient` from context. `remoteJwksVerifier(config)` now requires `HttpClient`, `Scope` and `Signature`.
- OIDC `id_token` verification, Cloudflare Access and `appleClientSecret` sign and verify through `effect/jose`.
- Removed from `Cipher`: `JwsAlgorithm`, `exportedPublicJwk`, `generateJwsKeyPair`, `signJws` and `verifyJws`. Use `effect/jose`'s `Jwk` and `Jws`.

Migration: a custom `JwtKeyStore` renames its two fields (`publicKeyJwk` to `publicKey`, `privateKeyPem` to `privateKey`); the stored values need no rewrite. No first-party adapter implements `JwtKeyStore` (`Testing.memoryJwtKeyStore` is updated), so the Drizzle and Alchemy packages are unchanged. A `RemoteJwksVerifier` pointed at an `http://` JWKS must move to HTTPS.
