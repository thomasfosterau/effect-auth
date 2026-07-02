---
title: "Jwt"
description: "API reference for the Jwt module."
---

## Jwt overview

JSON Web Tokens (compact JWS) for effect-auth.

Mirrors better-auth's jwt plugin: issue short-lived, asymmetrically signed
JWTs for authenticated users so downstream services can verify sessions
without a shared secret or a round-trip to the auth server, and publish
the matching public keys as a JWKS document.

Implemented with `node:crypto` only (no dependencies):

- `ES256` (ECDSA over P-256 with SHA-256) — the default. Node's ECDSA
  signatures are DER-encoded by default, but JOSE requires the raw
  `r || s` concatenation, so signing/verifying passes
  `dsaEncoding: "ieee-p1363"`.
- `EdDSA` (Ed25519) — better-auth's default; sign/verify with a `null`
  digest as required for Ed25519.

All three token segments use unpadded base64url encoding.

Serving the JWKS is the application's concern: expose the result of
`getJwks()` at `/.well-known/jwks.json` (or wherever your `iss` publishes
keys) so verifiers can fetch the public keys.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [Jwks (interface)](#jwks-interface)
  - [JwtAlgorithm (type alias)](#jwtalgorithm-type-alias)
  - [JwtConfig (interface)](#jwtconfig-interface)
  - [JwtError (class)](#jwterror-class)
  - [JwtKeyPair (interface)](#jwtkeypair-interface)
  - [JwtKeyStore](#jwtkeystore)
  - [JwtKeyStore (interface)](#jwtkeystore-interface)
  - [JwtKeyStoreTag (class)](#jwtkeystoretag-class)
  - [JwtService](#jwtservice)
  - [JwtService (interface)](#jwtservice-interface)
  - [JwtServiceLayer](#jwtservicelayer)
  - [JwtServiceTag (class)](#jwtservicetag-class)
  - [JwtSignResult (interface)](#jwtsignresult-interface)
  - [generateKeyPair](#generatekeypair)
  - [makeJwtService](#makejwtservice)

---

# utils

## Jwks (interface)

The JWKS document (RFC 7517) to serve at `/.well-known/jwks.json`.

**Signature**

```ts
export interface Jwks {
  readonly keys: readonly Record<string, unknown>[];
}
```

## JwtAlgorithm (type alias)

Supported signing algorithms

**Signature**

```ts
export type JwtAlgorithm = "ES256" | "EdDSA";
```

## JwtConfig (interface)

JWT service configuration

**Signature**

```ts
export interface JwtConfig {
  /** Value of the `iss` claim; verification requires an exact match */
  readonly issuer: string;
  /** Value of the `aud` claim; when set, verification requires it */
  readonly audience?: string;
  /** Token lifetime in milliseconds (default: 15 minutes) */
  readonly expiresIn?: number;
  /** Signing algorithm for newly generated keys (default: "ES256") */
  readonly algorithm?: JwtAlgorithm;
  /** Derive the `sub` claim from the user (default: `user.id`) */
  readonly getSubject?: (user: Types.User) => string;
  /** Extra claims merged into every token's payload */
  readonly definePayload?: (user: Types.User) => Record<string, unknown>;
}
```

## JwtError (class)

JWT error

**Signature**

```ts
export declare class JwtError
```

## JwtKeyPair (interface)

A signing key pair.

`publicKeyJwk` is the public half only, exported in JWK form and safe to
publish via the JWKS document. `privateKeyPem` is the PKCS#8 PEM of the
private key — encrypt it at rest in production; the library stores/reads
it as-is.

**Signature**

```ts
export interface JwtKeyPair {
  /** Key id (`kid`), embedded in token headers and the JWKS */
  readonly id: string;
  readonly algorithm: JwtAlgorithm;
  /** Public key in JWK form (no private material) */
  readonly publicKeyJwk: Record<string, unknown>;
  /** PKCS#8 PEM private key — encrypt at rest in production */
  readonly privateKeyPem: string;
  readonly createdAt: number;
}
```

## JwtKeyStore

**Signature**

```ts
export declare const JwtKeyStore: typeof JwtKeyStoreTag;
```

## JwtKeyStore (interface)

Storage interface for JWT signing keys

**Signature**

```ts
export interface JwtKeyStore {
  /** The key pair new tokens should be signed with, or null when none exists */
  readonly getActive: () => Effect.Effect<JwtKeyPair | null, Errors.AuthError>;
  readonly create: (pair: JwtKeyPair) => Effect.Effect<JwtKeyPair, Errors.AuthError>;
  /** Every known key pair (verification matches tokens by `kid`) */
  readonly list: () => Effect.Effect<readonly JwtKeyPair[], Errors.AuthError>;
}
```

## JwtKeyStoreTag (class)

**Signature**

```ts
export declare class JwtKeyStoreTag
```

## JwtService

**Signature**

```ts
export declare const JwtService: typeof JwtServiceTag;
```

## JwtService (interface)

JWT service

**Signature**

```ts
export interface JwtService {
  /**
   * Sign a JWT for a user. The header is `{ alg, kid, typ: "JWT" }`; the
   * payload carries `iss`/`aud?`/`sub`/`iat`/`exp` plus `definePayload(user)`
   * and any `extraClaims`. Lazily generates and persists a key pair on first
   * use when the store is empty.
   */
  readonly sign: (
    user: Types.User,
    extraClaims?: Record<string, unknown>,
  ) => Effect.Effect<JwtSignResult, JwtError | Errors.AuthError, JwtKeyStoreTag>;

  /**
   * Verify a compact JWS and return its decoded payload. Validates the
   * signature against the stored key whose `kid` matches the header, then
   * checks `exp`, `iss`, and (when configured) `aud`. Fails with
   * {@link JwtError} on any mismatch.
   */
  readonly verify: (
    token: string,
  ) => Effect.Effect<Record<string, unknown>, JwtError | Errors.AuthError, JwtKeyStoreTag>;

  /**
   * The JWKS document containing every stored public key (with `kid`,
   * `alg`, and `use: "sig"`) and no private material. Serve this at
   * `/.well-known/jwks.json`.
   */
  readonly getJwks: () => Effect.Effect<Jwks, Errors.AuthError, JwtKeyStoreTag>;
}
```

## JwtServiceLayer

**Signature**

```ts
export declare const JwtServiceLayer: (
  config: JwtConfig,
) => Layer.Layer<JwtServiceTag, never, never>;
```

## JwtServiceTag (class)

**Signature**

```ts
export declare class JwtServiceTag
```

## JwtSignResult (interface)

A signed token plus its expiry (Unix ms).

**Signature**

```ts
export interface JwtSignResult {
  readonly token: string;
  readonly expiresAt: number;
}
```

## generateKeyPair

Generate a fresh signing key pair for the given algorithm.

ES256 uses ECDSA over the P-256 curve; EdDSA uses Ed25519. The public key
is exported as a JWK (via `crypto.KeyObject.export({ format: "jwk" })`),
the private key as PKCS#8 PEM.

**Signature**

```ts
export declare const generateKeyPair: (
  algorithm: JwtAlgorithm,
) => Effect.Effect<JwtKeyPair, JwtError>;
```

## makeJwtService

Create a JWT service

**Signature**

```ts
export declare const makeJwtService: (config: JwtConfig) => Effect.Effect<JwtService, never>;
```
