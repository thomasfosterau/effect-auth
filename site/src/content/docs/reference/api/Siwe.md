---
title: "Siwe"
description: "API reference for the Siwe module."
---

## Siwe overview

Sign-In With Ethereum (SIWE, EIP-4361).

The user proves control of an Ethereum account by signing a structured
plaintext message (containing a server-issued, single-use nonce) with their
wallet. This module owns the protocol pieces that need no cryptography
beyond `node:crypto` — nonce issuance, EIP-4361 message construction and
parsing, and the sign-in orchestration (find-or-create the user by wallet
address, issue a session).

The actual signature check (secp256k1 public-key recovery + keccak256)
requires a dependency, so — per the hashing-policy precedent — it lives
behind the {@link SiweVerifierTag} interface, implemented by the
`@effect-auth/siwe` package. Sign-in stays disabled (404 at the HTTP layer)
until a verifier layer is provided.

User convention: the wallet address is stored lowercase in
`user.attributes.walletAddress`.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [SiweConfig (interface)](#siweconfig-interface)
  - [SiweError (class)](#siweerror-class)
  - [SiweMessage (interface)](#siwemessage-interface)
  - [SiweNonce (interface)](#siwenonce-interface)
  - [SiweNonceStore](#siwenoncestore)
  - [SiweNonceStore (interface)](#siwenoncestore-interface)
  - [SiweNonceStoreTag (class)](#siwenoncestoretag-class)
  - [SiweService](#siweservice)
  - [SiweService (interface)](#siweservice-interface)
  - [SiweServiceLayer](#siweservicelayer)
  - [SiweServiceTag (class)](#siweservicetag-class)
  - [SiweSignInResult (interface)](#siwesigninresult-interface)
  - [SiweUserStore](#siweuserstore)
  - [SiweUserStore (interface)](#siweuserstore-interface)
  - [SiweUserStoreTag (class)](#siweuserstoretag-class)
  - [SiweVerifier](#siweverifier)
  - [SiweVerifier (interface)](#siweverifier-interface)
  - [SiweVerifierTag (class)](#siweverifiertag-class)
  - [formatSiweMessage](#formatsiwemessage)
  - [makeSiweService](#makesiweservice)
  - [parseSiweMessage](#parsesiwemessage)

---

# utils

## SiweConfig (interface)

Configuration for {@link makeSiweService}.

**Signature**

```ts
export interface SiweConfig {
  /** RFC 3986 authority that must appear in signed messages (e.g. `app.example.com`). */
  readonly domain: string;
  /** Nonce lifetime in ms (default: 10 minutes). */
  readonly nonceExpiresIn?: number;
}
```

## SiweError (class)

Failure to issue a nonce, parse a message, or complete a SIWE sign-in.

**Signature**

```ts
export declare class SiweError
```

## SiweMessage (interface)

A parsed EIP-4361 message.

**Signature**

```ts
export interface SiweMessage {
  /** RFC 3986 authority requesting the signing (e.g. `app.example.com`). */
  readonly domain: string;
  /** `0x`-prefixed Ethereum address performing the signing. */
  readonly address: string;
  /** Human-readable statement shown by the wallet. */
  readonly statement?: string;
  /** RFC 3986 URI referring to the subject of the signing. */
  readonly uri: string;
  readonly version: "1";
  readonly chainId: number;
  /** Server-issued randomized token (from {@link SiweService.generateNonce}). */
  readonly nonce: string;
  /** ISO 8601 datetime of the issuance. */
  readonly issuedAt: string;
  /** ISO 8601 datetime after which the message is invalid. */
  readonly expirationTime?: string;
  /** ISO 8601 datetime before which the message is invalid. */
  readonly notBefore?: string;
  readonly requestId?: string;
  readonly resources?: readonly string[];
}
```

## SiweNonce (interface)

A single-use sign-in nonce.

**Signature**

```ts
export interface SiweNonce {
  readonly nonce: string;
  /** Epoch milliseconds. */
  readonly expiresAt: number;
  readonly createdAt: number;
}
```

## SiweNonceStore

**Signature**

```ts
export declare const SiweNonceStore: typeof SiweNonceStoreTag;
```

## SiweNonceStore (interface)

Ephemeral store for issued nonces.

**Signature**

```ts
export interface SiweNonceStore {
  readonly create: (nonce: SiweNonce) => Effect.Effect<SiweNonce, AuthError>;
  readonly get: (nonce: string) => Effect.Effect<SiweNonce | null, AuthError>;
  readonly delete: (nonce: string) => Effect.Effect<void, AuthError>;
}
```

## SiweNonceStoreTag (class)

**Signature**

```ts
export declare class SiweNonceStoreTag
```

## SiweService

**Signature**

```ts
export declare const SiweService: typeof SiweServiceTag;
```

## SiweService (interface)

**Signature**

```ts
export interface SiweService {
  /** Issue a single-use nonce for the wallet to embed in its message. */
  readonly generateNonce: () => Effect.Effect<
    { readonly nonce: string; readonly expiresAt: number },
    AuthError,
    SiweNonceStoreTag
  >;

  /**
   * Complete a SIWE sign-in: parse the message, check the domain, redeem the
   * nonce (single use), enforce the message's time window, verify the
   * signature, find-or-create the user by wallet address, and issue a session.
   */
  readonly verify: (input: {
    readonly message: string;
    readonly signature: string;
  }) => Effect.Effect<
    SiweSignInResult,
    SiweError | AuthError | HookError,
    SiweNonceStoreTag | SiweUserStoreTag | SiweVerifierTag | SessionManagerTag | Hooks
  >;
}
```

## SiweServiceLayer

**Signature**

```ts
export declare const SiweServiceLayer: (
  config: SiweConfig,
) => Layer.Layer<SiweServiceTag, never, never>;
```

## SiweServiceTag (class)

**Signature**

```ts
export declare class SiweServiceTag
```

## SiweSignInResult (interface)

Result of a completed SIWE sign-in.

**Signature**

```ts
export interface SiweSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  /** Lowercase wallet address the signature recovered to. */
  readonly walletAddress: string;
}
```

## SiweUserStore

**Signature**

```ts
export declare const SiweUserStore: typeof SiweUserStoreTag;
```

## SiweUserStore (interface)

Minimal user store for wallet sign-ins. Implementations look users up by
the lowercase wallet address and, on first sign-in, create a user carrying
`attributes.walletAddress`.

**Signature**

```ts
export interface SiweUserStore {
  readonly getUserByWalletAddress: (
    walletAddress: string,
  ) => Effect.Effect<Types.User | null, AuthError>;
  readonly createUser: (input: {
    readonly walletAddress: string;
  }) => Effect.Effect<Types.User, AuthError>;
}
```

## SiweUserStoreTag (class)

**Signature**

```ts
export declare class SiweUserStoreTag
```

## SiweVerifier

**Signature**

```ts
export declare const SiweVerifier: typeof SiweVerifierTag;
```

## SiweVerifier (interface)

Signature verification over the EIP-191 `personal_sign` scheme. Implemented
by `@effect-auth/siwe` (secp256k1 recovery needs a dependency, which stays
out of the core package per the hashing-policy precedent).

**Signature**

```ts
export interface SiweVerifier {
  /**
   * `true` when `signature` (65-byte `r || s || v` hex) over the EIP-191
   * envelope of `message` recovers an Ethereum address equal to `address`
   * (case-insensitive).
   */
  readonly verifyMessage: (input: {
    readonly message: string;
    readonly signature: string;
    readonly address: string;
  }) => Effect.Effect<boolean, SiweError>;
}
```

## SiweVerifierTag (class)

**Signature**

```ts
export declare class SiweVerifierTag
```

## formatSiweMessage

Serialize a {@link SiweMessage} into EIP-4361 plaintext for signing.

**Signature**

```ts
export declare const formatSiweMessage: (message: SiweMessage) => string;
```

## makeSiweService

**Signature**

```ts
export declare const makeSiweService: (config: SiweConfig) => Effect.Effect<SiweService, never>;
```

## parseSiweMessage

Parse EIP-4361 plaintext into a {@link SiweMessage}.

**Signature**

```ts
export declare const parseSiweMessage: (text: string) => Effect.Effect<SiweMessage, SiweError>;
```
