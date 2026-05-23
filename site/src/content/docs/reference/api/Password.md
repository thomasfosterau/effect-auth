---
title: "Password"
description: "API reference for the Password module."
---

## Password overview

Password Hashing Traits and Multi-Algorithm Support

Inspired by Rust's password_hash crate, this module provides:

- Trait-based API (PasswordHasher interface) for algorithm-agnostic hashing
- PHC string format support (algorithm$params$salt$hash)
- Multi-algorithm verification for seamless migration
- Extensible design for custom algorithms

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [HashedPassword](#hashedpassword)
  - [MultiAlgorithmVerifier](#multialgorithmverifier)
  - [MultiAlgorithmVerifier (interface)](#multialgorithmverifier-interface)
  - [MultiAlgorithmVerifierTag (class)](#multialgorithmverifiertag-class)
  - [PBKDF2HasherLive](#pbkdf2hasherlive)
  - [PasswordHasher](#passwordhasher)
  - [PasswordHasher (interface)](#passwordhasher-interface)
  - [PasswordHasherLayer](#passwordhasherlayer)
  - [PasswordHasherLive](#passwordhasherlive)
  - [PasswordHasherTag (class)](#passwordhashertag-class)
  - [makeMultiAlgorithmVerifier](#makemultialgorithmverifier)
  - [makeMultiAlgorithmVerifierLayer](#makemultialgorithmverifierlayer)
  - [makePBKDF2Hasher](#makepbkdf2hasher)
  - [makePasswordHasher](#makepasswordhasher)

---

# utils

## HashedPassword

Re-export of {@link Types.HashedPassword} for convenience.

**Signature**

```ts
export declare const HashedPassword: Types.HashedPassword;
```

## MultiAlgorithmVerifier

**Signature**

```ts
export declare const MultiAlgorithmVerifier: typeof MultiAlgorithmVerifierTag;
```

## MultiAlgorithmVerifier (interface)

Multi-algorithm password verifier
Supports verifying passwords against different hash formats,
enabling seamless migration between algorithms

**Signature**

```ts
export interface MultiAlgorithmVerifier {
  /**
   * Verify a password against a hash, automatically detecting the algorithm
   * from the PHC format string
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}
```

## MultiAlgorithmVerifierTag (class)

Tag for MultiAlgorithmVerifier service

**Signature**

```ts
export declare class MultiAlgorithmVerifierTag
```

## PBKDF2HasherLive

Layer that provides PBKDF2 password hasher explicitly

**Signature**

```ts
export declare const PBKDF2HasherLive: Context.Context<PasswordHasherTag>;
```

## PasswordHasher

**Signature**

```ts
export declare const PasswordHasher: typeof PasswordHasherTag;
```

## PasswordHasher (interface)

Core password hashing interface (trait)
Implement this interface to support custom password hashing algorithms

**Signature**

```ts
export interface PasswordHasher {
  /**
   * Unique identifier for this algorithm (used in PHC format)
   */
  readonly algorithm: string;

  /**
   * Hash a password using this algorithm
   */
  readonly hash: (password: string) => Effect.Effect<Types.HashedPassword, Errors.HashingError>;

  /**
   * Verify a password against a hash using this algorithm
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}
```

## PasswordHasherLayer

Layer that provides the default PBKDF2 password hasher

**Signature**

```ts
export declare const PasswordHasherLayer: Layer.Layer<PasswordHasherTag, never, never>;
```

## PasswordHasherLive

Backward-compatible Context value that provides the default PBKDF2 password hasher

**Signature**

```ts
export declare const PasswordHasherLive: Context.Context<PasswordHasherTag>;
```

## PasswordHasherTag (class)

Tag for PasswordHasher service

**Signature**

```ts
export declare class PasswordHasherTag
```

## makeMultiAlgorithmVerifier

Create a multi-algorithm verifier that supports multiple password hashers
This allows you to verify passwords that were hashed with different algorithms,
which is useful during algorithm migration

**Signature**

```ts
export declare const makeMultiAlgorithmVerifier: (
  hashers: readonly PasswordHasher[],
) => MultiAlgorithmVerifier;
```

**Example**

```typescript
import { Effect } from "effect";

declare const verifier: { verify: (p: string, h: string) => Effect.Effect<boolean> };
declare const password: string;
declare const storedHash: string;

const program = Effect.gen(function* () {
  // Will automatically detect which algorithm was used.
  const isValid = yield* verifier.verify(password, storedHash);
  return isValid;
});
```

## makeMultiAlgorithmVerifierLayer

Create a layer that provides a multi-algorithm verifier

**Signature**

```ts
export declare const makeMultiAlgorithmVerifierLayer: (
  hashers: readonly PasswordHasher[],
) => Layer.Layer<MultiAlgorithmVerifierTag, never, never>;
```

## makePBKDF2Hasher

PBKDF2 Password Hasher implementing the PasswordHasher trait
Following Copenhagen/Oslo guidelines for secure password hashing

**Signature**

```ts
export declare const makePBKDF2Hasher: () => PasswordHasher;
```

## makePasswordHasher

Backward compatibility: Default password hasher is PBKDF2

**Signature**

```ts
export declare const makePasswordHasher: () => PasswordHasher;
```
