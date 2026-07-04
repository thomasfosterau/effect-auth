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
  - [MultiAlgorithmVerifier (class)](#multialgorithmverifier-class)
  - [MultiAlgorithmVerifierShape (interface)](#multialgorithmverifiershape-interface)
  - [PasswordHasher (class)](#passwordhasher-class)
  - [PasswordHasherShape (interface)](#passwordhashershape-interface)
  - [makeMultiAlgorithmVerifier](#makemultialgorithmverifier)
  - [makePBKDF2Hasher](#makepbkdf2hasher)
  - [makeScryptHasher](#makescrypthasher)

---

# utils

## HashedPassword

Re-export of {@link Types.HashedPassword} for convenience.

**Signature**

```ts
export declare const HashedPassword: Types.HashedPassword;
```

## MultiAlgorithmVerifier (class)

Tag for MultiAlgorithmVerifier service

**Signature**

```ts
export declare class MultiAlgorithmVerifier
```

## MultiAlgorithmVerifierShape (interface)

Multi-algorithm password verifier
Supports verifying passwords against different hash formats,
enabling seamless migration between algorithms

**Signature**

```ts
export interface MultiAlgorithmVerifierShape {
  /**
   * Verify a password against a hash, automatically detecting the algorithm
   * from the PHC format string
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}
```

## PasswordHasher (class)

Tag for PasswordHasher service

**Signature**

```ts
export declare class PasswordHasher
```

## PasswordHasherShape (interface)

Core password hashing interface (trait)
Implement this interface to support custom password hashing algorithms

**Signature**

```ts
export interface PasswordHasherShape {
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

## makeMultiAlgorithmVerifier

Create a multi-algorithm verifier that supports multiple password hashers
This allows you to verify passwords that were hashed with different algorithms,
which is useful during algorithm migration

**Signature**

```ts
export declare const makeMultiAlgorithmVerifier: (
  hashers: readonly PasswordHasherShape[],
) => MultiAlgorithmVerifierShape;
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

## makePBKDF2Hasher

PBKDF2 Password Hasher implementing the PasswordHasher trait
Following Copenhagen/Oslo guidelines for secure password hashing

**Signature**

```ts
export declare const makePBKDF2Hasher: () => PasswordHasherShape;
```

## makeScryptHasher

scrypt Password Hasher implementing the PasswordHasher trait.

Uses Node's built-in `crypto.scrypt` (dependency-free) with OWASP-recommended
parameters (N=2^17, r=8, p=1). scrypt is memory-hard, making it more
resistant to GPU/ASIC attacks than PBKDF2.

PHC-style format: `scrypt$N$r$p$salt$hash` (N/r/p are stored so parameters
can be tuned without breaking existing hashes).

**Signature**

```ts
export declare const makeScryptHasher: (options?: {
  readonly cost?: number;
  readonly blockSize?: number;
  readonly parallelization?: number;
}) => PasswordHasherShape;
```
