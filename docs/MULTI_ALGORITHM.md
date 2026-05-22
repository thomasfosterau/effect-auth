# Multi-Algorithm Password Hashing

Inspired by Rust's `password_hash` crate, effect-auth provides a trait-based API for algorithm-agnostic password hashing with support for multiple algorithms.

## Key Features

### 1. Trait-Based Design

The `PasswordHasher` interface (trait) provides a standard contract for implementing password hashing algorithms:

```typescript
interface PasswordHasher {
  readonly algorithm: string; // PHC format identifier
  readonly hash: (password: string) => Effect<HashedPassword, HashingError>;
  readonly verify: (password: string, hash: string) => Effect<boolean, HashingError>;
}
```

### 2. PHC String Format

All hashers use the Password Hashing Competition (PHC) string format for interoperability:

```
algorithm$parameters$salt$hash
```

Example:

```
pbkdf2-sha256$210000$3a5f8c9d2e1b4a7c$f8e3d2c1b0a9...
```

### 3. Multi-Algorithm Support

The `MultiAlgorithmVerifier` allows you to verify passwords hashed with different algorithms:

```typescript
const verifier = makeMultiAlgorithmVerifier([
  makePBKDF2Hasher(),
  makeArgon2Hasher(), // When available
  makeBcryptHasher(), // When available
]);

// Automatically detects algorithm from hash
const isValid = yield * verifier.verify(password, storedHash);
```

## Usage

### Basic Usage with PBKDF2

```typescript
import { Effect } from "effect";
import * as Auth from "effect-auth";

const program = Effect.gen(function* () {
  const hasher = Auth.makePBKDF2Hasher();

  // Hash a password
  const hashed = yield* hasher.hash("myPassword123");
  console.log(hashed.algorithm); // "pbkdf2-sha256"
  console.log(hashed.hash); // PHC format string

  // Verify a password
  const isValid = yield* hasher.verify("myPassword123", hashed.hash);
  console.log(isValid); // true
});

await Effect.runPromise(Effect.provide(program, Auth.PasswordHasherLive));
```

### Multi-Algorithm Migration

```typescript
import { Effect } from "effect";
import * as Auth from "effect-auth";

// Scenario: You're migrating from PBKDF2 to Argon2
// Old users have PBKDF2 hashes, new users get Argon2

const program = Effect.gen(function* () {
  // Create verifier supporting multiple algorithms
  const verifier = Auth.makeMultiAlgorithmVerifier([
    Auth.makePBKDF2Hasher(),
    // makeArgon2Hasher(),  // Add when available
  ]);

  // Verify passwords from any supported algorithm
  const isValid = yield* verifier.verify(password, userPasswordHash);

  if (isValid) {
    // Optionally rehash with newer algorithm
    const newHasher = Auth.makePBKDF2Hasher(); // Or Argon2
    const newHash = yield* newHasher.hash(password);
    // Store newHash in database
  }
});
```

### Custom Algorithm Implementation

You can implement custom password hashers by implementing the `PasswordHasher` interface:

```typescript
import { Effect } from "effect";
import type { PasswordHasher } from "effect-auth";

const makeCustomHasher = (): PasswordHasher => ({
  algorithm: "custom-algo",

  hash: (password) =>
    Effect.gen(function* () {
      // Your custom hashing logic
      const hash = yield* customHashFunction(password);
      return {
        hash: `custom-algo$params$${hash}`,
        algorithm: "custom-algo",
      };
    }),

  verify: (password, hash) =>
    Effect.gen(function* () {
      // Your custom verification logic
      return yield* customVerifyFunction(password, hash);
    }),
});

// Use with multi-algorithm verifier
const verifier = makeMultiAlgorithmVerifier([makePBKDF2Hasher(), makeCustomHasher()]);
```

## Comparison with Rust's password_hash Crate

| Feature             | Rust password_hash        | effect-auth                     |
| ------------------- | ------------------------- | ------------------------------- |
| Trait-based API     | ✅ `PasswordHasher` trait | ✅ `PasswordHasher` interface   |
| PHC format          | ✅ Native support         | ✅ Native support               |
| Multi-algorithm     | ✅ Via trait objects      | ✅ Via `MultiAlgorithmVerifier` |
| Algorithm detection | ✅ Automatic              | ✅ Automatic                    |
| Extensibility       | ✅ Implement trait        | ✅ Implement interface          |
| Type safety         | ✅ Rust type system       | ✅ TypeScript + Effect types    |
| Error handling      | ✅ Result types           | ✅ Effect error types           |

## Algorithm Migration Strategy

1. **Add new algorithm to verifier**:

   ```typescript
   const verifier = makeMultiAlgorithmVerifier([
     makePBKDF2Hasher(), // Old algorithm
     makeArgon2Hasher(), // New algorithm
   ]);
   ```

2. **Use new algorithm for new users**:

   ```typescript
   const newHasher = makeArgon2Hasher();
   const hash = yield * newHasher.hash(password);
   ```

3. **Rehash on login** (optional but recommended):

   ```typescript
   const isValid = yield * verifier.verify(password, user.passwordHash);

   if (isValid && user.passwordHash.startsWith("pbkdf2")) {
     // Upgrade to Argon2
     const newHasher = makeArgon2Hasher();
     const newHash = yield * newHasher.hash(password);
     yield * updateUserPassword(user.id, newHash.hash);
   }
   ```

4. **Monitor and remove old algorithm**:
   Once all users have been migrated, remove the old hasher from the verifier.

## Security Considerations

1. **PHC Format**: Ensures consistent, parseable password hash strings
2. **Algorithm Identifier**: Always stored with hash for automatic detection
3. **Timing-Safe Comparison**: All verifiers use constant-time comparison
4. **Forward Compatibility**: Easy to add new algorithms as they become available
5. **Gradual Migration**: No need for mass password resets during upgrades

## Available Algorithms

Currently implemented:

- **PBKDF2-SHA256**: 210,000 iterations (OWASP recommended)

Planned/possible additions:

- **Argon2id**: Winner of Password Hashing Competition
- **Bcrypt**: Industry standard (via custom implementation)
- **Scrypt**: Memory-hard KDF

## Examples

See `examples/multi-algorithm.ts` for a complete working example demonstrating:

- Creating users with different algorithms
- Automatic algorithm detection
- Password verification across algorithms
- Error handling for unsupported algorithms

## References

- [Rust password_hash crate](https://docs.rs/password-hash/)
- [PHC String Format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
