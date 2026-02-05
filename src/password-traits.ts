/**
 * Password Hashing Traits and Multi-Algorithm Support
 * 
 * Inspired by Rust's password_hash crate, this module provides:
 * - Trait-based API (PasswordHasher interface) for algorithm-agnostic hashing
 * - PHC string format support (algorithm$params$salt$hash)
 * - Multi-algorithm verification for seamless migration
 * - Extensible design for custom algorithms
 */

import { Effect, Context } from "effect"
import type * as Types from "./types.js"
import * as Errors from "./errors.js"

/**
 * Core password hashing interface (trait)
 * Implement this interface to support custom password hashing algorithms
 */
export interface PasswordHasher {
  /**
   * Unique identifier for this algorithm (used in PHC format)
   */
  readonly algorithm: string

  /**
   * Hash a password using this algorithm
   */
  readonly hash: (password: string) => Effect.Effect<Types.HashedPassword, Errors.HashingError>
  
  /**
   * Verify a password against a hash using this algorithm
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>
}

/**
 * Multi-algorithm password verifier
 * Supports verifying passwords against different hash formats,
 * enabling seamless migration between algorithms
 */
export interface MultiAlgorithmVerifier {
  /**
   * Verify a password against a hash, automatically detecting the algorithm
   * from the PHC format string
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>
}

/**
 * Tag for PasswordHasher service
 */
export const PasswordHasher = Context.GenericTag<PasswordHasher>("@effect-auth/PasswordHasher")

/**
 * Tag for MultiAlgorithmVerifier service
 */
export const MultiAlgorithmVerifier = Context.GenericTag<MultiAlgorithmVerifier>(
  "@effect-auth/MultiAlgorithmVerifier"
)

/**
 * Parse a PHC format string to extract the algorithm identifier
 */
const parseAlgorithm = (hash: string): Effect.Effect<string, Errors.HashingError> =>
  Effect.sync(() => {
    const parts = hash.split("$")
    if (parts.length < 2) {
      return Effect.fail(new Errors.HashingError({
        message: "Invalid hash format: missing algorithm identifier"
      }))
    }
    return Effect.succeed(parts[0])
  }).pipe(Effect.flatten)

/**
 * Create a multi-algorithm verifier that supports multiple password hashers
 * This allows you to verify passwords that were hashed with different algorithms,
 * which is useful during algorithm migration
 * 
 * @example
 * ```typescript
 * const verifier = makeMultiAlgorithmVerifier([
 *   makePBKDF2Hasher(),
 *   makeArgon2Hasher(),
 *   makeBcryptHasher()
 * ])
 * 
 * // Will automatically detect which algorithm was used
 * const isValid = yield* verifier.verify(password, storedHash)
 * ```
 */
export const makeMultiAlgorithmVerifier = (
  hashers: readonly PasswordHasher[]
): MultiAlgorithmVerifier => {
  const hasherMap = new Map(hashers.map(h => [h.algorithm, h]))

  return {
    verify: (password, hash) =>
      Effect.gen(function* () {
        const algorithm = yield* parseAlgorithm(hash)
        const hasher = hasherMap.get(algorithm)

        if (!hasher) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: `Unsupported algorithm: ${algorithm}. Available: ${Array.from(hasherMap.keys()).join(", ")}`
            })
          )
        }

        return yield* hasher.verify(password, hash)
      })
  }
}

/**
 * Create a layer that provides a multi-algorithm verifier
 */
export const makeMultiAlgorithmVerifierLayer = (hashers: readonly PasswordHasher[]) =>
  Context.make(MultiAlgorithmVerifier, makeMultiAlgorithmVerifier(hashers))
