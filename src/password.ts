import { Effect, Context } from "effect"
import * as crypto from "node:crypto"
import { promisify } from "node:util"
import * as Errors from "./errors.js"
import type { PasswordHasher as IPasswordHasher } from "./password-traits.js"
import { PasswordHasher as PasswordHasherContext } from "./password-traits.js"

const pbkdf2 = promisify(crypto.pbkdf2)

// Re-export the trait-based interfaces and Context tags
export type { PasswordHasher, MultiAlgorithmVerifier } from "./password-traits.js"
export { 
  makeMultiAlgorithmVerifier, 
  makeMultiAlgorithmVerifierLayer,
  PasswordHasher as PasswordHasherContext,
  MultiAlgorithmVerifier as MultiAlgorithmVerifierContext
} from "./password-traits.js"

export type { HashedPassword } from "./types.js"

/**
 * PBKDF2 Password Hasher implementing the PasswordHasher trait
 * Following Copenhagen/Oslo guidelines for secure password hashing
 */
export const makePBKDF2Hasher = (): IPasswordHasher => {
  const ALGORITHM = "pbkdf2-sha256"
  const ITERATIONS = 210000 // OWASP recommended minimum
  const KEY_LENGTH = 64
  const SALT_LENGTH = 16

  return {
    algorithm: ALGORITHM,
    hash: (password: string) =>
      Effect.gen(function* () {
        // Validate input
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(new Errors.HashingError({
            message: "Password must be a non-empty string"
          }))
        }

        if (password.length < 1) {
          return yield* Effect.fail(new Errors.HashingError({
            message: "Password cannot be empty"
          }))
        }

        const salt = crypto.randomBytes(SALT_LENGTH)
        
        const derivedKey = yield* Effect.tryPromise({
          try: () => pbkdf2(password, salt, ITERATIONS, KEY_LENGTH, "sha256"),
          catch: (error) => new Errors.HashingError({
            message: "Failed to hash password",
            cause: error
          })
        })

        // Format: algorithm$iterations$salt$hash
        const hash = `${ALGORITHM}$${ITERATIONS}$${salt.toString("hex")}$${derivedKey.toString("hex")}`

        return {
          hash,
          algorithm: ALGORITHM
        }
      }),

    verify: (password: string, hash: string) =>
      Effect.gen(function* () {
        // Validate inputs
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(new Errors.HashingError({
            message: "Password must be a non-empty string"
          }))
        }

        if (!hash || typeof hash !== "string") {
          return yield* Effect.fail(new Errors.HashingError({
            message: "Hash must be a non-empty string"
          }))
        }

        const parts = hash.split("$")
        
        if (parts.length !== 4) {
          return yield* Effect.fail(new Errors.HashingError({
            message: "Invalid hash format"
          }))
        }

        const [algorithm, iterations, saltHex, hashHex] = parts

        if (algorithm !== ALGORITHM) {
          return yield* Effect.fail(new Errors.HashingError({
            message: `Unsupported algorithm: ${algorithm}`
          }))
        }

        const salt = Buffer.from(saltHex, "hex")
        const expectedHash = Buffer.from(hashHex, "hex")

        const derivedKey = yield* Effect.tryPromise({
          try: () => pbkdf2(password, salt, parseInt(iterations), KEY_LENGTH, "sha256"),
          catch: (error) => new Errors.HashingError({
            message: "Failed to verify password",
            cause: error
          })
        })

        // Use timing-safe comparison
        return crypto.timingSafeEqual(derivedKey, expectedHash)
      })
  }
}

/**
 * Backward compatibility: Default password hasher is PBKDF2
 */
export const makePasswordHasher = makePBKDF2Hasher

/**
 * Layer that provides the default PBKDF2 password hasher
 */
export const PasswordHasherLive = Context.make(PasswordHasherContext, makePBKDF2Hasher())

/**
 * Layer that provides PBKDF2 password hasher explicitly
 */
export const PBKDF2HasherLive = PasswordHasherLive
