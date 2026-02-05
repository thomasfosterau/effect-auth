import { Effect, Context } from "effect"
import * as crypto from "node:crypto"
import { promisify } from "node:util"
import type * as Types from "./types.js"
import * as Errors from "./errors.js"

const pbkdf2 = promisify(crypto.pbkdf2)

/**
 * Password hashing service interface
 */
export interface PasswordHasher {
  /**
   * Hash a password using a secure algorithm
   */
  readonly hash: (password: string) => Effect.Effect<Types.HashedPassword, Errors.HashingError>
  
  /**
   * Verify a password against a hash
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>
}

/**
 * Tag for PasswordHasher service
 */
export const PasswordHasher = Context.GenericTag<PasswordHasher>("@effect-auth/PasswordHasher")

/**
 * Default implementation using PBKDF2
 * Following Copenhagen/Oslo guidelines for secure password hashing
 */
export const makePasswordHasher = (): PasswordHasher => {
  const ALGORITHM = "pbkdf2-sha256"
  const ITERATIONS = 210000 // OWASP recommended minimum
  const KEY_LENGTH = 64
  const SALT_LENGTH = 16

  return {
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
 * Layer that provides the default PasswordHasher
 */
export const PasswordHasherLive = Context.make(PasswordHasher, makePasswordHasher())
