import { describe, it, expect } from "vitest"
import { Effect } from "effect"
import {
  makePBKDF2Hasher,
  makeMultiAlgorithmVerifier,
  PasswordHasherLive
} from "./Password.js"
import type { PasswordHasher } from "./Password.js"
import * as Errors from "./Errors.js"

// Mock hasher for testing multi-algorithm support
const makeMockBcryptHasher = (): PasswordHasher => ({
  algorithm: "bcrypt",
  hash: (password: string) =>
    Effect.succeed({
      hash: `bcrypt$12$mockSalt$${Buffer.from(password).toString("base64")}`,
      algorithm: "bcrypt"
    }),
  verify: (password: string, hash: string) =>
    Effect.sync(() => {
      const expectedHash = `bcrypt$12$mockSalt$${Buffer.from(password).toString("base64")}`
      return hash === expectedHash
    })
})

describe("Multi-Algorithm Password Hashing", () => {
  describe("makePBKDF2Hasher", () => {
    it("should include algorithm identifier", () => {
      const hasher = makePBKDF2Hasher()
      expect(hasher.algorithm).toBe("pbkdf2-sha256")
    })

    it("should hash password with algorithm in PHC format", async () => {
      const hasher = makePBKDF2Hasher()
      const result = await Effect.runPromise(
        Effect.provide(hasher.hash("test123"), PasswordHasherLive)
      )

      expect(result.hash).toMatch(/^pbkdf2-sha256\$/)
      expect(result.algorithm).toBe("pbkdf2-sha256")
    })
  })

  describe("makeMultiAlgorithmVerifier", () => {
    it("should verify password with correct algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const bcryptHasher = makeMockBcryptHasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher])

      // Hash with PBKDF2
      const pbkdf2Hash = await Effect.runPromise(
        Effect.provide(pbkdf2Hasher.hash("password123"), PasswordHasherLive)
      )

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(verifier.verify("password123", pbkdf2Hash.hash), PasswordHasherLive)
      )

      expect(isValid).toBe(true)
    })

    it("should verify password with different algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const bcryptHasher = makeMockBcryptHasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher])

      // Hash with mock bcrypt
      const bcryptHash = await Effect.runPromise(
        Effect.provide(bcryptHasher.hash("password123"), PasswordHasherLive)
      )

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(verifier.verify("password123", bcryptHash.hash), PasswordHasherLive)
      )

      expect(isValid).toBe(true)
    })

    it("should reject wrong password regardless of algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const bcryptHasher = makeMockBcryptHasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher])

      // Hash with PBKDF2
      const hash = await Effect.runPromise(
        Effect.provide(pbkdf2Hasher.hash("correctPassword"), PasswordHasherLive)
      )

      // Try to verify with wrong password
      const isValid = await Effect.runPromise(
        Effect.provide(verifier.verify("wrongPassword", hash.hash), PasswordHasherLive)
      )

      expect(isValid).toBe(false)
    })

    it("should fail with unsupported algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher])

      // Try to verify a hash from an unsupported algorithm
      const result = await Effect.runPromise(
        Effect.either(
          Effect.provide(
            verifier.verify("password", "argon2$someParams$hash"),
            PasswordHasherLive
          )
        )
      )

      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("Unsupported algorithm")
        expect(result.left.message).toContain("argon2")
      }
    })

    it("should support migration between algorithms", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const bcryptHasher = makeMockBcryptHasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher])

      // Simulate old user with bcrypt hash
      const oldHash = await Effect.runPromise(
        Effect.provide(bcryptHasher.hash("oldPassword"), PasswordHasherLive)
      )

      // New user with PBKDF2 hash
      const newHash = await Effect.runPromise(
        Effect.provide(pbkdf2Hasher.hash("newPassword"), PasswordHasherLive)
      )

      // Both should verify correctly
      const oldValid = await Effect.runPromise(
        Effect.provide(verifier.verify("oldPassword", oldHash.hash), PasswordHasherLive)
      )
      const newValid = await Effect.runPromise(
        Effect.provide(verifier.verify("newPassword", newHash.hash), PasswordHasherLive)
      )

      expect(oldValid).toBe(true)
      expect(newValid).toBe(true)
    })

    it("should handle invalid hash format", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher()
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher])

      const result = await Effect.runPromise(
        Effect.either(
          Effect.provide(
            verifier.verify("password", "invalidhash"),
            PasswordHasherLive
          )
        )
      )

      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
      }
    })
  })
})
