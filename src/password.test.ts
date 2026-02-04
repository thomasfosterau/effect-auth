import { describe, it, expect } from "vitest"
import { Effect } from "effect"
import { makePasswordHasher, PasswordHasherLive } from "../src/password.js"

describe("PasswordHasher", () => {
  const hasher = makePasswordHasher()

  it("should hash a password", async () => {
    const result = await Effect.runPromise(
      Effect.provide(hasher.hash("myPassword123"), PasswordHasherLive)
    )

    expect(result.hash).toBeDefined()
    expect(result.hash.length).toBeGreaterThan(0)
    expect(result.algorithm).toBe("pbkdf2-sha256")
    expect(result.hash).toContain("pbkdf2-sha256$")
  })

  it("should verify a correct password", async () => {
    const hashResult = await Effect.runPromise(
      Effect.provide(hasher.hash("myPassword123"), PasswordHasherLive)
    )

    const verifyResult = await Effect.runPromise(
      Effect.provide(hasher.verify("myPassword123", hashResult.hash), PasswordHasherLive)
    )

    expect(verifyResult).toBe(true)
  })

  it("should reject an incorrect password", async () => {
    const hashResult = await Effect.runPromise(
      Effect.provide(hasher.hash("myPassword123"), PasswordHasherLive)
    )

    const verifyResult = await Effect.runPromise(
      Effect.provide(hasher.verify("wrongPassword", hashResult.hash), PasswordHasherLive)
    )

    expect(verifyResult).toBe(false)
  })

  it("should generate different hashes for the same password", async () => {
    const hash1 = await Effect.runPromise(
      Effect.provide(hasher.hash("myPassword123"), PasswordHasherLive)
    )

    const hash2 = await Effect.runPromise(
      Effect.provide(hasher.hash("myPassword123"), PasswordHasherLive)
    )

    // Hashes should be different due to random salt
    expect(hash1.hash).not.toBe(hash2.hash)

    // But both should verify correctly
    const verify1 = await Effect.runPromise(
      Effect.provide(hasher.verify("myPassword123", hash1.hash), PasswordHasherLive)
    )
    const verify2 = await Effect.runPromise(
      Effect.provide(hasher.verify("myPassword123", hash2.hash), PasswordHasherLive)
    )

    expect(verify1).toBe(true)
    expect(verify2).toBe(true)
  })

  it("should fail on invalid hash format", async () => {
    const result = await Effect.runPromise(
      Effect.either(
        Effect.provide(hasher.verify("password", "invalid-hash"), PasswordHasherLive)
      )
    )

    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("HashingError")
    }
  })
})
