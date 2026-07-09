import { describe, it, expect } from "vite-plus/test";
import { Context, Effect } from "effect";
import { PasswordHasher, makePBKDF2Hasher, makeMultiAlgorithmVerifier } from "./Password.js";

// Mock hasher for testing multi-algorithm support
const makeMockBcryptHasher = (): typeof PasswordHasher.Service => ({
  algorithm: "bcrypt",
  hash: (password: string) =>
    Effect.succeed({
      hash: `bcrypt$12$mockSalt$${Buffer.from(password).toString("base64")}`,
      algorithm: "bcrypt",
    }),
  verify: (password: string, hash: string) =>
    Effect.sync(() => {
      const expectedHash = `bcrypt$12$mockSalt$${Buffer.from(password).toString("base64")}`;
      return hash === expectedHash;
    }),
});

describe("Multi-Algorithm Password Hashing", () => {
  describe("makePBKDF2Hasher", () => {
    it("should include algorithm identifier", () => {
      const hasher = makePBKDF2Hasher();
      expect(hasher.algorithm).toBe("pbkdf2-sha256");
    });

    it("should hash password with algorithm in PHC format", async () => {
      const hasher = makePBKDF2Hasher();
      const result = await Effect.runPromise(
        Effect.provide(hasher.hash("test123"), Context.make(PasswordHasher, makePBKDF2Hasher())),
      );

      expect(result.hash).toMatch(/^pbkdf2-sha256\$/);
      expect(result.algorithm).toBe("pbkdf2-sha256");
    });
  });

  describe("makeMultiAlgorithmVerifier", () => {
    it("should verify password with correct algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with PBKDF2
      const pbkdf2Hash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("password123"),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("password123", pbkdf2Hash.hash),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      expect(isValid).toBe(true);
    });

    it("should verify password with different algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with mock bcrypt
      const bcryptHash = await Effect.runPromise(
        Effect.provide(
          bcryptHasher.hash("password123"),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("password123", bcryptHash.hash),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      expect(isValid).toBe(true);
    });

    it("should reject wrong password regardless of algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with PBKDF2
      const hash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("correctPassword"),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      // Try to verify with wrong password
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("wrongPassword", hash.hash),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      expect(isValid).toBe(false);
    });

    it("should fail with unsupported algorithm", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher]);

      // Try to verify a hash from an unsupported algorithm
      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            verifier.verify("password", "argon2$someParams$hash"),
            Context.make(PasswordHasher, makePBKDF2Hasher()),
          ),
        ),
      );

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("HashingError");
        expect(result.failure.message).toContain("Unsupported algorithm");
        expect(result.failure.message).toContain("argon2");
      }
    });

    it("should support migration between algorithms", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Simulate old user with bcrypt hash
      const oldHash = await Effect.runPromise(
        Effect.provide(
          bcryptHasher.hash("oldPassword"),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      // New user with PBKDF2 hash
      const newHash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("newPassword"),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      // Both should verify correctly
      const oldValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("oldPassword", oldHash.hash),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );
      const newValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("newPassword", newHash.hash),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      );

      expect(oldValid).toBe(true);
      expect(newValid).toBe(true);
    });

    it("should handle invalid hash format", async () => {
      const pbkdf2Hasher = makePBKDF2Hasher();
      const verifier = makeMultiAlgorithmVerifier([pbkdf2Hasher]);

      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            verifier.verify("password", "invalidhash"),
            Context.make(PasswordHasher, makePBKDF2Hasher()),
          ),
        ),
      );

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("HashingError");
      }
    });
  });
});
