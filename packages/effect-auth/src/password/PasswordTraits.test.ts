import { describe, it, expect } from "vite-plus/test";
import { Context, Effect } from "effect";
import { PasswordHasher } from "./Password.ts";
import * as Password from "./Password.ts";

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
  describe("Password.pbkdf2Hasher", () => {
    it("should include algorithm identifier", () => {
      const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      expect(hasher.algorithm).toBe("pbkdf2-sha256");
    });

    it("should hash password with algorithm in PHC format", async () => {
      const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const result = await Effect.runPromise(
        Effect.provide(
          hasher.hash("test123"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      expect(result.hash).toMatch(/^pbkdf2-sha256\$/);
      expect(result.algorithm).toBe("pbkdf2-sha256");
    });
  });

  describe("Password.multiAlgorithmVerifier", () => {
    it("should verify password with correct algorithm", async () => {
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with PBKDF2
      const pbkdf2Hash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("password123"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("password123", pbkdf2Hash.hash),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      expect(isValid).toBe(true);
    });

    it("should verify password with different algorithm", async () => {
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with mock bcrypt
      const bcryptHash = await Effect.runPromise(
        Effect.provide(
          bcryptHasher.hash("password123"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      // Verify with multi-algorithm verifier
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("password123", bcryptHash.hash),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      expect(isValid).toBe(true);
    });

    it("should reject wrong password regardless of algorithm", async () => {
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Hash with PBKDF2
      const hash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("correctPassword"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      // Try to verify with wrong password
      const isValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("wrongPassword", hash.hash),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      expect(isValid).toBe(false);
    });

    it("should fail with unsupported algorithm", async () => {
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher]);

      // Try to verify a hash from an unsupported algorithm
      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            verifier.verify("password", "argon2$someParams$hash"),
            Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
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
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const bcryptHasher = makeMockBcryptHasher();
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher, bcryptHasher]);

      // Simulate old user with bcrypt hash
      const oldHash = await Effect.runPromise(
        Effect.provide(
          bcryptHasher.hash("oldPassword"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      // New user with PBKDF2 hash
      const newHash = await Effect.runPromise(
        Effect.provide(
          pbkdf2Hasher.hash("newPassword"),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      // Both should verify correctly
      const oldValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("oldPassword", oldHash.hash),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );
      const newValid = await Effect.runPromise(
        Effect.provide(
          verifier.verify("newPassword", newHash.hash),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      );

      expect(oldValid).toBe(true);
      expect(newValid).toBe(true);
    });

    it("should handle invalid hash format", async () => {
      const pbkdf2Hasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const verifier = Password.multiAlgorithmVerifier([pbkdf2Hasher]);

      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            verifier.verify("password", "invalidhash"),
            Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
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
