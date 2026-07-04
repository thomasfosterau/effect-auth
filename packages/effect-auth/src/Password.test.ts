import { describe, it, expect } from "vite-plus/test";
import { Context, Effect } from "effect";
import { PasswordHasher, makePBKDF2Hasher } from "./Password.js";

describe("PasswordHasher", () => {
  const hasher = makePBKDF2Hasher();

  it("should hash a password", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    expect(result.hash).toBeDefined();
    expect(result.hash.length).toBeGreaterThan(0);
    expect(result.algorithm).toBe("pbkdf2-sha256");
    expect(result.hash).toContain("pbkdf2-sha256$");
  });

  it("should verify a correct password", async () => {
    const hashResult = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    const verifyResult = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hashResult.hash),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    expect(verifyResult).toBe(true);
  });

  it("should reject an incorrect password", async () => {
    const hashResult = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    const verifyResult = await Effect.runPromise(
      Effect.provide(
        hasher.verify("wrongPassword", hashResult.hash),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    expect(verifyResult).toBe(false);
  });

  it("should generate different hashes for the same password", async () => {
    const hash1 = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    const hash2 = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    // Hashes should be different due to random salt
    expect(hash1.hash).not.toBe(hash2.hash);

    // But both should verify correctly
    const verify1 = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hash1.hash),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );
    const verify2 = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hash2.hash),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    expect(verify1).toBe(true);
    expect(verify2).toBe(true);
  });

  it("should fail on invalid hash format", async () => {
    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(
          hasher.verify("password", "invalid-hash"),
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

describe("ScryptHasher", () => {
  it("should hash and verify a password", async () => {
    const { makeScryptHasher } = await import("./Password.js");
    const scrypt = makeScryptHasher();

    const hashed = await Effect.runPromise(scrypt.hash("mySecurePassword123"));
    expect(hashed.algorithm).toBe("scrypt");
    expect(hashed.hash.startsWith("scrypt$")).toBe(true);

    const valid = await Effect.runPromise(scrypt.verify("mySecurePassword123", hashed.hash));
    expect(valid).toBe(true);

    const invalid = await Effect.runPromise(scrypt.verify("wrongPassword", hashed.hash));
    expect(invalid).toBe(false);
  });

  it("should produce different hashes for the same password (random salt)", async () => {
    const { makeScryptHasher } = await import("./Password.js");
    const scrypt = makeScryptHasher({ cost: 16384 });

    const h1 = await Effect.runPromise(scrypt.hash("samePassword"));
    const h2 = await Effect.runPromise(scrypt.hash("samePassword"));
    expect(h1.hash).not.toBe(h2.hash);
  });

  it("should verify hashes produced with non-default parameters", async () => {
    const { makeScryptHasher } = await import("./Password.js");
    const weak = makeScryptHasher({ cost: 16384, blockSize: 8, parallelization: 1 });
    const strong = makeScryptHasher();

    // Parameters are stored in the hash, so a default-config hasher verifies them.
    const hashed = await Effect.runPromise(weak.hash("migrating-password"));
    const valid = await Effect.runPromise(strong.verify("migrating-password", hashed.hash));
    expect(valid).toBe(true);
  });

  it("should interop with the multi-algorithm verifier", async () => {
    const { makeScryptHasher, makePBKDF2Hasher, makeMultiAlgorithmVerifier } =
      await import("./Password.js");
    const verifier = makeMultiAlgorithmVerifier([
      makePBKDF2Hasher(),
      makeScryptHasher({ cost: 16384 }),
    ]);

    const scryptHash = await Effect.runPromise(makeScryptHasher({ cost: 16384 }).hash("pw-one"));
    const pbkdf2Hash = await Effect.runPromise(makePBKDF2Hasher().hash("pw-two"));

    expect(await Effect.runPromise(verifier.verify("pw-one", scryptHash.hash))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("pw-two", pbkdf2Hash.hash))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("nope", scryptHash.hash))).toBe(false);
  });

  it("should fail on malformed scrypt hash", async () => {
    const { makeScryptHasher } = await import("./Password.js");
    const scrypt = makeScryptHasher();

    const result = await Effect.runPromise(Effect.result(scrypt.verify("password", "scrypt$bad")));
    expect(result._tag).toBe("Failure");
  });

  it("routes PHC-format (leading `$`) hashes by their second segment", async () => {
    const { makeMultiAlgorithmVerifier } = await import("./Password.js");
    // A stand-in PHC hasher (e.g. Argon2) whose hashes begin with `$argon2id$`.
    const phcHasher = {
      algorithm: "argon2id",
      hash: () =>
        Effect.succeed({ hash: "$argon2id$v=19$m=1,t=1,p=1$abc$def", algorithm: "argon2id" }),
      verify: (password: string) => Effect.succeed(password === "right"),
    };
    const verifier = makeMultiAlgorithmVerifier([phcHasher]);
    const phc = "$argon2id$v=19$m=1,t=1,p=1$abc$def";
    expect(await Effect.runPromise(verifier.verify("right", phc))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("wrong", phc))).toBe(false);
  });
});
