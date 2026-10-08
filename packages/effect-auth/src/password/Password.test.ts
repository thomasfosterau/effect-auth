import { describe, it, expect } from "vite-plus/test";
import { Context, Effect } from "effect";
import { PasswordHasher, scryptHasher } from "./Password.ts";
import * as Password from "./Password.ts";

describe("PasswordHasher", () => {
  const hasher = Password.pbkdf2Hasher({ iterations: 1000 });

  it("should hash a password", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
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
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    const verifyResult = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hashResult.hash),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    expect(verifyResult).toBe(true);
  });

  it("should reject an incorrect password", async () => {
    const hashResult = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    const verifyResult = await Effect.runPromise(
      Effect.provide(
        hasher.verify("wrongPassword", hashResult.hash),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    expect(verifyResult).toBe(false);
  });

  it("should generate different hashes for the same password", async () => {
    const hash1 = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    const hash2 = await Effect.runPromise(
      Effect.provide(
        hasher.hash("myPassword123"),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );

    // Hashes should be different due to random salt
    expect(hash1.hash).not.toBe(hash2.hash);

    // But both should verify correctly
    const verify1 = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hash1.hash),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
      ),
    );
    const verify2 = await Effect.runPromise(
      Effect.provide(
        hasher.verify("myPassword123", hash2.hash),
        Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
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
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
      ),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("HashingError");
    }
  });

  it("should fail cleanly on malformed iterations (not a RangeError defect)", async () => {
    // A hash with a non-numeric iteration count must produce HashingError, never a thrown RangeError.
    const malformed = "pbkdf2-sha256$notanumber$aaaa$bbbb";
    const result = await Effect.runPromise(Effect.result(hasher.verify("password", malformed)));
    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("HashingError");
    }
  });

  it("should fail cleanly on negative iterations", async () => {
    const malformed = "pbkdf2-sha256$-1$aaaa$bbbb";
    const result = await Effect.runPromise(Effect.result(hasher.verify("password", malformed)));
    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("HashingError");
    }
  });

  it("should return false (not defect) for an absurdly long password in verify", async () => {
    const longPassword = "a".repeat(2000);
    const hashResult = await Effect.runPromise(hasher.hash("short-password"));
    // Should return false without running the KDF, not throw or defect.
    const result = await Effect.runPromise(hasher.verify(longPassword, hashResult.hash));
    expect(result).toBe(false);
  });

  it("needsRehash returns false for a current hash and true for an old one", async () => {
    // The default count on purpose: this test is about which hashes the
    // production hasher flags for upgrade. Pinned structurally in Pbkdf2Defaults.test.ts.
    const h = Password.pbkdf2Hasher();
    const current = await Effect.runPromise(h.hash("pw"));
    expect(h.needsRehash!(current.hash)).toBe(false);

    // Simulate a hash produced with old params (210000 iterations, 64-byte key).
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("pw"),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" },
      keyMaterial,
      64 * 8,
    );
    const oldKey = Buffer.from(bits);
    const oldHash = `pbkdf2-sha256$210000$${Buffer.from(salt).toString("hex")}$${oldKey.toString("hex")}`;
    expect(h.needsRehash!(oldHash)).toBe(true);

    // Old hash must still verify correctly (uses stored key length).
    const valid = await Effect.runPromise(h.verify("pw", oldHash));
    expect(valid).toBe(true);
  });
});

describe("ScryptHasher", () => {
  it("should hash and verify a password", async () => {
    const { scryptHasher } = await import("./Password.ts");
    // A cheap explicit cost: this test is about the round trip, not the cost,
    // and the default N = 2^17 (128 MiB per derivation) times out on a loaded
    // machine (#270). ScryptDefaults.test.ts pins the defaults structurally.
    const scrypt = scryptHasher({ cost: 1024 });

    const hashed = await Effect.runPromise(scrypt.hash("mySecurePassword123"));
    expect(hashed.algorithm).toBe("scrypt");
    expect(hashed.hash.startsWith("scrypt$")).toBe(true);

    const valid = await Effect.runPromise(scrypt.verify("mySecurePassword123", hashed.hash));
    expect(valid).toBe(true);

    const invalid = await Effect.runPromise(scrypt.verify("wrongPassword", hashed.hash));
    expect(invalid).toBe(false);
  });

  it("should produce different hashes for the same password (random salt)", async () => {
    const { scryptHasher } = await import("./Password.ts");
    const scrypt = scryptHasher({ cost: 1024 });

    const h1 = await Effect.runPromise(scrypt.hash("samePassword"));
    const h2 = await Effect.runPromise(scrypt.hash("samePassword"));
    expect(h1.hash).not.toBe(h2.hash);
  });

  it("should verify hashes produced with non-default parameters", async () => {
    const { scryptHasher } = await import("./Password.ts");
    const weak = scryptHasher({ cost: 1024, blockSize: 8, parallelization: 1 });
    const strong = scryptHasher();

    // Parameters are stored in the hash, so a default-config hasher verifies them.
    const hashed = await Effect.runPromise(weak.hash("migrating-password"));
    const valid = await Effect.runPromise(strong.verify("migrating-password", hashed.hash));
    expect(valid).toBe(true);
  });

  it("should hash and verify when p + 2 exceeds N (maxmem covers 128 * r * (N + p + 2))", async () => {
    const { scryptHasher } = await import("./Password.ts");
    // N = 4, r = 8, p = 8 needs 14336 bytes of scrypt memory; the former
    // 256 * N * r formula allowed 8192, so both hashing and verifying failed.
    const scrypt = scryptHasher({ cost: 4, blockSize: 8, parallelization: 8 });

    const hashed = await Effect.runPromise(scrypt.hash("small-n-large-p"));
    expect(hashed.hash.startsWith("scrypt$4$8$8$")).toBe(true);

    expect(await Effect.runPromise(scrypt.verify("small-n-large-p", hashed.hash))).toBe(true);
    expect(await Effect.runPromise(scrypt.verify("wrong-password", hashed.hash))).toBe(false);
  });

  it("should interop with the multi-algorithm verifier", async () => {
    const { scryptHasher, pbkdf2Hasher, multiAlgorithmVerifier } = await import("./Password.ts");
    const verifier = multiAlgorithmVerifier([
      pbkdf2Hasher({ iterations: 1000 }),
      scryptHasher({ cost: 1024 }),
    ]);

    const scryptHash = await Effect.runPromise(scryptHasher({ cost: 1024 }).hash("pw-one"));
    const pbkdf2Hash = await Effect.runPromise(pbkdf2Hasher({ iterations: 1000 }).hash("pw-two"));

    expect(await Effect.runPromise(verifier.verify("pw-one", scryptHash.hash))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("pw-two", pbkdf2Hash.hash))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("nope", scryptHash.hash))).toBe(false);
  });

  it("should fail on malformed scrypt hash", async () => {
    const { scryptHasher } = await import("./Password.ts");
    const scrypt = scryptHasher();

    const result = await Effect.runPromise(Effect.result(scrypt.verify("password", "scrypt$bad")));
    expect(result._tag).toBe("Failure");
  });

  it("routes PHC-format (leading `$`) hashes by their second segment", async () => {
    const { multiAlgorithmVerifier } = await import("./Password.ts");
    // A stand-in PHC hasher (e.g. Argon2) whose hashes begin with `$argon2id$`.
    const phcHasher = {
      algorithm: "argon2id",
      hash: () =>
        Effect.succeed({ hash: "$argon2id$v=19$m=1,t=1,p=1$abc$def", algorithm: "argon2id" }),
      verify: (password: string) => Effect.succeed(password === "right"),
    };
    const verifier = multiAlgorithmVerifier([phcHasher]);
    const phc = "$argon2id$v=19$m=1,t=1,p=1$abc$def";
    expect(await Effect.runPromise(verifier.verify("right", phc))).toBe(true);
    expect(await Effect.runPromise(verifier.verify("wrong", phc))).toBe(false);
  });
});

describe("scrypt stored parameter limits", () => {
  // A stored hash with the given N, r and p. The salt and key are placeholders:
  // verify must refuse the parameters before it derives anything.
  const stored = (N: string, r: string, p: string) =>
    `scrypt$${N}$${r}$${p}$${"00".repeat(16)}$${"00".repeat(64)}`;

  // Sets that would make an unguarded verify run a huge KDF (p = 1000000,
  // N * r above the memory cap) are tested in ScryptDefaults.test.ts against a
  // stubbed crypto.scrypt, so a regression fails on an assertion, not a timeout.
  const refused: ReadonlyArray<readonly [label: string, hash: string]> = [
    ["N not a power of two", stored("3", "8", "1")],
    ["N = 0", stored("0", "8", "1")],
    ["N = 1", stored("1", "8", "1")],
    ["a non-numeric N", stored("1e3", "8", "1")],
    ["r = 0", stored("1024", "0", "1")],
    ["p = 0", stored("1024", "8", "0")],
    ["N = 2^30", stored(String(2 ** 30), "8", "1")],
    ["r above the cap", stored("1024", "1000", "1")],
  ];

  it.each(refused)(
    "refuses a stored hash with %s as a HashingError, not a defect or a boolean",
    async (_label, hash) => {
      const result = await Effect.runPromise(
        Effect.result(scryptHasher().verify("password", hash)),
      );
      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("HashingError");
      }
    },
  );

  it("refuses a parameter set Node rejects at hash time as a HashingError, not a defect", async () => {
    // N = 3 is not a power of two: hash() refuses the configuration before
    // calling Node (which would otherwise throw a RangeError synchronously).
    const result = await Effect.runPromise(
      Effect.result(scryptHasher({ cost: 3 }).hash("password")),
    );
    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("HashingError");
    }
  });

  it("refuses to hash with a configuration its own verify would refuse", async () => {
    // Node accepts blockSize 0, so without this check hash() would write
    // `scrypt$1024$0$1$…`, which verify then refuses forever (a lockout).
    const result = await Effect.runPromise(
      Effect.result(scryptHasher({ cost: 1024, blockSize: 0 }).hash("password")),
    );
    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("HashingError");
    }
  });

  it("verifies its own hashes across valid configurations", async () => {
    for (const options of [
      { cost: 1024 },
      { cost: 1024, blockSize: 1 },
      { cost: 2, blockSize: 8, parallelization: 8 },
      { cost: 1024, blockSize: 4, parallelization: 3 },
    ]) {
      const hasher = scryptHasher(options);
      const hashed = await Effect.runPromise(hasher.hash("round-trip"));
      expect(await Effect.runPromise(hasher.verify("round-trip", hashed.hash))).toBe(true);
    }
  });

  it("still verifies a stored hash with r and p at the caps", async () => {
    const hasher = scryptHasher({ cost: 1024, blockSize: 32, parallelization: 16 });
    const hashed = await Effect.runPromise(hasher.hash("at-the-caps"));
    expect(hashed.hash.startsWith("scrypt$1024$32$16$")).toBe(true);
    expect(await Effect.runPromise(scryptHasher().verify("at-the-caps", hashed.hash))).toBe(true);
  });

  it("needsRehash flags a stored r or p below the configured value and keeps a stronger one", () => {
    const hasher = scryptHasher({ cost: 1024, blockSize: 8, parallelization: 2 });
    expect(hasher.needsRehash!(stored("1024", "4", "2"))).toBe(true);
    expect(hasher.needsRehash!(stored("1024", "8", "1"))).toBe(true);
    expect(hasher.needsRehash!(stored("1024", "8", "2"))).toBe(false);
    expect(hasher.needsRehash!(stored("1024", "16", "4"))).toBe(false);
  });

  it("needsRehash flags a stored hash that verify would refuse", () => {
    const hasher = scryptHasher({ cost: 1024 });
    for (const [, hash] of refused) {
      expect(hasher.needsRehash!(hash)).toBe(true);
    }
  });
});

describe("PBKDF2 iterations option", () => {
  it("round-trips at a configured count and verify reads the stored count", async () => {
    // The real KDF at a cheap count: the round trip is the point, not the cost.
    // Pbkdf2Defaults.test.ts pins the default (600,000) structurally.
    const hashed = await Effect.runPromise(
      Password.pbkdf2Hasher({ iterations: 1000 }).hash("pw-cheap"),
    );
    expect(hashed.hash.startsWith("pbkdf2-sha256$1000$")).toBe(true);

    const same = Password.pbkdf2Hasher({ iterations: 1000 });
    expect(await Effect.runPromise(same.verify("pw-cheap", hashed.hash))).toBe(true);
    expect(await Effect.runPromise(same.verify("wrong", hashed.hash))).toBe(false);

    // A hasher configured for a different count still verifies the stored count.
    const other = Password.pbkdf2Hasher({ iterations: 2000 });
    expect(await Effect.runPromise(other.verify("pw-cheap", hashed.hash))).toBe(true);
  });
});
