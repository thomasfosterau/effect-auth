import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import {
  generateKeyPair,
  JwtKeyStore,
  makeJwtService,
  type JwtConfig,
  type JwtKeyPair,
} from "./Jwt.js";
import { makeAes256GcmCipher } from "./Cipher.js";
import type { User } from "./Types.js";

const keyPairs: JwtKeyPair[] = [];

const jwtKeyStore = {
  getActive: () => Effect.sync(() => keyPairs[keyPairs.length - 1] ?? null),

  create: (pair: JwtKeyPair) =>
    Effect.sync(() => {
      keyPairs.push(pair);
      return pair;
    }),

  list: () => Effect.sync(() => [...keyPairs]),
};

const storeContext = Context.make(JwtKeyStore, jwtKeyStore);

const user: User = {
  id: "user-1",
  email: "jwt@example.com",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  attributes: {},
};

const baseConfig: JwtConfig = {
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
};

const run = <A, E>(program: Effect.Effect<A, E, JwtKeyStore>) =>
  Effect.runPromise(Effect.provide(program, storeContext));

describe("JwtService", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should sign and verify a token with ES256", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({ ...baseConfig, algorithm: "ES256" });
        const signed = yield* service.sign(user);
        const payload = yield* service.verify(signed.token);
        return { signed, payload };
      }),
    );

    expect(result.signed.token.split(".")).toHaveLength(3);
    expect(result.signed.expiresAt).toBeGreaterThan(Date.now());
    expect(result.payload["sub"]).toBe("user-1");
    expect(result.payload["iss"]).toBe("https://auth.example.com");
    expect(result.payload["aud"]).toBe("https://api.example.com");
    expect(typeof result.payload["iat"]).toBe("number");
    expect(typeof result.payload["exp"]).toBe("number");
  });

  it("should sign and verify a token with EdDSA", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({ ...baseConfig, algorithm: "EdDSA" });
        const signed = yield* service.sign(user);
        const payload = yield* service.verify(signed.token);
        return { signed, payload };
      }),
    );

    expect(result.payload["sub"]).toBe("user-1");
    expect(keyPairs[0]?.algorithm).toBe("EdDSA");
  });

  it("should lazily create a key pair on first sign", async () => {
    expect(keyPairs).toHaveLength(0);

    await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService(baseConfig);
        yield* service.sign(user);
        yield* service.sign(user);
      }),
    );

    // A single pair is created and then reused
    expect(keyPairs).toHaveLength(1);
    expect(keyPairs[0]?.algorithm).toBe("ES256");
  });

  it("should reject tampered tokens", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService(baseConfig);
        const { token } = yield* service.sign(user);

        const [header, payload, signature] = token.split(".") as [string, string, string];
        const forgedPayload = Buffer.from(
          JSON.stringify({
            ...(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
              string,
              unknown
            >),
            sub: "attacker",
          }),
          "utf8",
        ).toString("base64url");

        return yield* Effect.result(service.verify(`${header}.${forgedPayload}.${signature}`));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("JwtError");
      expect(result.failure.message).toContain("signature");
    }
  });

  it("should reject malformed tokens", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService(baseConfig);
        return yield* Effect.result(service.verify("not-a-jwt"));
      }),
    );
    expect(result._tag).toBe("Failure");
  });

  it("should reject expired tokens", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({ ...baseConfig, expiresIn: -1000 });
        const { token } = yield* service.sign(user);
        return yield* Effect.result(service.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("JwtError");
      expect(result.failure.message).toContain("expired");
    }
  });

  it("should reject tokens from a different issuer", async () => {
    const result = await run(
      Effect.gen(function* () {
        // Both services share the same key store, so the signature checks
        // out — only the issuer claim differs.
        const signer = yield* makeJwtService({ issuer: "https://other.example.com" });
        const verifier = yield* makeJwtService(baseConfig);
        const { token } = yield* signer.sign(user);
        return yield* Effect.result(verifier.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("JwtError");
      expect(result.failure.message).toContain("issuer");
    }
  });

  it("should reject tokens with the wrong audience", async () => {
    const result = await run(
      Effect.gen(function* () {
        const signer = yield* makeJwtService({
          issuer: baseConfig.issuer,
          audience: "https://elsewhere.example.com",
        });
        const verifier = yield* makeJwtService(baseConfig);
        const { token } = yield* signer.sign(user);
        return yield* Effect.result(verifier.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("JwtError");
      expect(result.failure.message).toContain("audience");
    }
  });

  it("should include definePayload and extra claims", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          definePayload: (u) => ({ email: u.email, plan: "pro" }),
        });
        const { token } = yield* service.sign(user, { role: "admin" });
        return yield* service.verify(token);
      }),
    );

    expect(payload["email"]).toBe("jwt@example.com");
    expect(payload["plan"]).toBe("pro");
    expect(payload["role"]).toBe("admin");
  });

  it("should use a custom subject when configured", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          getSubject: (u) => `urn:users:${u.id}`,
        });
        const { token } = yield* service.sign(user);
        return yield* service.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("urn:users:user-1");
  });

  it("should expose public keys via JWKS without private material", async () => {
    const jwks = await run(
      Effect.gen(function* () {
        const es256 = yield* makeJwtService({ ...baseConfig, algorithm: "ES256" });
        yield* es256.sign(user);
        const ed25519 = yield* generateKeyPair("EdDSA");
        const store = yield* JwtKeyStore;
        yield* store.create(ed25519);

        const service = yield* makeJwtService(baseConfig);
        return yield* service.getJwks();
      }),
    );

    expect(jwks.keys).toHaveLength(2);

    for (const key of jwks.keys) {
      expect(typeof key["kid"]).toBe("string");
      expect(key["use"]).toBe("sig");
      expect(["ES256", "EdDSA"]).toContain(key["alg"]);
      // No private material in the JWKS
      expect(key["d"]).toBeUndefined();
      expect(JSON.stringify(key)).not.toContain("PRIVATE KEY");
    }

    const es256Key = jwks.keys.find((key) => key["alg"] === "ES256");
    expect(es256Key?.["kty"]).toBe("EC");
    expect(es256Key?.["crv"]).toBe("P-256");

    const edKey = jwks.keys.find((key) => key["alg"] === "EdDSA");
    expect(edKey?.["kty"]).toBe("OKP");
    expect(edKey?.["crv"]).toBe("Ed25519");
  });

  it("should verify tokens signed by an older key via kid lookup", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService(baseConfig);
        const { token } = yield* service.sign(user);

        // Rotate: a new key becomes active, the old one stays in the store
        const rotated = yield* generateKeyPair("ES256");
        const store = yield* JwtKeyStore;
        yield* store.create(rotated);

        return yield* service.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
  });
});

describe("JwtService with private key encryption", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should sign and verify with encrypted private key (ES256, { secret })", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          encryptPrivateKey: { secret: "test-encryption-secret-32-bytes!!" },
        });
        const signed = yield* service.sign(user);
        const payload = yield* service.verify(signed.token);
        return { signed, payload };
      }),
    );

    expect(result.signed.token.split(".")).toHaveLength(3);
    expect(result.signed.expiresAt).toBeGreaterThan(Date.now());
    expect(result.payload["sub"]).toBe("user-1");
    expect(result.payload["iss"]).toBe("https://auth.example.com");

    // The stored private key PEM should be ciphertext, not a PEM block
    expect(keyPairs[0]?.privateKeyPem).toBeDefined();
    expect(keyPairs[0]?.privateKeyPem).not.toContain("PRIVATE KEY");
  });

  it("should sign and verify with encrypted private key (EdDSA, { secret })", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          algorithm: "EdDSA",
          encryptPrivateKey: { secret: "test-encryption-secret-32-bytes!!" },
        });
        const signed = yield* service.sign(user);
        const payload = yield* service.verify(signed.token);
        return { payload };
      }),
    );

    expect(result.payload["sub"]).toBe("user-1");
    expect(keyPairs[0]?.algorithm).toBe("EdDSA");
    expect(keyPairs[0]?.privateKeyPem).not.toContain("PRIVATE KEY");
  });

  it("should sign and verify with a custom { cipher }", async () => {
    const cipher = makeAes256GcmCipher("custom-cipher-secret");

    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          encryptPrivateKey: { cipher },
        });
        const signed = yield* service.sign(user);
        const payload = yield* service.verify(signed.token);
        return { payload };
      }),
    );

    expect(result.payload["sub"]).toBe("user-1");
    expect(keyPairs[0]?.privateKeyPem).not.toContain("PRIVATE KEY");
  });

  it("should reuse the encrypted key across multiple sign calls", async () => {
    await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          encryptPrivateKey: { secret: "test-encryption-secret-32-bytes!!" },
        });
        yield* service.sign(user);
        yield* service.sign(user);
        yield* service.sign(user);
      }),
    );

    // Only one key pair should be generated and stored
    expect(keyPairs).toHaveLength(1);
  });

  it("should verify tokens signed with an encrypted key after key rotation", async () => {
    // Verification uses publicKeyJwk (plaintext), not privateKeyPem, so the
    // encrypted private key in the store does not need to be decrypted here.
    const result = await run(
      Effect.gen(function* () {
        const service = yield* makeJwtService({
          ...baseConfig,
          encryptPrivateKey: { secret: "test-encryption-secret-32-bytes!!" },
        });

        const { token } = yield* service.sign(user);

        // Rotate: new unencrypted key becomes active in the store
        const rotated = yield* generateKeyPair("ES256");
        const store = yield* JwtKeyStore;
        yield* store.create(rotated);

        // Verify still resolves the correct kid and uses its public key
        return yield* service.verify(token);
      }),
    );

    expect(result["sub"]).toBe("user-1");
  });
});
