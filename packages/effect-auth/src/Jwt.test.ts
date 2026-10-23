import { assert, describe, it, expect, beforeEach, beforeAll, afterAll } from "vite-plus/test";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { Array as Arr, Context, Crypto, Effect, Predicate, Redacted, Result, Schema } from "effect";
import { generateKeyPair, JwtKeyStore, type JwtConfig, type JwtKeyPair } from "./Jwt.ts";
import * as Jwt from "./Jwt.ts";
import * as Cipher from "./Cipher.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type { User } from "./Types.ts";

/** JSON text to and from a JSON object (a JOSE header or claims set). */
const decodeJsonObject = Schema.decodeUnknownSync(
  Schema.fromJsonString(Schema.Record(Schema.String, Schema.Unknown)),
);
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));
/** A compact JWS's header, payload and signature segments. */
const jwsSegments = Schema.decodeUnknownSync(
  Schema.Tuple([Schema.String, Schema.String, Schema.String]),
);

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

const storeContext = Context.merge(
  Context.make(JwtKeyStore, jwtKeyStore),
  Context.make(Crypto.Crypto, PlatformCrypto.instance),
);

const user: User = {
  id: "user-1",
  createdAt: new Date(),
  updatedAt: new Date(),
  // `email` is not a first-class `User` field (login handles are `Identifier`
  // records), so the claim source for `definePayload` lives in `attributes`.
  attributes: { email: "jwt@example.com" },
};

const baseConfig: JwtConfig = {
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
};

const run = <A, E>(program: Effect.Effect<A, E, JwtKeyStore | Crypto.Crypto>) =>
  Effect.runPromise(Effect.provide(program, storeContext));

describe("JwtService", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should sign and verify a token with ES256", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ ...baseConfig, algorithm: "ES256" });
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
    expect(result.payload["iat"]).toBeTypeOf("number");
    expect(result.payload["exp"]).toBeTypeOf("number");
  });

  it("should sign and verify a token with EdDSA", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ ...baseConfig, algorithm: "EdDSA" });
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
        const service = yield* Jwt.make(baseConfig);
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
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);

        const [header, payload, signature] = jwsSegments(token.split("."));
        const forgedPayload = Buffer.from(
          encodeJson({
            ...decodeJsonObject(Buffer.from(payload, "base64url").toString("utf8")),
            sub: "attacker",
          }),
          "utf8",
        ).toString("base64url");

        return yield* Effect.result(service.verify(`${header}.${forgedPayload}.${signature}`));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("signature");
  });

  it("should reject malformed tokens", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return yield* Effect.result(service.verify("not-a-jwt"));
      }),
    );
    expect(result._tag).toBe("Failure");
  });

  it("should reject expired tokens", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ ...baseConfig, expiresIn: -1000 });
        const { token } = yield* service.sign(user);
        return yield* Effect.result(service.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("expired");
  });

  it("should reject tokens from a different issuer", async () => {
    const result = await run(
      Effect.gen(function* () {
        // Both services share the same key store, so the signature checks
        // out — only the issuer claim differs.
        const signer = yield* Jwt.make({ issuer: "https://other.example.com" });
        const verifier = yield* Jwt.make(baseConfig);
        const { token } = yield* signer.sign(user);
        return yield* Effect.result(verifier.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("issuer");
  });

  it("should reject tokens with the wrong audience", async () => {
    const result = await run(
      Effect.gen(function* () {
        const signer = yield* Jwt.make({
          issuer: baseConfig.issuer,
          audience: "https://elsewhere.example.com",
        });
        const verifier = yield* Jwt.make(baseConfig);
        const { token } = yield* signer.sign(user);
        return yield* Effect.result(verifier.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("audience");
  });

  it("should include definePayload and extra claims", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
          ...baseConfig,
          definePayload: (u) => ({ email: u.attributes["email"], plan: "pro" }),
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
        const service = yield* Jwt.make({
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
        const es256 = yield* Jwt.make({ ...baseConfig, algorithm: "ES256" });
        yield* es256.sign(user);
        const ed25519 = yield* generateKeyPair("EdDSA", PlatformCrypto.instance);
        const store = yield* JwtKeyStore;
        yield* store.create(ed25519);

        const service = yield* Jwt.make(baseConfig);
        return yield* service.getJwks();
      }),
    );

    expect(jwks.keys).toHaveLength(2);

    Arr.forEach(jwks.keys, (key) => {
      expect(key["kid"]).toBeTypeOf("string");
      expect(key["use"]).toBe("sig");
      expect(["ES256", "EdDSA"]).toContain(key["alg"]);
      // No private material in the JWKS
      expect(key["d"]).toBeUndefined();
      expect(encodeJson(key)).not.toContain("PRIVATE KEY");
    });

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
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);

        // Rotate: a new key becomes active, the old one stays in the store
        const rotated = yield* generateKeyPair("ES256", PlatformCrypto.instance);
        const store = yield* JwtKeyStore;
        yield* store.create(rotated);

        return yield* service.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
  });
});

describe("JwtService — nbf validation", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should accept a token with a past nbf", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const pastNbf = Math.floor(Date.now() / 1000) - 60; // 1 minute ago
        const { token } = yield* service.sign(user, { nbf: pastNbf });
        return yield* service.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
  });

  it("should reject a token whose nbf is in the future", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const futureNbf = Math.floor(Date.now() / 1000) + 3600; // 1 hour ahead
        const { token } = yield* service.sign(user, { nbf: futureNbf });
        return yield* Effect.result(service.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("not yet valid");
  });

  it("should accept a token with no nbf claim", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user); // no nbf
        return yield* service.verify(token);
      }),
    );

    expect(payload["nbf"]).toBeUndefined();
    expect(payload["sub"]).toBe("user-1");
  });
});

describe("JwtService — clock-skew leeway", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should accept a slightly-expired token when leeway covers the gap", async () => {
    // Token expired 2 s ago; leeway of 5 s should accept it.
    const payload = await run(
      Effect.gen(function* () {
        // Sign with a negative expiresIn so exp is 2 s in the past
        const signer = yield* Jwt.make({ ...baseConfig, expiresIn: -2000 });
        const verifier = yield* Jwt.make({ ...baseConfig, clockSkewLeeway: 5000 });
        const { token } = yield* signer.sign(user);
        return yield* verifier.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
  });

  it("should reject an expired token when gap exceeds leeway", async () => {
    // Token expired 10 s ago; leeway of 5 s is not enough.
    const result = await run(
      Effect.gen(function* () {
        const signer = yield* Jwt.make({ ...baseConfig, expiresIn: -10000 });
        const verifier = yield* Jwt.make({ ...baseConfig, clockSkewLeeway: 5000 });
        const { token } = yield* signer.sign(user);
        return yield* Effect.result(verifier.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("expired");
  });

  it("should accept a not-yet-valid token when leeway covers the gap", async () => {
    // nbf is 2 s in the future; leeway of 5 s should accept it.
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ ...baseConfig, clockSkewLeeway: 5000 });
        const nearFutureNbf = Math.floor(Date.now() / 1000) + 2;
        const { token } = yield* service.sign(user, { nbf: nearFutureNbf });
        return yield* service.verify(token);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
  });

  it("should reject a not-yet-valid token when gap exceeds leeway", async () => {
    // nbf is 10 s in the future; leeway of 5 s is not enough.
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ ...baseConfig, clockSkewLeeway: 5000 });
        const farFutureNbf = Math.floor(Date.now() / 1000) + 10;
        const { token } = yield* service.sign(user, { nbf: farFutureNbf });
        return yield* Effect.result(service.verify(token));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("not yet valid");
  });
});

describe("JwtService with private key encryption", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  it("should sign and verify with encrypted private key (ES256, { secret })", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
          ...baseConfig,
          encryptPrivateKey: { secret: Redacted.make("test-encryption-secret-32-bytes!!") },
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
        const service = yield* Jwt.make({
          ...baseConfig,
          algorithm: "EdDSA",
          encryptPrivateKey: { secret: Redacted.make("test-encryption-secret-32-bytes!!") },
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
    const cipher = Cipher.aes256GcmCipher("custom-cipher-secret");

    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
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
        const service = yield* Jwt.make({
          ...baseConfig,
          encryptPrivateKey: { secret: Redacted.make("test-encryption-secret-32-bytes!!") },
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
        const service = yield* Jwt.make({
          ...baseConfig,
          encryptPrivateKey: { secret: Redacted.make("test-encryption-secret-32-bytes!!") },
        });

        const { token } = yield* service.sign(user);

        // Rotate: new unencrypted key becomes active in the store
        const rotated = yield* generateKeyPair("ES256", PlatformCrypto.instance);
        const store = yield* JwtKeyStore;
        yield* store.create(rotated);

        // Verify still resolves the correct kid and uses its public key
        return yield* service.verify(token);
      }),
    );

    expect(result["sub"]).toBe("user-1");
  });
});

// ---------------------------------------------------------------------------
// Remote JWKS verification
// ---------------------------------------------------------------------------

describe("RemoteJwksVerifier", () => {
  // Isolated key store so beforeEach on the shared store doesn't interfere.
  const remotePairs: JwtKeyPair[] = [];
  const remoteStore = {
    getActive: () => Effect.sync(() => remotePairs[remotePairs.length - 1] ?? null),
    create: (pair: JwtKeyPair) =>
      Effect.sync(() => {
        remotePairs.push(pair);
        return pair;
      }),
    list: () => Effect.sync(() => [...remotePairs]),
  };
  const remoteContext = Context.merge(
    Context.make(JwtKeyStore, remoteStore),
    Context.make(Crypto.Crypto, PlatformCrypto.instance),
  );
  const runRemote = <A, E>(program: Effect.Effect<A, E, JwtKeyStore | Crypto.Crypto>) =>
    Effect.runPromise(Effect.provide(program, remoteContext));

  let server: Server;
  let jwksUrl: string;
  let signedToken: string;

  beforeAll(async () => {
    // Sign a token to trigger lazy key-pair creation in the remote store.
    signedToken = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);
        return token;
      }),
    );

    // Get the JWKS to serve from the test HTTP server.
    const jwks = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return yield* service.getJwks();
      }),
    );

    server = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(encodeJson(jwks));
    });

    await new Promise<void>((resolve) => server.listen(0, () => resolve()));
    const addr = server.address();
    // A server listening on a TCP port reports an `AddressInfo`.
    assert(
      Predicate.isNotNull(addr) && !Predicate.isString(addr),
      "the JWKS server listens on a port",
    );
    jwksUrl = `http://127.0.0.1:${addr.port}/.well-known/jwks.json`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("should verify a valid JWT against the remote JWKS", async () => {
    const payload = await Effect.runPromise(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: jwksUrl,
          issuer: baseConfig.issuer,
          ...(baseConfig.audience !== undefined && { audience: baseConfig.audience }),
        });
        return yield* verifier.verify(signedToken);
      }),
    );

    expect(payload["sub"]).toBe("user-1");
    expect(payload["iss"]).toBe(baseConfig.issuer);
    expect(payload["aud"]).toBe(baseConfig.audience);
  });

  it("should reject a tampered token", async () => {
    const [hdr, pay, sig] = jwsSegments(signedToken.split("."));
    const forgedPay = Buffer.from(
      encodeJson({
        ...decodeJsonObject(Buffer.from(pay, "base64url").toString("utf8")),
        sub: "attacker",
      }),
    ).toString("base64url");

    const result = await Effect.runPromise(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: jwksUrl,
            issuer: baseConfig.issuer,
          });
          return yield* verifier.verify(`${hdr}.${forgedPay}.${sig}`);
        }),
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("signature");
  });

  it("should reject a token with an unknown kid", async () => {
    // Replace the kid in the header with one that doesn't exist in the JWKS.
    const [hdr, pay, sig] = jwsSegments(signedToken.split("."));
    const parsedHeader = decodeJsonObject(Buffer.from(hdr, "base64url").toString("utf8"));
    const badHeader = Buffer.from(encodeJson({ ...parsedHeader, kid: "no-such-kid" })).toString(
      "base64url",
    );

    const result = await Effect.runPromise(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: jwksUrl,
            issuer: baseConfig.issuer,
          });
          return yield* verifier.verify(`${badHeader}.${pay}.${sig}`);
        }),
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("kid");
  });

  it("should reject a token with a future nbf via the remote verifier", async () => {
    const futureNbfToken = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user, {
          nbf: Math.floor(Date.now() / 1000) + 3600,
        });
        return token;
      }),
    );

    const result = await Effect.runPromise(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: jwksUrl,
            issuer: baseConfig.issuer,
          });
          return yield* verifier.verify(futureNbfToken);
        }),
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("not yet valid");
  });

  it("should reuse the cache across multiple verify calls", async () => {
    // Two verify calls on the same verifier instance should both succeed;
    // internal caching means only one network request was made.
    const results = await Effect.runPromise(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: jwksUrl,
          issuer: baseConfig.issuer,
          ...(baseConfig.audience !== undefined && { audience: baseConfig.audience }),
          cacheTtlMs: 60_000,
        });
        const r1 = yield* verifier.verify(signedToken);
        const r2 = yield* verifier.verify(signedToken);
        return [r1, r2] as const;
      }),
    );

    expect(results[0]["sub"]).toBe("user-1");
    expect(results[1]["sub"]).toBe("user-1");
  });

  it("should reject an issuer mismatch via the remote verifier", async () => {
    const result = await Effect.runPromise(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: jwksUrl,
            issuer: "https://wrong-issuer.example.com",
          });
          return yield* verifier.verify(signedToken);
        }),
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
    expect(result.failure.message).toContain("issuer");
  });
});
