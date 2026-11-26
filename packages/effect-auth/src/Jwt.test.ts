import { assert, describe, it, expect, beforeEach, beforeAll } from "vite-plus/test";
import { testCryptoContext, type TestCryptoServices } from "./testing/TestCrypto.ts";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import type * as Scope from "effect/Scope";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { FetchHttpClient, HttpClient, HttpClientResponse } from "effect/http";
import { Jwk, Jwt as JoseJwt } from "effect/jose";
import {
  generateKeyPair,
  JwtKeyStore,
  type GeneratedJwtKeyPair,
  type JwtConfig,
  type JwtKeyPair,
} from "./Jwt.ts";
import * as Jwt from "./Jwt.ts";
import * as Cipher from "./Cipher.ts";
import * as RootSecret from "./RootSecret.ts";
import { testJwsKeyPair, testSignJws } from "./testing/TestJws.ts";
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
/** The protected header of a compact JWS or JWE. */
const jweHeader = (token: string) =>
  decodeJsonObject(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8"));

const keyPairs: JwtKeyPair[] = [];

/** A generated pair as a store row for verification only: its private key is never read. */
const verifyOnly = (pair: GeneratedJwtKeyPair): JwtKeyPair => ({ ...pair, privateKey: "" });

const jwtKeyStore = {
  getActive: Effect.sync(() => Arr.last(keyPairs)),

  create: (pair: JwtKeyPair) =>
    Effect.sync(() => {
      keyPairs.push(pair);
      return pair;
    }),

  list: Effect.sync(() => [...keyPairs]),
};

const storeContext = Context.merge(Context.make(JwtKeyStore, jwtKeyStore), testCryptoContext());

const user: User = {
  id: "user-1",
  createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
  updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
  // `email` is not a first-class `User` field (login handles are `Identifier`
  // records), so the claim source for `definePayload` lives in `attributes`.
  attributes: { email: "jwt@example.com" },
};

const baseConfig: JwtConfig = {
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
};

const run = <A, E>(program: Effect.Effect<A, E, JwtKeyStore | TestCryptoServices>) =>
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
    expect(result.signed.expiresAt).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
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

  it("signs access tokens with the at+jwt type", async () => {
    const token = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return (yield* service.sign(user)).token;
      }),
    );
    const [header] = jwsSegments(token.split("."));
    expect(decodeJsonObject(Buffer.from(header, "base64url").toString("utf8"))["typ"]).toBe(
      "at+jwt",
    );
  });

  it("refuses an id_token signed with the same keys", async () => {
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({ issuer: baseConfig.issuer });
        const { token } = yield* service.signIdToken({
          iss: baseConfig.issuer,
          sub: user.id,
          aud: "client-1",
        });
        return yield* Effect.result(service.verify(token));
      }),
    );

    assert(Result.isFailure(result));
    expect(result.failure.message).toContain("Token type");
  });

  it("refuses a token with no typ or another typ, and accepts application/at+jwt", async () => {
    const results = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const pair = yield* generateKeyPair("ES256");
        keyPairs.push(verifyOnly(pair));
        const signingKey = yield* Jwk.importPrivate(pair.privateKey, pair.algorithm);
        const now = Math.floor(DateTime.toEpochMillis(DateTime.nowUnsafe()) / 1000);
        const claims = {
          iss: baseConfig.issuer,
          aud: "https://api.example.com",
          sub: "u",
          exp: now + 60,
        };
        const forge = (typ: string | undefined) =>
          Effect.map(
            JoseJwt.sign(Schema.Json, claims, signingKey, {
              kid: pair.id,
              ...(typ !== undefined && { typ }),
            }),
            Redacted.value,
          );
        return yield* Effect.forEach(
          [undefined, "JWT", "id_token+jwt", "Application/AT+JWT"],
          (typ) => Effect.flatMap(forge(typ), (token) => Effect.result(service.verify(token))),
          { concurrency: 1 },
        );
      }),
    );

    expect(results.map(Result.isSuccess)).toEqual([false, false, false, true]);
  });

  it("signs an id_token with exactly its claims, never definePayload or the audience", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
          ...baseConfig,
          definePayload: () => ({ roles: ["admin"] }),
        });
        const { token } = yield* service.signIdToken({
          iss: "https://oidc.example.com",
          sub: user.id,
          aud: "client-1",
          nonce: "n",
        });
        const [header, body] = jwsSegments(token.split("."));
        return {
          header: decodeJsonObject(Buffer.from(header, "base64url").toString("utf8")),
          body: decodeJsonObject(Buffer.from(body, "base64url").toString("utf8")),
        };
      }),
    );

    expect(payload.header["typ"]).toBe("JWT");
    expect(R.keys(payload.body).toSorted()).toEqual(["aud", "exp", "iat", "iss", "nonce", "sub"]);
    expect(payload.body["aud"]).toBe("client-1");
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
        const ed25519 = yield* generateKeyPair("EdDSA").pipe(Effect.map(verifyOnly));
        const store = yield* JwtKeyStore;
        yield* store.create(ed25519);

        const service = yield* Jwt.make(baseConfig);
        return yield* service.getJwks;
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

    expect(jwks.keys.find((key) => key.alg === "ES256")).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(jwks.keys.find((key) => key.alg === "EdDSA")).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
    });
  });

  it("should verify tokens signed by an older key via kid lookup", async () => {
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);

        // Rotate: a new key becomes active, the old one stays in the store
        const rotated = yield* generateKeyPair("ES256").pipe(Effect.map(verifyOnly));
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
        const pastNbf = Math.floor((yield* Clock.currentTimeMillis) / 1000) - 60; // 1 minute ago
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
        const futureNbf = Math.floor((yield* Clock.currentTimeMillis) / 1000) + 3600; // 1 hour ahead
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
        const nearFutureNbf = Math.floor((yield* Clock.currentTimeMillis) / 1000) + 2;
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
        const farFutureNbf = Math.floor((yield* Clock.currentTimeMillis) / 1000) + 10;
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
    expect(result.signed.expiresAt).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
    expect(result.payload["sub"]).toBe("user-1");
    expect(result.payload["iss"]).toBe("https://auth.example.com");

    // The stored private key is a compact JWE bound to the key id
    const stored = keyPairs[0];
    assert(stored !== undefined, "a key pair is stored");
    expect(stored.privateKey.split(".")).toHaveLength(5);
    expect(jweHeader(stored.privateKey)).toMatchObject({
      alg: "dir",
      enc: "A256GCM",
      kid: stored.id,
    });
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
    expect(keyPairs[0]?.privateKey).not.toContain("PRIVATE KEY");
  });

  it("should sign and verify with a custom { cipher }", async () => {
    const result = await run(
      Effect.gen(function* () {
        const cipher = yield* Cipher.aes256GcmCipher("custom-cipher-secret");
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
    expect(keyPairs[0]?.privateKey).not.toContain("PRIVATE KEY");
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
    // Verification uses the public key (plaintext), not the private key, so the
    // encrypted private key in the store does not need to be decrypted here.
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
          ...baseConfig,
          encryptPrivateKey: { secret: Redacted.make("test-encryption-secret-32-bytes!!") },
        });

        const { token } = yield* service.sign(user);

        // Rotate: new unencrypted key becomes active in the store
        const rotated = yield* generateKeyPair("ES256").pipe(Effect.map(verifyOnly));
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

describe("JwtService — stored private keys", () => {
  beforeEach(() => {
    keyPairs.splice(0, keyPairs.length);
  });

  const decodePublicJwk = Schema.decodeUnknownSync(Jwk.PublicJwk);

  /** A row as written before the JWE format: a plaintext PKCS#8 PEM. */
  const pemRow = (id: string): JwtKeyPair => {
    const { publicKeyJwk, privateKeyPem } = testJwsKeyPair("ES256");
    return {
      id,
      algorithm: "ES256",
      publicKey: decodePublicJwk(publicKeyJwk),
      privateKey: privateKeyPem,
      createdAt: 0,
    };
  };

  it("signs with a key stored as plaintext PEM before the JWE format", async () => {
    keyPairs.push(pemRow("legacy-pem"));
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);
        expect(jweHeader(token)["kid"]).toBe("legacy-pem");
        return yield* service.verify(token);
      }),
    );
    expect(payload["sub"]).toBe("user-1");
  });

  it("signs with a key sealed as v2 under the root secret", async () => {
    const row = pemRow("legacy-v2");
    const sealed = await run(
      Effect.gen(function* () {
        const sealer = yield* RootSecret.sealerFor("jwt-private-key", undefined);
        return yield* sealer.seal(row.privateKey, row.id);
      }),
    );
    expect(sealed.startsWith(Cipher.SEALED_PREFIX)).toBe(true);
    keyPairs.push({ ...row, privateKey: sealed });
    const payload = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return yield* service.verify((yield* service.sign(user)).token);
      }),
    );
    expect(payload["sub"]).toBe("user-1");
  });

  it("refuses a JWE moved to another key id", async () => {
    await run(
      Effect.gen(function* () {
        yield* (yield* Jwt.make(baseConfig)).sign(user);
      }),
    );
    const original = keyPairs[0];
    assert(original !== undefined, "a key pair is stored");
    keyPairs.splice(0, 1, { ...original, id: "moved" });

    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return yield* Effect.result(service.sign(user));
      }),
    );
    assert(Result.isFailure(result));
    expect(result.failure.message).toBe("Failed to decrypt the private key");
  });

  it("refuses a JWE under another root secret", async () => {
    await run(
      Effect.gen(function* () {
        yield* (yield* Jwt.make(baseConfig)).sign(user);
      }),
    );
    const result = await run(
      Effect.gen(function* () {
        const service = yield* Jwt.make({
          ...baseConfig,
          encryptPrivateKey: { secret: Redacted.make("another-secret-of-at-least-32-bytes") },
        });
        return yield* Effect.result(service.sign(user));
      }),
    );
    assert(Result.isFailure(result));
    expect(result.failure.message).toBe("Failed to decrypt the private key");
  });
});

const b64 = (value: Schema.Json) => Buffer.from(encodeJson(value)).toString("base64url");

const rsaClaims = () => ({
  iss: baseConfig.issuer,
  sub: "rsa-user",
  exp: Math.floor(DateTime.toEpochMillis(DateTime.nowUnsafe()) / 1000) + 300,
});

describe("RemoteJwksVerifier", () => {
  // Isolated key store so beforeEach on the shared store doesn't interfere.
  const remotePairs: JwtKeyPair[] = [];
  const remoteStore = {
    getActive: Effect.sync(() => Arr.last(remotePairs)),
    create: (pair: JwtKeyPair) =>
      Effect.sync(() => {
        remotePairs.push(pair);
        return pair;
      }),
    list: Effect.sync(() => [...remotePairs]),
  };
  const remoteContext = Context.merge(Context.make(JwtKeyStore, remoteStore), testCryptoContext());
  const runRemote = <A, E>(program: Effect.Effect<A, E, JwtKeyStore | TestCryptoServices>) =>
    Effect.runPromise(Effect.provide(program, remoteContext));

  // A third-party issuer signing with RS256, which JwtService never does.
  const rsa = testJwsKeyPair("RS256");
  const rsaJwks = { keys: [{ ...rsa.publicKeyJwk, kid: "rsa-1", alg: "RS256", use: "sig" }] };
  const rsaSigned = (
    claims: Schema.JsonObject,
    header: Schema.JsonObject = { alg: "RS256", kid: "rsa-1", typ: "at+jwt" },
  ): string => {
    const input = `${b64(header)}.${b64(claims)}`;
    const signature = testSignJws("RS256", Buffer.from(input), rsa.privateKeyPem);
    return `${input}.${Buffer.from(signature).toString("base64url")}`;
  };

  const jwksUrl = "https://issuer.test/.well-known/jwks.json";
  const rsaJwksUrl = "https://issuer.test/rsa/jwks.json";
  let jwks: Jwt.Jwks = { keys: [] };
  let signedToken: string;
  const requested: string[] = [];

  /** An issuer answering the two JWKS URLs, recording each request. */
  const issuerClient = HttpClient.make((request) =>
    Effect.sync(() => {
      requested.push(request.url);
      const body = request.url === rsaJwksUrl ? rsaJwks : request.url === jwksUrl ? jwks : null;
      return HttpClientResponse.fromWeb(
        request,
        new Response(encodeJson(body), {
          status: body === null ? 404 : 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }),
  );

  /** Run a program that builds a verifier over {@link issuerClient}. */
  const runVerifier = <A, E>(
    program: Effect.Effect<A, E, HttpClient.HttpClient | Scope.Scope | TestCryptoServices>,
  ) =>
    Effect.runPromise(
      program.pipe(
        Effect.scoped,
        Effect.provideService(HttpClient.HttpClient, issuerClient),
        Effect.provide(testCryptoContext()),
      ),
    );

  const verifyWithTokenType = (
    tokenType: string | null | undefined,
    issuer: string,
    token: string,
  ) =>
    runVerifier(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: rsaJwksUrl,
            issuer,
            ...(tokenType !== undefined && { tokenType }),
          });
          return yield* verifier.verify(token);
        }),
      ),
    );

  beforeAll(async () => {
    // Sign a token to trigger lazy key-pair creation in the remote store.
    signedToken = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user);
        return token;
      }),
    );

    // The JWKS the issuer serves.
    jwks = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return yield* service.getJwks;
      }),
    );
  });

  it("should verify a valid JWT against the remote JWKS", async () => {
    const payload = await runVerifier(
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

    const result = await runVerifier(
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

    const result = await runVerifier(
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

  it("fetches once for a burst of forged kids, and keeps verifying real ones", async () => {
    const [hdr, pay, sig] = jwsSegments(signedToken.split("."));
    const parsedHeader = decodeJsonObject(Buffer.from(hdr, "base64url").toString("utf8"));
    const forged = (kid: string) =>
      `${Buffer.from(encodeJson({ ...parsedHeader, kid })).toString("base64url")}.${pay}.${sig}`;
    requested.splice(0, requested.length);

    const subject = await runVerifier(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: jwksUrl,
          issuer: baseConfig.issuer,
        });
        yield* Effect.forEach(
          Arr.makeBy(20, (i) => forged(`forged-${i}`)),
          (token) => Effect.flip(verifier.verify(token)),
          { concurrency: 1 },
        );
        return (yield* verifier.verify(signedToken))["sub"];
      }),
    );

    expect(subject).toBe("user-1");
    expect(requested).toEqual([jwksUrl]);
  });

  it("asks fetch not to follow a redirect from the JWKS URL", async () => {
    const redirectModes: Array<string | undefined> = [];
    const recordingClient = HttpClient.make((request, _url, _signal, fiber) => {
      const init = Context.getOption(fiber.context, FetchHttpClient.RequestInit);
      redirectModes.push(Option.isSome(init) ? init.value.redirect : undefined);
      return issuerClient.execute(request);
    });

    await Effect.runPromise(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: rsaJwksUrl,
          issuer: baseConfig.issuer,
        });
        return yield* verifier.verify(rsaSigned(rsaClaims()));
      }).pipe(
        Effect.scoped,
        Effect.provideService(HttpClient.HttpClient, recordingClient),
        Effect.provide(testCryptoContext()),
      ),
    );

    expect(redirectModes).toEqual(["manual"]);
  });

  it("should reject a token with a future nbf via the remote verifier", async () => {
    const futureNbfToken = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        const { token } = yield* service.sign(user, {
          nbf: Math.floor((yield* Clock.currentTimeMillis) / 1000) + 3600,
        });
        return token;
      }),
    );

    const result = await runVerifier(
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
    requested.splice(0, requested.length);
    // Two verify calls on the same verifier instance should both succeed;
    // internal caching means only one network request was made.
    const results = await runVerifier(
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
    expect(requested).toEqual([jwksUrl]);
  });

  it("refuses an id_token signed with the published keys", async () => {
    const idToken = await runRemote(
      Effect.gen(function* () {
        const service = yield* Jwt.make(baseConfig);
        return (yield* service.signIdToken({
          iss: baseConfig.issuer,
          sub: user.id,
          aud: "client-1",
        })).token;
      }),
    );
    const result = await runVerifier(
      Effect.result(
        Effect.gen(function* () {
          const verifier = yield* Jwt.remoteJwksVerifier({
            jwksUri: jwksUrl,
            issuer: baseConfig.issuer,
          });
          return yield* verifier.verify(idToken);
        }),
      ),
    );

    assert(Result.isFailure(result));
    expect(result.failure.message).toContain("Token type");
  });

  it("checks no typ with tokenType null, and still checks the issuer", async () => {
    const untyped = { alg: "RS256", kid: "rsa-1" };
    const token = rsaSigned(rsaClaims(), untyped);
    const refused = await verifyWithTokenType(undefined, baseConfig.issuer, token);
    assert(Result.isFailure(refused));
    expect(refused.failure.message).toContain("Token type");

    const accepted = await verifyWithTokenType(null, baseConfig.issuer, token);
    assert(Result.isSuccess(accepted));
    expect(accepted.success["sub"]).toBe("rsa-user");

    const wrongIssuer = await verifyWithTokenType(null, "https://wrong-issuer.example.com", token);
    assert(Result.isFailure(wrongIssuer));
  });

  it("should reject an issuer mismatch via the remote verifier", async () => {
    const result = await runVerifier(
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

  it("verifies an RS256 token from a third-party issuer", async () => {
    const payload = await runVerifier(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: rsaJwksUrl,
          issuer: baseConfig.issuer,
        });
        return yield* verifier.verify(rsaSigned(rsaClaims()));
      }),
    );
    expect(payload["sub"]).toBe("rsa-user");
  });

  it("refuses an algorithm left out of `algorithms`", async () => {
    const result = await runVerifier(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: rsaJwksUrl,
          issuer: baseConfig.issuer,
          algorithms: ["ES256", "EdDSA"],
        });
        return yield* Effect.result(verifier.verify(rsaSigned(rsaClaims())));
      }),
    );
    assert(Result.isFailure(result));
    expect(result.failure.message).toBe("Token algorithm does not match the signing key");
  });

  it("refuses a token without `exp`", async () => {
    const { exp: _, ...claims } = rsaClaims();
    const result = await runVerifier(
      Effect.gen(function* () {
        const verifier = yield* Jwt.remoteJwksVerifier({
          jwksUri: rsaJwksUrl,
          issuer: baseConfig.issuer,
        });
        return yield* Effect.result(verifier.verify(rsaSigned(claims)));
      }),
    );
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("JwtError");
  });

  it("RemoteJwksVerifier.layer refuses a JWKS URL that is not HTTPS", async () => {
    const exit = await Effect.runPromiseExit(
      Effect.service(Jwt.RemoteJwksVerifier).pipe(
        Effect.provide(
          Jwt.RemoteJwksVerifier.layer({
            jwksUri: "http://issuer.test/.well-known/jwks.json",
            issuer: baseConfig.issuer,
          }),
        ),
      ),
    );
    expect(exit._tag).toBe("Failure");
  });

  it("RemoteJwksVerifier.layerHttpClient fetches through the HttpClient it is given", async () => {
    requested.splice(0, requested.length);
    const payload = await Effect.runPromise(
      Effect.gen(function* () {
        const verifier = yield* Jwt.RemoteJwksVerifier;
        return yield* verifier.verify(rsaSigned(rsaClaims()));
      }).pipe(
        Effect.provide(
          Jwt.RemoteJwksVerifier.layerHttpClient({
            jwksUri: rsaJwksUrl,
            issuer: baseConfig.issuer,
          }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, issuerClient))),
        ),
      ),
    );
    expect(payload["sub"]).toBe("rsa-user");
    expect(requested).toEqual([rsaJwksUrl]);
  });
});
