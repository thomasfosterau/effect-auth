import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Clock, Context, Data, Effect, Layer, MutableHashMap, Order } from "effect";
import { type AuthenticateAttempt, Hooks } from "../Hooks.ts";
import { authenticateGate } from "../testing/AuthenticateGate.ts";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { Digest, SecureRandom } from "effect/crypto";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { base64UrlDecode, ChallengeStore, CredentialStore } from "./WebAuthn.ts";
import * as WebAuthn from "./WebAuthn.ts";
import type {
  WebAuthnChallenge,
  WebAuthnCredential,
  WebAuthnConfig,
  WebAuthnUser,
  RegistrationResponse,
} from "./WebAuthn.ts";
import {
  ChallengeNotFoundError,
  ChallengeExpiredError,
  WebAuthnVerificationError,
  CredentialNotFoundError,
  AuthError,
} from "../Errors.ts";

// Mock implementations for testing
const mockChallengeStore = {
  challenges: MutableHashMap.empty<string, WebAuthnChallenge>(),

  create: (challenge: WebAuthnChallenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge.challenge).toString("hex");
      MutableHashMap.set(mockChallengeStore.challenges, key, challenge);
      return challenge;
    }),

  get: (challenge: Uint8Array) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      return Option.getOrNull(MutableHashMap.get(mockChallengeStore.challenges, key));
    }),

  delete: (challenge: Uint8Array) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      MutableHashMap.remove(mockChallengeStore.challenges, key);
    }),
};

const mockCredentialStore = {
  credentials: MutableHashMap.empty<string, WebAuthnCredential>(),

  create: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      MutableHashMap.set(mockCredentialStore.credentials, credential.id, credential);
      return credential;
    }),

  get: (credentialId: string) =>
    Effect.sync(() =>
      Option.getOrNull(MutableHashMap.get(mockCredentialStore.credentials, credentialId)),
    ),

  getByCredentialId: (credentialId: string) =>
    Effect.sync(() =>
      Option.getOrNull(MutableHashMap.get(mockCredentialStore.credentials, credentialId)),
    ),

  update: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      MutableHashMap.set(mockCredentialStore.credentials, credential.id, credential);
      return credential;
    }),

  delete: (credentialId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(mockCredentialStore.credentials, credentialId);
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => {
      const credentials = Array.from(MutableHashMap.values(mockCredentialStore.credentials)).filter(
        (c) => c.userId === userId,
      );
      return credentials;
    }),
};

const config: WebAuthnConfig = {
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000, // 5 minutes
};

const testUser: WebAuthnUser = {
  id: "user-123",
  name: "test@example.com",
  displayName: "Test User",
};

// `Digest.layerWebCrypto` builds synchronously, from the `WebCrypto` reference.
const platformDigest = Effect.runSync(
  Effect.provide(
    Effect.gen(function* () {
      return yield* Digest.Digest;
    }),
    Digest.layerWebCrypto,
  ),
);

/** The `Hooks` a layer builds, as a value to put in a `Context`. */
const hooksOf = (layer: Layer.Layer<Hooks>): typeof Hooks.Service =>
  Effect.runSync(Effect.provide(Hooks, layer));

/** The stores and crypto every test uses, with `hooks` (no plugins by default). */
const dependenciesWith = (hooks: typeof Hooks.Service) =>
  Context.merge(
    Context.merge(
      Context.make(ChallengeStore, mockChallengeStore),
      Context.make(CredentialStore, mockCredentialStore),
    ),
    Context.merge(
      Context.merge(
        Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
        Context.make(Digest.Digest, platformDigest),
      ),
      Context.make(Hooks, hooks),
    ),
  );

const dependencies = dependenciesWith(hooksOf(Hooks.Default));

describe("WebAuthn Service", () => {
  beforeEach(() => {
    // Clear mocks before each test
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it("should generate a registration challenge", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const result = yield* service.generateRegistrationChallenge(testUser);

          expect(result.challenge).toBeInstanceOf(Uint8Array);
          expect(result.challenge.length).toBe(32); // 256 bits
          expect(result.expiresAt).toBeGreaterThan(yield* Clock.currentTimeMillis);

          // Verify challenge was stored
          expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(1);
        }),
        dependencies,
      ),
    );
  });

  it("should generate unique challenges", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const result1 = yield* service.generateRegistrationChallenge(testUser);
          const result2 = yield* service.generateRegistrationChallenge(testUser);

          expect(result1.challenge).not.toEqual(result2.challenge);
          expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(2);
        }),
        dependencies,
      ),
    );
  });

  it("should generate an authentication challenge", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const result = yield* service.generateAuthenticationChallenge(testUser.id);

          expect(result.challenge).toBeInstanceOf(Uint8Array);
          expect(result.challenge.length).toBe(32);
          expect(result.expiresAt).toBeGreaterThan(yield* Clock.currentTimeMillis);

          // Verify challenge was stored with userId
          const stored = Array.from(MutableHashMap.values(mockChallengeStore.challenges))[0];
          expect(stored.userId).toBe(testUser.id);
        }),
        dependencies,
      ),
    );
  });

  it("should generate a usernameless authentication challenge (no userId)", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const result = yield* service.generateAuthenticationChallenge();

          expect(result.challenge).toBeInstanceOf(Uint8Array);
          expect(result.challenge.length).toBe(32);

          // Verify challenge was stored WITHOUT userId
          const stored = Array.from(MutableHashMap.values(mockChallengeStore.challenges))[0];
          expect(stored.userId).toBeUndefined();
        }),
        dependencies,
      ),
    );
  });

  it("should fail to verify with expired challenge", async () => {
    const expiredConfig: WebAuthnConfig = {
      ...config,
      challengeExpiresIn: -1000, // Expired 1 second ago
    };

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(expiredConfig);
          const { challenge } = yield* service.generateRegistrationChallenge(testUser);

          // Try to verify with expired challenge
          const mockResponse: RegistrationResponse = {
            credentialId: globalThis.crypto.getRandomValues(new Uint8Array(16)),
            attestationObject: new Uint8Array([]),
            clientDataJSON: new Uint8Array([]),
          };

          yield* service.verifyRegistration(testUser.id, challenge, mockResponse);
        }),
        dependencies,
      ).pipe(Effect.flip),
    );

    expect(result).toBeInstanceOf(ChallengeExpiredError);
  });

  it("should fail to verify with non-existent challenge", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const fakeChallenge = globalThis.crypto.getRandomValues(new Uint8Array(32));

          const mockResponse: RegistrationResponse = {
            credentialId: globalThis.crypto.getRandomValues(new Uint8Array(16)),
            attestationObject: new Uint8Array([]),
            clientDataJSON: new Uint8Array([]),
          };

          yield* service.verifyRegistration(testUser.id, fakeChallenge, mockResponse);
        }),
        dependencies,
      ).pipe(Effect.flip),
    );

    expect(result).toBeInstanceOf(ChallengeNotFoundError);
  });

  it("should handle base64url encoding/decoding", () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 255, 254, 253]);
    const encoded = Buffer.from(original)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it("should handle challenge cleanup after expiration", async () => {
    const expiredConfig: WebAuthnConfig = {
      ...config,
      challengeExpiresIn: -1000,
    };

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(expiredConfig);
          const { challenge } = yield* service.generateRegistrationChallenge(testUser);

          expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(1);

          // Try to verify with expired challenge - should fail
          const mockResponse: RegistrationResponse = {
            credentialId: globalThis.crypto.getRandomValues(new Uint8Array(16)),
            attestationObject: new Uint8Array([]),
            clientDataJSON: new Uint8Array([]),
          };

          // Expect this to fail with ChallengeExpiredError
          const result = yield* Effect.flip(
            service.verifyRegistration(testUser.id, challenge, mockResponse),
          );

          expect(result).toBeInstanceOf(ChallengeExpiredError);
          // Challenge should be deleted after expiration check
          expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(0);
        }),
        dependencies,
      ),
    );
  });

  it("should store credential with correct user ID", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          yield* service.generateRegistrationChallenge(testUser);

          // Create a mock credential
          const mockCredential: WebAuthnCredential = {
            id: "test-credential-id",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7, // ES256
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };

          yield* mockCredentialStore.create(mockCredential);

          const stored = yield* mockCredentialStore.get("test-credential-id");
          expect(stored?.userId).toBe(testUser.id);
        }),
        dependencies,
      ),
    );
  });

  it("should support multiple credentials per user", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const credentials: WebAuthnCredential[] = [
            {
              id: "cred-1",
              userId: testUser.id,
              publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
              algorithm: -7,
              counter: 0,
              createdAt: yield* Clock.currentTimeMillis,
            },
            {
              id: "cred-2",
              userId: testUser.id,
              publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
              algorithm: -7,
              counter: 0,
              createdAt: yield* Clock.currentTimeMillis,
            },
          ];

          yield* Effect.forEach(credentials, (cred) => mockCredentialStore.create(cred), {
            concurrency: 1,
            discard: true,
          });

          const userCredentials = yield* mockCredentialStore.listByUserId(testUser.id);
          expect(userCredentials.length).toBe(2);
        }),
        dependencies,
      ),
    );
  });

  it("should update credential counter", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const mockCredential: WebAuthnCredential = {
            id: "test-cred",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 5,
            createdAt: yield* Clock.currentTimeMillis,
          };

          yield* mockCredentialStore.create(mockCredential);

          const updated = { ...mockCredential, counter: 6 };
          yield* mockCredentialStore.update(updated);

          const retrieved = yield* mockCredentialStore.get("test-cred");
          expect(retrieved?.counter).toBe(6);
        }),
        dependencies,
      ),
    );
  });

  it("advertises ES256, RS256, and EdDSA in the registration challenge", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make({ ...config, residentKey: "required" });
          const result = yield* service.generateRegistrationChallenge(testUser);
          return result;
        }),
        dependencies,
      ),
    );
    expect(result.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -257, -8]);
    expect(result.authenticatorSelection).toEqual({
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "preferred",
    });
    expect(result.excludeCredentials).toEqual([]);
  });

  // --- Credential management tests ------------------------------------------

  it("listCredentials returns all passkeys for a user", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);

          // Pre-populate two credentials for testUser and one for another user.
          const cred1: WebAuthnCredential = {
            id: "cred-a",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          const cred2: WebAuthnCredential = {
            id: "cred-b",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          const other: WebAuthnCredential = {
            id: "cred-c",
            userId: "other-user",
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* mockCredentialStore.create(cred1);
          yield* mockCredentialStore.create(cred2);
          yield* mockCredentialStore.create(other);

          const list = yield* service.listCredentials(testUser.id);
          expect(list.length).toBe(2);
          expect(
            Arr.sort(
              list.map((c) => c.id),
              Order.String,
            ),
          ).toEqual(["cred-a", "cred-b"]);
        }),
        dependencies,
      ),
    );
  });

  it("deleteCredential removes the passkey when the owner calls it", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const cred: WebAuthnCredential = {
            id: "del-cred",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* mockCredentialStore.create(cred);

          yield* service.deleteCredential(testUser.id, cred.id);

          const after = yield* mockCredentialStore.get(cred.id);
          expect(after).toBeNull();
        }),
        dependencies,
      ),
    );
  });

  it("deleteCredential fails with CredentialNotFoundError for an unknown id", async () => {
    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          return yield* Effect.flip(service.deleteCredential(testUser.id, "nonexistent"));
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(CredentialNotFoundError);
  });

  it("deleteCredential fails with AuthError when another user tries to delete", async () => {
    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const cred: WebAuthnCredential = {
            id: "other-owned",
            userId: "owner-user",
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* mockCredentialStore.create(cred);

          return yield* Effect.flip(service.deleteCredential(testUser.id, cred.id));
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(AuthError);
  });

  it("renameCredential updates the name when the owner calls it", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const cred: WebAuthnCredential = {
            id: "rename-cred",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* mockCredentialStore.create(cred);

          const updated = yield* service.renameCredential(testUser.id, cred.id, "My YubiKey");
          expect(updated.name).toBe("My YubiKey");

          const stored = yield* mockCredentialStore.get(cred.id);
          expect(stored?.name).toBe("My YubiKey");
        }),
        dependencies,
      ),
    );
  });

  it("renameCredential fails with AuthError when another user tries to rename", async () => {
    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const cred: WebAuthnCredential = {
            id: "rename-protected",
            userId: "owner-user",
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: yield* Clock.currentTimeMillis,
          };
          yield* mockCredentialStore.create(cred);

          return yield* Effect.flip(service.renameCredential(testUser.id, cred.id, "Hijacked"));
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(AuthError);
  });
});

// --- Multi-algorithm registration + authentication round trips ---------------

/** Minimal deterministic CBOR encoder (enough for COSE keys + attestation). */
const cborHead = (major: number, n: number): number[] => {
  const type = major << 5;
  if (n < 24) return [type | n];
  if (n < 256) return [type | 24, n];
  if (n < 65536) return [type | 25, (n >> 8) & 0xff, n & 0xff];
  return [type | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
};
const cborUint = (n: number): number[] => cborHead(0, n);
const cborNegInt = (n: number): number[] => cborHead(1, -1 - n);
const cborBytes = (b: Uint8Array): number[] => [...cborHead(2, b.length), ...b];
const cborText = (s: string): number[] => {
  const b = Buffer.from(s, "utf8");
  return [...cborHead(3, b.length), ...b];
};
const cborMap = (entries: ReadonlyArray<readonly [number[], number[]]>): number[] => {
  return [...cborHead(5, entries.length), ...Arr.flatMap(entries, ([k, v]) => [...k, ...v])];
};

const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  Arr.reduce(arrays, 0, (offset, a) => {
    out.set(a, offset);
    return offset + a.length;
  });
  return out;
};

type Alg = -7 | -257 | -8;

const keyGenParams = (alg: Alg) =>
  alg === -7
    ? { name: "ECDSA", namedCurve: "P-256" }
    : alg === -257
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : { name: "Ed25519" };

// The public JWK members each key type exports.
const Ec2Jwk = Schema.Struct({ x: Schema.String, y: Schema.String });
const RsaJwk = Schema.Struct({ n: Schema.String, e: Schema.String });
const OkpJwk = Schema.Struct({ x: Schema.String });

/**
 * Generate a keypair and its COSE-key CBOR bytes for the given algorithm.
 * `algorithmLabel` overrides the advertised COSE `alg` value, for tests that
 * need a key labelled with an algorithm effect-auth does not support, and
 * `curve` the advertised EC2 `crv` (P-256, 1, by default).
 */
const buildKey = async (
  alg: Alg,
  algorithmLabel: number = alg,
  curve = 1,
): Promise<{ privateKey: CryptoKey; cose: number[] }> => {
  const keyPair = await globalThis.crypto.subtle.generateKey(keyGenParams(alg), true, [
    "sign",
    "verify",
  ]);
  // Every algorithm `keyGenParams` names is asymmetric, so the result is a pair.
  assert("privateKey" in keyPair, `${alg} generates a key pair`);
  const { publicKey, privateKey } = keyPair;

  if (alg === -7) {
    const jwk = Schema.decodeUnknownSync(Ec2Jwk)(
      await globalThis.crypto.subtle.exportKey("jwk", publicKey),
    );
    const x = new Uint8Array(Buffer.from(jwk.x, "base64url"));
    const y = new Uint8Array(Buffer.from(jwk.y, "base64url"));
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(2)],
        [cborUint(3), cborNegInt(algorithmLabel)],
        [cborNegInt(-1), cborUint(curve)],
        [cborNegInt(-2), cborBytes(x)],
        [cborNegInt(-3), cborBytes(y)],
      ]),
    };
  }
  if (alg === -257) {
    const jwk = Schema.decodeUnknownSync(RsaJwk)(
      await globalThis.crypto.subtle.exportKey("jwk", publicKey),
    );
    const n = new Uint8Array(Buffer.from(jwk.n, "base64url"));
    const e = new Uint8Array(Buffer.from(jwk.e, "base64url"));
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(3)],
        [cborUint(3), cborNegInt(algorithmLabel)],
        [cborNegInt(-1), cborBytes(n)],
        [cborNegInt(-2), cborBytes(e)],
      ]),
    };
  }
  const jwk = Schema.decodeUnknownSync(OkpJwk)(
    await globalThis.crypto.subtle.exportKey("jwk", publicKey),
  );
  const x = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  return {
    privateKey,
    cose: cborMap([
      [cborUint(1), cborUint(1)],
      [cborUint(3), cborNegInt(algorithmLabel)],
      [cborNegInt(-1), cborUint(6)],
      [cborNegInt(-2), cborBytes(x)],
    ]),
  };
};

/** SHA-256 of the relying party id, memoized since it never changes. */
let rpIdHashCache: Uint8Array | undefined;
const getRpIdHash = async (): Promise<Uint8Array> => {
  if (rpIdHashCache === undefined) {
    rpIdHashCache = new Uint8Array(
      await globalThis.crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(config.relyingPartyId),
      ),
    );
  }
  return rpIdHashCache;
};

/** `signAssertion` rejected; a test-setup failure, surfaced as a defect. */
class SignAssertionError extends Data.TaggedError("SignAssertionError")<{
  readonly cause: unknown;
}> {}

const encodeClientDataJSON = Schema.encodeSync(
  Schema.fromJsonString(
    Schema.Struct({
      type: Schema.String,
      challenge: Schema.String,
      origin: Schema.String,
      crossOrigin: Schema.optional(Schema.Boolean),
    }),
  ),
);

const clientDataJSON = (
  type: "webauthn.create" | "webauthn.get",
  challenge: Uint8Array,
  crossOrigin?: boolean,
): Uint8Array =>
  new Uint8Array(
    Buffer.from(
      encodeClientDataJSON({
        type,
        challenge: Buffer.from(challenge).toString("base64url"),
        origin: "https://example.com",
        ...(crossOrigin === undefined ? {} : { crossOrigin }),
      }),
      "utf8",
    ),
  );

/** Authenticator-data flag bits (WebAuthn §6.1). */
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;

/**
 * Assemble a `none`-format attestation object embedding the COSE key, with the
 * authenticator-data `flags` (UP | UV | AT by default).
 */
const attestationObject = async (
  cose: number[],
  credentialId: Uint8Array,
  flags = UP | UV | AT,
): Promise<Uint8Array> => {
  const acd = concatBytes(
    new Uint8Array(16), // aaguid
    new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
    credentialId,
    new Uint8Array(cose),
  );
  const authData = concatBytes(
    await getRpIdHash(),
    new Uint8Array([flags]),
    new Uint8Array([0, 0, 0, 0]), // counter 0
    acd,
  );
  return new Uint8Array(
    cborMap([
      [cborText("fmt"), cborText("none")],
      [cborText("attStmt"), cborMap([])],
      [cborText("authData"), cborBytes(authData)],
    ]),
  );
};

const signCounter = (counter: number): Uint8Array =>
  new Uint8Array([
    (counter >>> 24) & 0xff,
    (counter >>> 16) & 0xff,
    (counter >>> 8) & 0xff,
    counter & 0xff,
  ]);

/**
 * DER-encode an unsigned big-endian integer (adds a leading 0x00 if the high
 * bit is set, so it isn't misread as negative).
 */
const derInteger = (bytes: Uint8Array): Uint8Array => {
  const firstNonZero = bytes.findIndex((b) => b !== 0);
  const start = Math.max(0, firstNonZero === -1 ? bytes.length - 1 : firstNonZero);
  const trimmed = bytes.subarray(start);
  const needsPad = ((trimmed[0] ?? 0) & 0x80) !== 0;
  const content = needsPad ? concatBytes(new Uint8Array([0]), trimmed) : trimmed;
  return concatBytes(new Uint8Array([0x02, content.length]), content);
};

/**
 * Real WebAuthn authenticators emit DER-encoded ECDSA signatures (which is
 * what `WebAuthn.ts` verifies against). Web Crypto's ECDSA `sign` emits raw
 * IEEE-P1363 `r || s`, so convert P-256 signatures (64 bytes: r[32] || s[32]).
 */
const p1363ToDer = (signature: Uint8Array): Uint8Array => {
  const r = derInteger(signature.subarray(0, 32));
  const s = derInteger(signature.subarray(32, 64));
  const body = concatBytes(r, s);
  return concatBytes(new Uint8Array([0x30, body.length]), body);
};

const signAssertion = async (
  alg: Alg,
  privateKey: CryptoKey,
  authenticatorData: Uint8Array,
  clientData: Uint8Array,
): Promise<Uint8Array> => {
  const clientDataHash = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(clientData),
  );
  const message = concatBytes(authenticatorData, new Uint8Array(clientDataHash));
  // ES256/RS256 hash with SHA-256; Ed25519 hashes internally.
  const signature = await globalThis.crypto.subtle.sign(
    alg === -8 ? "Ed25519" : alg === -7 ? { name: "ECDSA", hash: "SHA-256" } : "RSASSA-PKCS1-v1_5",
    privateKey,
    new Uint8Array(message),
  );
  // ES256 (Web Crypto emits raw r||s; authenticators/WebAuthn.ts expect DER).
  return alg === -7 ? p1363ToDer(new Uint8Array(signature)) : new Uint8Array(signature);
};

describe.each<{ name: string; alg: Alg }>([
  { name: "ES256", alg: -7 },
  { name: "RS256", alg: -257 },
  { name: "EdDSA", alg: -8 },
])("WebAuthn $name round trip", ({ alg }) => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it("registers a credential and verifies an assertion", async () => {
    const { privateKey, cose } = await buildKey(alg);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);
    const rpIdHash = await getRpIdHash();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);

          // Registration.
          const reg = yield* service.generateRegistrationChallenge(testUser);
          const registration = yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });
          expect(registration.credential.algorithm).toBe(alg);
          expect(registration.userVerified).toBe(true);

          // Authentication with a fresh (incremented) counter.
          const auth = yield* service.generateAuthenticationChallenge(testUser.id);
          const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
          const clientData = clientDataJSON("webauthn.get", auth.challenge);
          const signature = yield* Effect.tryPromise({
            try: () => signAssertion(alg, privateKey, authenticatorData, clientData),
            catch: (cause) => new SignAssertionError({ cause }),
          }).pipe(Effect.orDie);
          const result = yield* service.verifyAuthentication(auth.challenge, {
            credentialId,
            authenticatorData,
            clientDataJSON: clientData,
            signature,
          });
          expect(result.newCounter).toBe(1);
          return result;
        }),
        dependencies,
      ),
    );
  });

  it("rejects an assertion signed by the wrong key", async () => {
    const { cose } = await buildKey(alg);
    const wrong = await buildKey(alg);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);
    const rpIdHash = await getRpIdHash();

    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const reg = yield* service.generateRegistrationChallenge(testUser);
          yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });

          const auth = yield* service.generateAuthenticationChallenge(testUser.id);
          const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
          const clientData = clientDataJSON("webauthn.get", auth.challenge);
          // Sign with an unrelated private key.
          const signature = yield* Effect.tryPromise({
            try: () => signAssertion(alg, wrong.privateKey, authenticatorData, clientData),
            catch: (cause) => new SignAssertionError({ cause }),
          }).pipe(Effect.orDie);
          return yield* Effect.flip(
            service.verifyAuthentication(auth.challenge, {
              credentialId,
              authenticatorData,
              clientDataJSON: clientData,
              signature,
            }),
          );
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
  });

  it("completes a usernameless (discoverable) register+login round trip", async () => {
    const { privateKey, cose } = await buildKey(alg);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);
    const rpIdHash = await getRpIdHash();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);

          // Registration (bound challenge — userId known at registration time).
          const reg = yield* service.generateRegistrationChallenge(testUser);
          const registration = yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });
          expect(registration.credential.userId).toBe(testUser.id);

          // Usernameless authentication — no userId passed.
          const auth = yield* service.generateAuthenticationChallenge();
          const storedChallenge = Array.from(
            MutableHashMap.values(mockChallengeStore.challenges),
          )[0];
          expect(storedChallenge?.userId).toBeUndefined();

          const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
          const clientData = clientDataJSON("webauthn.get", auth.challenge);
          const signature = yield* Effect.tryPromise({
            try: () => signAssertion(alg, privateKey, authenticatorData, clientData),
            catch: (cause) => new SignAssertionError({ cause }),
          }).pipe(Effect.orDie);
          const result = yield* service.verifyAuthentication(auth.challenge, {
            credentialId,
            authenticatorData,
            clientDataJSON: clientData,
            signature,
          });

          // The service resolves the user from the stored credential.
          expect(result.credential.userId).toBe(testUser.id);
          expect(result.newCounter).toBe(1);
        }),
        dependencies,
      ),
    );
  });

  it("rejects a usernameless assertion when the credential is from a different user", async () => {
    const { cose } = await buildKey(alg);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);
    const rpIdHash = await getRpIdHash();
    const otherKey = await buildKey(alg);

    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);

          // Register under testUser, then try a bound challenge for a DIFFERENT user.
          const reg = yield* service.generateRegistrationChallenge(testUser);
          yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });

          // Bound challenge for a different user.
          const auth = yield* service.generateAuthenticationChallenge("other-user-999");
          const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
          const clientData = clientDataJSON("webauthn.get", auth.challenge);
          const signature = yield* Effect.tryPromise({
            try: () => signAssertion(alg, otherKey.privateKey, authenticatorData, clientData),
            catch: (cause) => new SignAssertionError({ cause }),
          }).pipe(Effect.orDie);
          return yield* Effect.flip(
            service.verifyAuthentication(auth.challenge, {
              credentialId,
              authenticatorData,
              clientDataJSON: clientData,
              signature,
            }),
          );
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
  });
});

describe("WebAuthn algorithm support", () => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it("rejects registration of a credential using an unsupported COSE algorithm", async () => {
    // A P-256 key advertised as ES384 (-35), which effect-auth does not support.
    const { cose } = await buildKey(-7, -35);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const reg = yield* service.generateRegistrationChallenge(testUser);
          return yield* Effect.flip(
            service.verifyRegistration(testUser.id, reg.challenge, {
              credentialId,
              attestationObject: attestationObj,
              clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
            }),
          );
        }),
        dependencies,
      ),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toContain("Unsupported algorithm: -35");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
  });

  it("rejects a registration whose attestation object is not valid CBOR", async () => {
    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const reg = yield* service.generateRegistrationChallenge(testUser);
          return yield* Effect.flip(
            service.verifyRegistration(testUser.id, reg.challenge, {
              credentialId: globalThis.crypto.getRandomValues(new Uint8Array(20)),
              attestationObject: new Uint8Array([0xff, 0xff, 0xff]),
              clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
            }),
          );
        }),
        dependencies,
      ),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Failed to parse attestation object");
  });

  it("rejects an assertion whose authenticator data is truncated", async () => {
    const { privateKey, cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const reg = yield* service.generateRegistrationChallenge(testUser);
          yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });

          const auth = yield* service.generateAuthenticationChallenge(testUser.id);
          const authenticatorData = new Uint8Array(36); // one byte short of the minimum
          const clientData = clientDataJSON("webauthn.get", auth.challenge);
          const signature = yield* Effect.tryPromise({
            try: () => signAssertion(-7, privateKey, authenticatorData, clientData),
            catch: (cause) => new SignAssertionError({ cause }),
          }).pipe(Effect.orDie);
          return yield* Effect.flip(
            service.verifyAuthentication(auth.challenge, {
              credentialId,
              authenticatorData,
              clientDataJSON: clientData,
              signature,
            }),
          );
        }),
        dependencies,
      ),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Failed to parse authenticator data");
  });
});
// --- Ceremony binding, user verification and the stored credential (#591) ----

/** Run `program` over a fresh service with `overrides` on the shared config. */
const withService = <A, E>(
  program: (service: typeof WebAuthn.WebAuthnService.Service) => Effect.Effect<A, E>,
  overrides: Partial<WebAuthnConfig> = {},
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.flatMap(WebAuthn.make({ ...config, ...overrides }), program),
      dependencies,
    ),
  );

/** A signed assertion over `challenge` with authenticator-data `flags`. */
const assertion = (
  privateKey: CryptoKey,
  credentialId: Uint8Array,
  challenge: Uint8Array,
  options: { readonly flags?: number | undefined; readonly counter?: number | undefined } = {},
) =>
  Effect.gen(function* () {
    const rpIdHash = yield* Effect.tryPromise({
      try: getRpIdHash,
      catch: (cause) => new SignAssertionError({ cause }),
    });
    const authenticatorData = concatBytes(
      rpIdHash,
      new Uint8Array([options.flags ?? UP | UV]),
      signCounter(options.counter ?? 1),
    );
    const clientData = clientDataJSON("webauthn.get", challenge);
    const signature = yield* Effect.tryPromise({
      try: () => signAssertion(-7, privateKey, authenticatorData, clientData),
      catch: (cause) => new SignAssertionError({ cause }),
    });
    return { credentialId, authenticatorData, clientDataJSON: clientData, signature };
  }).pipe(Effect.orDie);

describe("WebAuthn ceremony binding (#591)", () => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it("refuses an authentication challenge redeemed as a registration, and keeps it", async () => {
    // The attack: a login challenge bound to the victim, answered with an
    // attestation over the attacker's own key.
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const login = yield* service.generateAuthenticationChallenge(testUser.id);
        return yield* Effect.flip(
          service.verifyRegistration(testUser.id, login.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", login.challenge),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Challenge was issued for authentication, not registration");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
    expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(1);
  });

  it("refuses a registration challenge redeemed as an authentication", async () => {
    const { privateKey, cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        yield* service.verifyRegistration(testUser.id, reg.challenge, {
          credentialId,
          attestationObject: attestationObj,
          clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
        });
        const second = yield* service.generateRegistrationChallenge(testUser);
        const response = yield* assertion(privateKey, credentialId, second.challenge);
        return yield* Effect.flip(service.verifyAuthentication(second.challenge, response));
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Challenge was issued for registration, not authentication");
  });

  it("files the credential under the signed-in user only on that user's challenge", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* Effect.flip(
          service.verifyRegistration("attacker-456", reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Challenge was not issued to this user");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
  });

  it("refuses a cross-origin ceremony", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* Effect.flip(
          service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge, true),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Cross-origin ceremonies are not accepted");
  });
});

describe("WebAuthn user verification (#591)", () => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it('refuses a registration without UV when userVerification is "required"', async () => {
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId, UP | AT);

    const err = await withService(
      (service) =>
        Effect.gen(function* () {
          const reg = yield* service.generateRegistrationChallenge(testUser);
          expect(reg.authenticatorSelection.userVerification).toBe("required");
          return yield* Effect.flip(
            service.verifyRegistration(testUser.id, reg.challenge, {
              credentialId,
              attestationObject: attestationObj,
              clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
            }),
          );
        }),
      { userVerification: "required" },
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("User verification is required");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
  });

  it('refuses an assertion without UV when userVerification is "required"', async () => {
    const { privateKey, cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService(
      (service) =>
        Effect.gen(function* () {
          const reg = yield* service.generateRegistrationChallenge(testUser);
          yield* service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });
          const login = yield* service.generateAuthenticationChallenge(testUser.id);
          const response = yield* assertion(privateKey, credentialId, login.challenge, {
            flags: UP,
          });
          return yield* Effect.flip(service.verifyAuthentication(login.challenge, response));
        }),
      { userVerification: "required" },
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("User verification is required");
  });

  it('reports UV and the backup flags under "preferred"', async () => {
    const { privateKey, cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId, UP | BE | AT);

    const result = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        const registration = yield* service.verifyRegistration(testUser.id, reg.challenge, {
          credentialId,
          attestationObject: attestationObj,
          clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
        });
        const login = yield* service.generateAuthenticationChallenge();
        const response = yield* assertion(privateKey, credentialId, login.challenge, {
          flags: UP | UV | BE | BS,
        });
        const authentication = yield* service.verifyAuthentication(login.challenge, response);
        return { registration, authentication };
      }),
    );
    expect(result.registration).toMatchObject({
      userVerified: false,
      backupEligible: true,
      backupState: false,
    });
    expect(result.authentication).toMatchObject({
      userVerified: true,
      backupEligible: true,
      backupState: true,
    });
  });

  it("refuses a backup state on a credential that is not backup eligible", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId, UP | UV | BS | AT);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* Effect.flip(
          service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Backup state set on a credential that is not backup eligible");
  });
});

describe("WebAuthn registration stores the attested credential (#591)", () => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  it("refuses a response whose credential id is not the attested one", async () => {
    const { cose } = await buildKey(-7);
    const attestedId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, attestedId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* Effect.flip(
          service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId: globalThis.crypto.getRandomValues(new Uint8Array(20)),
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Credential ID does not match the attested credential");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
  });

  it("stores the credential under the attested id", async () => {
    const { cose } = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const registration = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* service.verifyRegistration(testUser.id, reg.challenge, {
          credentialId,
          attestationObject: attestationObj,
          clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
        });
      }),
    );
    expect(registration.credential.id).toBe(Buffer.from(credentialId).toString("base64url"));
    expect(
      Option.isSome(
        MutableHashMap.get(mockCredentialStore.credentials, registration.credential.id),
      ),
    ).toBe(true);
  });

  it("refuses an id already registered to another user, leaving that user's credential", async () => {
    // The attacker replays the victim's credential id with their own key: in a
    // set-style store (a Map, a KV) the create would overwrite the victim's row.
    const victimKey = await buildKey(-7);
    const attackerKey = await buildKey(-7);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const victimAttestation = await attestationObject(victimKey.cose, credentialId);
    const attackerAttestation = await attestationObject(attackerKey.cose, credentialId);
    const attacker: WebAuthnUser = { id: "attacker-456", name: "a@example.com", displayName: "A" };

    const outcome = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        const registered = yield* service.verifyRegistration(testUser.id, reg.challenge, {
          credentialId,
          attestationObject: victimAttestation,
          clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
        });
        const attackerReg = yield* service.generateRegistrationChallenge(attacker);
        const refusal = yield* Effect.flip(
          service.verifyRegistration(attacker.id, attackerReg.challenge, {
            credentialId,
            attestationObject: attackerAttestation,
            clientDataJSON: clientDataJSON("webauthn.create", attackerReg.challenge),
          }),
        );
        return { registered, refusal };
      }),
    );
    assert.instanceOf(outcome.refusal, WebAuthnVerificationError);
    expect(outcome.refusal.message).toBe("Credential is already registered");
    const stored = Option.getOrUndefined(
      MutableHashMap.get(mockCredentialStore.credentials, outcome.registered.credential.id),
    );
    expect(stored?.userId).toBe(testUser.id);
    expect(stored?.publicKey).toEqual(outcome.registered.credential.publicKey);
  });

  it("refuses an ES256 key on a curve other than P-256", async () => {
    // A P-256 key advertised on P-384 (COSE crv 2).
    const { cose } = await buildKey(-7, -7, 2);
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = await attestationObject(cose, credentialId);

    const err = await withService((service) =>
      Effect.gen(function* () {
        const reg = yield* service.generateRegistrationChallenge(testUser);
        return yield* Effect.flip(
          service.verifyRegistration(testUser.id, reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          }),
        );
      }),
    );
    assert.instanceOf(err, WebAuthnVerificationError);
    expect(err.message).toBe("Invalid credential public key");
    expect(MutableHashMap.size(mockCredentialStore.credentials)).toBe(0);
  });
});

/** A test-setup promise; a rejection is a defect. */
const setUp = <A>(promise: () => Promise<A>) =>
  Effect.tryPromise({ try: promise, catch: (cause) => new SignAssertionError({ cause }) }).pipe(
    Effect.orDie,
  );

describe("passkey sign-in runs beforeAuthenticate (#678)", () => {
  beforeEach(() => {
    MutableHashMap.clear(mockChallengeStore.challenges);
    MutableHashMap.clear(mockCredentialStore.credentials);
  });

  /** Register an ES256 passkey for the test user, then sign an assertion for a fresh challenge. */
  const registerAndAssert = Effect.fn("registerAndAssert")(function* (
    service: typeof WebAuthn.WebAuthnService.Service,
  ) {
    const { privateKey, cose } = yield* setUp(() => buildKey(-7));
    const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const attestationObj = yield* setUp(() => attestationObject(cose, credentialId));
    const rpIdHash = yield* setUp(getRpIdHash);
    const reg = yield* service.generateRegistrationChallenge(testUser);
    yield* service.verifyRegistration(testUser.id, reg.challenge, {
      credentialId,
      attestationObject: attestationObj,
      clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
    });
    const auth = yield* service.generateAuthenticationChallenge(testUser.id);
    const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
    const clientData = clientDataJSON("webauthn.get", auth.challenge);
    const signature = yield* setUp(() =>
      signAssertion(-7, privateKey, authenticatorData, clientData),
    );
    return {
      challenge: auth.challenge,
      response: { credentialId, authenticatorData, clientDataJSON: clientData, signature },
    };
  });

  it("runs the gate for the credential's user before the signature is checked", async () => {
    const seen: Array<AuthenticateAttempt> = [];
    const refused = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const { challenge, response } = yield* registerAndAssert(service);
          return yield* Effect.flip(service.verifyAuthentication(challenge, response));
        }),
        dependenciesWith(hooksOf(authenticateGate(seen, true))),
      ),
    );
    expect(refused._tag).toBe("RateLimitError");
    expect(seen).toEqual([
      {
        method: "passkey",
        identifier: { type: "user", value: testUser.id },
        userId: testUser.id,
      },
    ]);
    // Refused before anything was spent: the counter is unchanged and the
    // authentication challenge is still stored.
    const [credential] = MutableHashMap.values(mockCredentialStore.credentials);
    expect(credential?.counter).toBe(0);
    expect(MutableHashMap.size(mockChallengeStore.challenges)).toBe(1);
  });

  it("signs in through a gate that lets the attempt through", async () => {
    const seen: Array<AuthenticateAttempt> = [];
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const { challenge, response } = yield* registerAndAssert(service);
          return yield* service.verifyAuthentication(challenge, response);
        }),
        dependenciesWith(hooksOf(authenticateGate(seen, false))),
      ),
    );
    expect(result.credential.userId).toBe(testUser.id);
    expect(seen.map((attempt) => attempt.method)).toEqual(["passkey"]);
  });

  it("runs the gate unkeyed for an unknown challenge", async () => {
    const seen: Array<AuthenticateAttempt> = [];
    const refused = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          return yield* Effect.flip(
            service.verifyAuthentication(new Uint8Array(32), {
              credentialId: new Uint8Array(20),
              authenticatorData: new Uint8Array(37),
              clientDataJSON: new Uint8Array(0),
              signature: new Uint8Array(0),
            }),
          );
        }),
        dependenciesWith(hooksOf(authenticateGate(seen, true))),
      ),
    );
    // The gate's refusal wins over the not-found answer, so the per-IP limit
    // can stop a caller guessing challenges.
    expect(refused._tag).toBe("RateLimitError");
    expect(seen).toEqual([{ method: "passkey" }]);
  });
});
