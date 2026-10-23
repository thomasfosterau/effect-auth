import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Array as Arr, Effect, Context, Crypto, Data, Order, Schema } from "effect";
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
  challenges: new Map<string, WebAuthnChallenge>(),

  create: (challenge: WebAuthnChallenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge.challenge).toString("hex");
      mockChallengeStore.challenges.set(key, challenge);
      return challenge;
    }),

  get: (challenge: Uint8Array) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      return mockChallengeStore.challenges.get(key) ?? null;
    }),

  delete: (challenge: Uint8Array) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      mockChallengeStore.challenges.delete(key);
    }),
};

const mockCredentialStore = {
  credentials: new Map<string, WebAuthnCredential>(),

  create: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.set(credential.id, credential);
      return credential;
    }),

  get: (credentialId: string) =>
    Effect.sync(() => mockCredentialStore.credentials.get(credentialId) ?? null),

  getByCredentialId: (credentialId: string) =>
    Effect.sync(() => mockCredentialStore.credentials.get(credentialId) ?? null),

  update: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.set(credential.id, credential);
      return credential;
    }),

  delete: (credentialId: string) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.delete(credentialId);
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => {
      const credentials = Array.from(mockCredentialStore.credentials.values()).filter(
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

const dependencies = Context.merge(
  Context.merge(
    Context.make(ChallengeStore, mockChallengeStore),
    Context.make(CredentialStore, mockCredentialStore),
  ),
  Context.make(Crypto.Crypto, PlatformCrypto.instance),
);

describe("WebAuthn Service", () => {
  beforeEach(() => {
    // Clear mocks before each test
    mockChallengeStore.challenges.clear();
    mockCredentialStore.credentials.clear();
  });

  it("should generate a registration challenge", async () => {
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const result = yield* service.generateRegistrationChallenge(testUser);

          expect(result.challenge).toBeInstanceOf(Uint8Array);
          expect(result.challenge.length).toBe(32); // 256 bits
          expect(result.expiresAt).toBeGreaterThan(Date.now());

          // Verify challenge was stored
          expect(mockChallengeStore.challenges.size).toBe(1);
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
          expect(mockChallengeStore.challenges.size).toBe(2);
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
          expect(result.expiresAt).toBeGreaterThan(Date.now());

          // Verify challenge was stored with userId
          const stored = Array.from(mockChallengeStore.challenges.values())[0];
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
          const stored = Array.from(mockChallengeStore.challenges.values())[0];
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

          yield* service.verifyRegistration(challenge, mockResponse);
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

          yield* service.verifyRegistration(fakeChallenge, mockResponse);
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

          expect(mockChallengeStore.challenges.size).toBe(1);

          // Try to verify with expired challenge - should fail
          const mockResponse: RegistrationResponse = {
            credentialId: globalThis.crypto.getRandomValues(new Uint8Array(16)),
            attestationObject: new Uint8Array([]),
            clientDataJSON: new Uint8Array([]),
          };

          // Expect this to fail with ChallengeExpiredError
          const result = yield* Effect.flip(service.verifyRegistration(challenge, mockResponse));

          expect(result).toBeInstanceOf(ChallengeExpiredError);
          // Challenge should be deleted after expiration check
          expect(mockChallengeStore.challenges.size).toBe(0);
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
            createdAt: Date.now(),
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
              createdAt: Date.now(),
            },
            {
              id: "cred-2",
              userId: testUser.id,
              publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
              algorithm: -7,
              counter: 0,
              createdAt: Date.now(),
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
            createdAt: Date.now(),
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
            createdAt: Date.now(),
          };
          const cred2: WebAuthnCredential = {
            id: "cred-b",
            userId: testUser.id,
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: Date.now(),
          };
          const other: WebAuthnCredential = {
            id: "cred-c",
            userId: "other-user",
            publicKey: globalThis.crypto.getRandomValues(new Uint8Array(65)),
            algorithm: -7,
            counter: 0,
            createdAt: Date.now(),
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
            createdAt: Date.now(),
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
            createdAt: Date.now(),
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
            createdAt: Date.now(),
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
            createdAt: Date.now(),
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

/**
 * Generate a keypair and its COSE-key CBOR bytes for the given algorithm.
 * `algorithmLabel` overrides the advertised COSE `alg` value, for tests that
 * need a key labelled with an algorithm effect-auth does not support.
 */
const buildKey = async (
  alg: Alg,
  algorithmLabel: number = alg,
): Promise<{ privateKey: CryptoKey; cose: number[] }> => {
  const { publicKey, privateKey } = (await globalThis.crypto.subtle.generateKey(
    keyGenParams(alg),
    true,
    ["sign", "verify"],
  )) as { publicKey: CryptoKey; privateKey: CryptoKey };

  if (alg === -7) {
    const jwk = (await globalThis.crypto.subtle.exportKey("jwk", publicKey)) as {
      x: string;
      y: string;
    };
    const x = new Uint8Array(Buffer.from(jwk.x, "base64url"));
    const y = new Uint8Array(Buffer.from(jwk.y, "base64url"));
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(2)],
        [cborUint(3), cborNegInt(algorithmLabel)],
        [cborNegInt(-1), cborUint(1)],
        [cborNegInt(-2), cborBytes(x)],
        [cborNegInt(-3), cborBytes(y)],
      ]),
    };
  }
  if (alg === -257) {
    const jwk = (await globalThis.crypto.subtle.exportKey("jwk", publicKey)) as {
      n: string;
      e: string;
    };
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
  const jwk = (await globalThis.crypto.subtle.exportKey("jwk", publicKey)) as { x: string };
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
    Schema.Struct({ type: Schema.String, challenge: Schema.String, origin: Schema.String }),
  ),
);

const clientDataJSON = (
  type: "webauthn.create" | "webauthn.get",
  challenge: Uint8Array,
): Uint8Array =>
  new Uint8Array(
    Buffer.from(
      encodeClientDataJSON({
        type,
        challenge: Buffer.from(challenge).toString("base64url"),
        origin: "https://example.com",
      }),
      "utf8",
    ),
  );

/** Assemble a `none`-format attestation object embedding the COSE key. */
const attestationObject = async (cose: number[], credentialId: Uint8Array): Promise<Uint8Array> => {
  const acd = concatBytes(
    new Uint8Array(16), // aaguid
    new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
    credentialId,
    new Uint8Array(cose),
  );
  const authData = concatBytes(
    await getRpIdHash(),
    new Uint8Array([0x45]), // UP | UV | AT
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
    clientData as NodeJS.BufferSource,
  );
  const message = concatBytes(authenticatorData, new Uint8Array(clientDataHash));
  // ES256/RS256 hash with SHA-256; Ed25519 hashes internally.
  const signature = await globalThis.crypto.subtle.sign(
    alg === -8 ? "Ed25519" : alg === -7 ? { name: "ECDSA", hash: "SHA-256" } : "RSASSA-PKCS1-v1_5",
    privateKey,
    message as NodeJS.BufferSource,
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
    mockChallengeStore.challenges.clear();
    mockCredentialStore.credentials.clear();
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
          const registration = yield* service.verifyRegistration(reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });
          expect(registration.credential.algorithm).toBe(alg);
          expect(registration.verified).toBe(true);

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
          yield* service.verifyRegistration(reg.challenge, {
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
          const registration = yield* service.verifyRegistration(reg.challenge, {
            credentialId,
            attestationObject: attestationObj,
            clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
          });
          expect(registration.credential.userId).toBe(testUser.id);

          // Usernameless authentication — no userId passed.
          const auth = yield* service.generateAuthenticationChallenge();
          const storedChallenge = Array.from(mockChallengeStore.challenges.values())[0];
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
          yield* service.verifyRegistration(reg.challenge, {
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
    mockChallengeStore.challenges.clear();
    mockCredentialStore.credentials.clear();
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
            service.verifyRegistration(reg.challenge, {
              credentialId,
              attestationObject: attestationObj,
              clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
            }),
          );
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
    expect((err as WebAuthnVerificationError).message).toContain("Unsupported algorithm: -35");
    expect(mockCredentialStore.credentials.size).toBe(0);
  });

  it("rejects a registration whose attestation object is not valid CBOR", async () => {
    const err = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* WebAuthn.make(config);
          const reg = yield* service.generateRegistrationChallenge(testUser);
          return yield* Effect.flip(
            service.verifyRegistration(reg.challenge, {
              credentialId: globalThis.crypto.getRandomValues(new Uint8Array(20)),
              attestationObject: new Uint8Array([0xff, 0xff, 0xff]),
              clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
            }),
          );
        }),
        dependencies,
      ),
    );
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
    expect((err as WebAuthnVerificationError).message).toBe("Failed to parse attestation object");
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
          yield* service.verifyRegistration(reg.challenge, {
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
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
    expect((err as WebAuthnVerificationError).message).toBe("Failed to parse authenticator data");
  });
});
