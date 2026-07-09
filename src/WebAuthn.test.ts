import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Context } from "effect";
import { base64UrlDecode, ChallengeStore, CredentialStore } from "./WebAuthn.js";
import { make } from "./WebAuthnService.js";
import type {
  WebAuthnChallenge,
  WebAuthnCredential,
  WebAuthnConfig,
  WebAuthnUser,
  RegistrationResponse,
} from "./WebAuthn.js";
import {
  ChallengeNotFoundError,
  ChallengeExpiredError,
  WebAuthnVerificationError,
  CredentialNotFoundError,
  AuthError,
} from "./Errors.js";
import * as crypto from "node:crypto";

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
  Context.make(ChallengeStore, mockChallengeStore),
  Context.make(CredentialStore, mockCredentialStore),
);

describe("WebAuthn Service", () => {
  beforeEach(() => {
    // Clear mocks before each test
    mockChallengeStore.challenges.clear();
    mockCredentialStore.credentials.clear();
  });

  it("should generate a registration challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const result = yield* service.generateRegistrationChallenge(testUser);

      expect(result.challenge).toBeInstanceOf(Uint8Array);
      expect(result.challenge.length).toBe(32); // 256 bits
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      // Verify challenge was stored
      expect(mockChallengeStore.challenges.size).toBe(1);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should generate unique challenges", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const result1 = yield* service.generateRegistrationChallenge(testUser);
      const result2 = yield* service.generateRegistrationChallenge(testUser);

      expect(result1.challenge).not.toEqual(result2.challenge);
      expect(mockChallengeStore.challenges.size).toBe(2);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should generate an authentication challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const result = yield* service.generateAuthenticationChallenge(testUser.id);

      expect(result.challenge).toBeInstanceOf(Uint8Array);
      expect(result.challenge.length).toBe(32);
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      // Verify challenge was stored with userId
      const stored = Array.from(mockChallengeStore.challenges.values())[0];
      expect(stored.userId).toBe(testUser.id);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should generate a usernameless authentication challenge (no userId)", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const result = yield* service.generateAuthenticationChallenge();

      expect(result.challenge).toBeInstanceOf(Uint8Array);
      expect(result.challenge.length).toBe(32);

      // Verify challenge was stored WITHOUT userId
      const stored = Array.from(mockChallengeStore.challenges.values())[0];
      expect(stored.userId).toBeUndefined();
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should fail to verify with expired challenge", async () => {
    const expiredConfig: WebAuthnConfig = {
      ...config,
      challengeExpiresIn: -1000, // Expired 1 second ago
    };

    const program = Effect.gen(function* () {
      const service = yield* make(expiredConfig);
      const { challenge } = yield* service.generateRegistrationChallenge(testUser);

      // Try to verify with expired challenge
      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([]),
      };

      yield* service.verifyRegistration(challenge, mockResponse);
    });

    const result = await Effect.runPromise(Effect.provide(program, dependencies).pipe(Effect.flip));

    expect(result).toBeInstanceOf(ChallengeExpiredError);
  });

  it("should fail to verify with non-existent challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const fakeChallenge = crypto.randomBytes(32);

      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([]),
      };

      yield* service.verifyRegistration(fakeChallenge, mockResponse);
    });

    const result = await Effect.runPromise(Effect.provide(program, dependencies).pipe(Effect.flip));

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

    const program = Effect.gen(function* () {
      const service = yield* make(expiredConfig);
      const { challenge } = yield* service.generateRegistrationChallenge(testUser);

      expect(mockChallengeStore.challenges.size).toBe(1);

      // Try to verify with expired challenge - should fail
      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([]),
      };

      // Expect this to fail with ChallengeExpiredError
      const result = yield* Effect.flip(service.verifyRegistration(challenge, mockResponse));

      expect(result).toBeInstanceOf(ChallengeExpiredError);
      // Challenge should be deleted after expiration check
      expect(mockChallengeStore.challenges.size).toBe(0);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should store credential with correct user ID", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      yield* service.generateRegistrationChallenge(testUser);

      // Create a mock credential
      const mockCredential: WebAuthnCredential = {
        id: "test-credential-id",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7, // ES256
        counter: 0,
        createdAt: Date.now(),
      };

      yield* mockCredentialStore.create(mockCredential);

      const stored = yield* mockCredentialStore.get("test-credential-id");
      expect(stored?.userId).toBe(testUser.id);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should support multiple credentials per user", async () => {
    const program = Effect.gen(function* () {
      const credentials: WebAuthnCredential[] = [
        {
          id: "cred-1",
          userId: testUser.id,
          publicKey: crypto.randomBytes(65),
          algorithm: -7,
          counter: 0,
          createdAt: Date.now(),
        },
        {
          id: "cred-2",
          userId: testUser.id,
          publicKey: crypto.randomBytes(65),
          algorithm: -7,
          counter: 0,
          createdAt: Date.now(),
        },
      ];

      for (const cred of credentials) {
        yield* mockCredentialStore.create(cred);
      }

      const userCredentials = yield* mockCredentialStore.listByUserId(testUser.id);
      expect(userCredentials.length).toBe(2);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("should update credential counter", async () => {
    const program = Effect.gen(function* () {
      const mockCredential: WebAuthnCredential = {
        id: "test-cred",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 5,
        createdAt: Date.now(),
      };

      yield* mockCredentialStore.create(mockCredential);

      const updated = { ...mockCredential, counter: 6 };
      yield* mockCredentialStore.update(updated);

      const retrieved = yield* mockCredentialStore.get("test-cred");
      expect(retrieved?.counter).toBe(6);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("advertises ES256, RS256, and EdDSA in the registration challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make({ ...config, residentKey: "required" });
      const result = yield* service.generateRegistrationChallenge(testUser);
      return result;
    });
    const result = await Effect.runPromise(Effect.provide(program, dependencies));
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
    const program = Effect.gen(function* () {
      const service = yield* make(config);

      // Pre-populate two credentials for testUser and one for another user.
      const cred1: WebAuthnCredential = {
        id: "cred-a",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      const cred2: WebAuthnCredential = {
        id: "cred-b",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      const other: WebAuthnCredential = {
        id: "cred-c",
        userId: "other-user",
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      yield* mockCredentialStore.create(cred1);
      yield* mockCredentialStore.create(cred2);
      yield* mockCredentialStore.create(other);

      const list = yield* service.listCredentials(testUser.id);
      expect(list.length).toBe(2);
      expect(list.map((c) => c.id).sort()).toEqual(["cred-a", "cred-b"]);
    });
    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("deleteCredential removes the passkey when the owner calls it", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const cred: WebAuthnCredential = {
        id: "del-cred",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      yield* mockCredentialStore.create(cred);

      yield* service.deleteCredential(testUser.id, cred.id);

      const after = yield* mockCredentialStore.get(cred.id);
      expect(after).toBeNull();
    });
    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("deleteCredential fails with CredentialNotFoundError for an unknown id", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      return yield* Effect.flip(service.deleteCredential(testUser.id, "nonexistent"));
    });
    const err = await Effect.runPromise(Effect.provide(program, dependencies));
    expect(err).toBeInstanceOf(CredentialNotFoundError);
  });

  it("deleteCredential fails with AuthError when another user tries to delete", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const cred: WebAuthnCredential = {
        id: "other-owned",
        userId: "owner-user",
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      yield* mockCredentialStore.create(cred);

      return yield* Effect.flip(service.deleteCredential(testUser.id, cred.id));
    });
    const err = await Effect.runPromise(Effect.provide(program, dependencies));
    expect(err).toBeInstanceOf(AuthError);
  });

  it("renameCredential updates the name when the owner calls it", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const cred: WebAuthnCredential = {
        id: "rename-cred",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      yield* mockCredentialStore.create(cred);

      const updated = yield* service.renameCredential(testUser.id, cred.id, "My YubiKey");
      expect(updated.name).toBe("My YubiKey");

      const stored = yield* mockCredentialStore.get(cred.id);
      expect(stored?.name).toBe("My YubiKey");
    });
    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("renameCredential fails with AuthError when another user tries to rename", async () => {
    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const cred: WebAuthnCredential = {
        id: "rename-protected",
        userId: "owner-user",
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
      };
      yield* mockCredentialStore.create(cred);

      return yield* Effect.flip(service.renameCredential(testUser.id, cred.id, "Hijacked"));
    });
    const err = await Effect.runPromise(Effect.provide(program, dependencies));
    expect(err).toBeInstanceOf(AuthError);
  });
});

// --- Multi-algorithm registration + authentication round trips ---------------

/** Minimal deterministic CBOR encoder (enough for COSE keys + attestation). */
const cborHead = (major: number, n: number): number[] => {
  let head: number[];
  if (n < 24) head = [n];
  else if (n < 256) head = [24, n];
  else if (n < 65536) head = [25, (n >> 8) & 0xff, n & 0xff];
  else head = [26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  head[0]! |= major << 5;
  return head;
};
const cborUint = (n: number): number[] => cborHead(0, n);
const cborNegInt = (n: number): number[] => cborHead(1, -1 - n);
const cborBytes = (b: Uint8Array): number[] => [...cborHead(2, b.length), ...b];
const cborText = (s: string): number[] => {
  const b = Buffer.from(s, "utf8");
  return [...cborHead(3, b.length), ...b];
};
const cborMap = (entries: ReadonlyArray<readonly [number[], number[]]>): number[] => {
  const parts = cborHead(5, entries.length);
  for (const [k, v] of entries) parts.push(...k, ...v);
  return parts;
};

const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
};

type Alg = -7 | -257 | -8;

/** Generate a keypair and its COSE-key CBOR bytes for the given algorithm. */
const buildKey = (alg: Alg): { privateKey: crypto.KeyObject; cose: number[] } => {
  if (alg === -7) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const x = new Uint8Array(Buffer.from(jwk.x, "base64url"));
    const y = new Uint8Array(Buffer.from(jwk.y, "base64url"));
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(2)],
        [cborUint(3), cborNegInt(-7)],
        [cborNegInt(-1), cborUint(1)],
        [cborNegInt(-2), cborBytes(x)],
        [cborNegInt(-3), cborBytes(y)],
      ]),
    };
  }
  if (alg === -257) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
    const n = new Uint8Array(Buffer.from(jwk.n, "base64url"));
    const e = new Uint8Array(Buffer.from(jwk.e, "base64url"));
    return {
      privateKey,
      cose: cborMap([
        [cborUint(1), cborUint(3)],
        [cborUint(3), cborNegInt(-257)],
        [cborNegInt(-1), cborBytes(n)],
        [cborNegInt(-2), cborBytes(e)],
      ]),
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const x = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  return {
    privateKey,
    cose: cborMap([
      [cborUint(1), cborUint(1)],
      [cborUint(3), cborNegInt(-8)],
      [cborNegInt(-1), cborUint(6)],
      [cborNegInt(-2), cborBytes(x)],
    ]),
  };
};

const rpIdHash = new Uint8Array(crypto.createHash("sha256").update(config.relyingPartyId).digest());

const clientDataJSON = (
  type: "webauthn.create" | "webauthn.get",
  challenge: Uint8Array,
): Uint8Array =>
  new Uint8Array(
    Buffer.from(
      JSON.stringify({
        type,
        challenge: Buffer.from(challenge).toString("base64url"),
        origin: "https://example.com",
      }),
      "utf8",
    ),
  );

/** Assemble a `none`-format attestation object embedding the COSE key. */
const attestationObject = (cose: number[], credentialId: Uint8Array): Uint8Array => {
  const acd = concatBytes(
    new Uint8Array(16), // aaguid
    new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
    credentialId,
    new Uint8Array(cose),
  );
  const authData = concatBytes(
    rpIdHash,
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

const signAssertion = (
  alg: Alg,
  privateKey: crypto.KeyObject,
  authenticatorData: Uint8Array,
  clientData: Uint8Array,
): Uint8Array => {
  const message = concatBytes(
    authenticatorData,
    new Uint8Array(crypto.createHash("sha256").update(clientData).digest()),
  );
  // ES256/RS256 hash with SHA-256; Ed25519 hashes internally (digest null).
  const signature =
    alg === -8
      ? crypto.sign(null, message, privateKey)
      : crypto.sign("sha256", message, privateKey);
  return new Uint8Array(signature);
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
    const { privateKey, cose } = buildKey(alg);
    const credentialId = crypto.randomBytes(20);

    const program = Effect.gen(function* () {
      const service = yield* make(config);

      // Registration.
      const reg = yield* service.generateRegistrationChallenge(testUser);
      const registration = yield* service.verifyRegistration(reg.challenge, {
        credentialId,
        attestationObject: attestationObject(cose, credentialId),
        clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
      });
      expect(registration.credential.algorithm).toBe(alg);
      expect(registration.verified).toBe(true);

      // Authentication with a fresh (incremented) counter.
      const auth = yield* service.generateAuthenticationChallenge(testUser.id);
      const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
      const clientData = clientDataJSON("webauthn.get", auth.challenge);
      const result = yield* service.verifyAuthentication(auth.challenge, {
        credentialId,
        authenticatorData,
        clientDataJSON: clientData,
        signature: signAssertion(alg, privateKey, authenticatorData, clientData),
      });
      expect(result.newCounter).toBe(1);
      return result;
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("rejects an assertion signed by the wrong key", async () => {
    const { cose } = buildKey(alg);
    const wrong = buildKey(alg);
    const credentialId = crypto.randomBytes(20);

    const program = Effect.gen(function* () {
      const service = yield* make(config);
      const reg = yield* service.generateRegistrationChallenge(testUser);
      yield* service.verifyRegistration(reg.challenge, {
        credentialId,
        attestationObject: attestationObject(cose, credentialId),
        clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
      });

      const auth = yield* service.generateAuthenticationChallenge(testUser.id);
      const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
      const clientData = clientDataJSON("webauthn.get", auth.challenge);
      // Sign with an unrelated private key.
      return yield* Effect.flip(
        service.verifyAuthentication(auth.challenge, {
          credentialId,
          authenticatorData,
          clientDataJSON: clientData,
          signature: signAssertion(alg, wrong.privateKey, authenticatorData, clientData),
        }),
      );
    });

    const err = await Effect.runPromise(Effect.provide(program, dependencies));
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
  });

  it("completes a usernameless (discoverable) register+login round trip", async () => {
    const { privateKey, cose } = buildKey(alg);
    const credentialId = crypto.randomBytes(20);

    const program = Effect.gen(function* () {
      const service = yield* make(config);

      // Registration (bound challenge — userId known at registration time).
      const reg = yield* service.generateRegistrationChallenge(testUser);
      const registration = yield* service.verifyRegistration(reg.challenge, {
        credentialId,
        attestationObject: attestationObject(cose, credentialId),
        clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
      });
      expect(registration.credential.userId).toBe(testUser.id);

      // Usernameless authentication — no userId passed.
      const auth = yield* service.generateAuthenticationChallenge();
      const storedChallenge = Array.from(mockChallengeStore.challenges.values())[0];
      expect(storedChallenge?.userId).toBeUndefined();

      const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
      const clientData = clientDataJSON("webauthn.get", auth.challenge);
      const result = yield* service.verifyAuthentication(auth.challenge, {
        credentialId,
        authenticatorData,
        clientDataJSON: clientData,
        signature: signAssertion(alg, privateKey, authenticatorData, clientData),
      });

      // The service resolves the user from the stored credential.
      expect(result.credential.userId).toBe(testUser.id);
      expect(result.newCounter).toBe(1);
    });

    await Effect.runPromise(Effect.provide(program, dependencies));
  });

  it("rejects a usernameless assertion when the credential is from a different user", async () => {
    const { cose } = buildKey(alg);
    const credentialId = crypto.randomBytes(20);

    const program = Effect.gen(function* () {
      const service = yield* make(config);

      // Register under testUser, then try a bound challenge for a DIFFERENT user.
      const reg = yield* service.generateRegistrationChallenge(testUser);
      yield* service.verifyRegistration(reg.challenge, {
        credentialId,
        attestationObject: attestationObject(cose, credentialId),
        clientDataJSON: clientDataJSON("webauthn.create", reg.challenge),
      });

      // Bound challenge for a different user.
      const auth = yield* service.generateAuthenticationChallenge("other-user-999");
      const authenticatorData = concatBytes(rpIdHash, new Uint8Array([0x05]), signCounter(1));
      const clientData = clientDataJSON("webauthn.get", auth.challenge);
      return yield* Effect.flip(
        service.verifyAuthentication(auth.challenge, {
          credentialId,
          authenticatorData,
          clientDataJSON: clientData,
          signature: signAssertion(alg, buildKey(alg).privateKey, authenticatorData, clientData),
        }),
      );
    });

    const err = await Effect.runPromise(Effect.provide(program, dependencies));
    expect(err).toBeInstanceOf(WebAuthnVerificationError);
  });
});
