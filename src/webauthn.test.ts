import { describe, it, expect, beforeEach } from "vitest"
import { Effect, Context } from "effect"
import { 
  makeWebAuthnService, 
  ChallengeStore, 
  CredentialStore,
  base64UrlDecode
} from "./webauthn.js"
import type {
  WebAuthnChallenge,
  WebAuthnCredential,
  WebAuthnConfig,
  WebAuthnUser,
  RegistrationResponse
} from "./webauthn-types.js"
import { 
  ChallengeNotFoundError, 
  ChallengeExpiredError,
  CredentialNotFoundError,
  WebAuthnVerificationError 
} from "./errors.js"
import * as crypto from "node:crypto"

// Mock implementations for testing
const mockChallengeStore = {
  challenges: new Map<string, WebAuthnChallenge>(),

  create: (challenge: WebAuthnChallenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge.challenge).toString("hex")
      mockChallengeStore.challenges.set(key, challenge)
      return challenge
    }),

  get: (challenge: Uint8Array) =>
    Effect.gen(function* () {
      const key = Buffer.from(challenge).toString("hex")
      const stored = mockChallengeStore.challenges.get(key)
      if (!stored) {
        return yield* Effect.fail(
          new ChallengeNotFoundError({
            message: "Challenge not found"
          })
        )
      }
      return stored
    }),

  delete: (challenge: Uint8Array) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex")
      mockChallengeStore.challenges.delete(key)
    })
}

const mockCredentialStore = {
  credentials: new Map<string, WebAuthnCredential>(),

  create: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.set(credential.id, credential)
      return credential
    }),

  get: (credentialId: string) =>
    Effect.gen(function* () {
      const credential = mockCredentialStore.credentials.get(credentialId)
      if (!credential) {
        return yield* Effect.fail(
          new CredentialNotFoundError({
            message: "Credential not found",
            credentialId
          })
        )
      }
      return credential
    }),

  update: (credential: WebAuthnCredential) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.set(credential.id, credential)
      return credential
    }),

  delete: (credentialId: string) =>
    Effect.sync(() => {
      mockCredentialStore.credentials.delete(credentialId)
    }),

  getByUserId: (userId: string) =>
    Effect.sync(() => {
      const credentials = Array.from(mockCredentialStore.credentials.values())
        .filter(c => c.userId === userId)
      return credentials
    })
}

const config: WebAuthnConfig = {
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000 // 5 minutes
}

const testUser: WebAuthnUser = {
  id: "user-123",
  name: "test@example.com",
  displayName: "Test User"
}

const dependencies = Context.merge(
  Context.make(ChallengeStore, mockChallengeStore),
  Context.make(CredentialStore, mockCredentialStore)
)

describe("WebAuthn Service", () => {
  beforeEach(() => {
    // Clear mocks before each test
    mockChallengeStore.challenges.clear()
    mockCredentialStore.credentials.clear()
  })

  it("should generate a registration challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(config)
      const result = yield* service.generateRegistrationChallenge(testUser)

      expect(result.challenge).toBeInstanceOf(Uint8Array)
      expect(result.challenge.length).toBe(32) // 256 bits
      expect(result.expiresAt).toBeGreaterThan(Date.now())

      // Verify challenge was stored
      expect(mockChallengeStore.challenges.size).toBe(1)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should generate unique challenges", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(config)
      const result1 = yield* service.generateRegistrationChallenge(testUser)
      const result2 = yield* service.generateRegistrationChallenge(testUser)

      expect(result1.challenge).not.toEqual(result2.challenge)
      expect(mockChallengeStore.challenges.size).toBe(2)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should generate an authentication challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(config)
      const result = yield* service.generateAuthenticationChallenge(testUser.id)

      expect(result.challenge).toBeInstanceOf(Uint8Array)
      expect(result.challenge.length).toBe(32)
      expect(result.expiresAt).toBeGreaterThan(Date.now())

      // Verify challenge was stored with userId
      const stored = Array.from(mockChallengeStore.challenges.values())[0]
      expect(stored.userId).toBe(testUser.id)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should fail to verify with expired challenge", async () => {
    const expiredConfig: WebAuthnConfig = {
      ...config,
      challengeExpiresIn: -1000 // Expired 1 second ago
    }

    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(expiredConfig)
      const { challenge } = yield* service.generateRegistrationChallenge(testUser)

      // Try to verify with expired challenge
      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([])
      }

      yield* service.verifyRegistration(challenge, mockResponse, "https://example.com")
    })

    const result = await Effect.runPromise(
      Effect.provide(program, dependencies).pipe(Effect.flip)
    )

    expect(result).toBeInstanceOf(ChallengeExpiredError)
  })

  it("should fail to verify with non-existent challenge", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(config)
      const fakeChallenge = crypto.randomBytes(32)

      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([])
      }

      yield* service.verifyRegistration(fakeChallenge, mockResponse, "https://example.com")
    })

    const result = await Effect.runPromise(
      Effect.provide(program, dependencies).pipe(Effect.flip)
    )

    expect(result).toBeInstanceOf(ChallengeNotFoundError)
  })

  it("should handle base64url encoding/decoding", () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 255, 254, 253])
    const encoded = Buffer.from(original)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "")
    
    const decoded = base64UrlDecode(encoded)
    expect(decoded).toEqual(original)
  })

  it("should handle challenge cleanup after expiration", async () => {
    const expiredConfig: WebAuthnConfig = {
      ...config,
      challengeExpiresIn: -1000
    }

    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(expiredConfig)
      const { challenge } = yield* service.generateRegistrationChallenge(testUser)

      expect(mockChallengeStore.challenges.size).toBe(1)

      // Try to verify with expired challenge - should fail
      const mockResponse: RegistrationResponse = {
        credentialId: crypto.randomBytes(16),
        attestationObject: new Uint8Array([]),
        clientDataJSON: new Uint8Array([])
      }

      // Expect this to fail with ChallengeExpiredError
      const result = yield* Effect.flip(
        service.verifyRegistration(challenge, mockResponse, "https://example.com")
      )

      expect(result).toBeInstanceOf(ChallengeExpiredError)
      // Challenge should be deleted after expiration check
      expect(mockChallengeStore.challenges.size).toBe(0)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should store credential with correct user ID", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeWebAuthnService(config)
      const { challenge } = yield* service.generateRegistrationChallenge(testUser)

      // Create a mock credential
      const mockCredential: WebAuthnCredential = {
        id: "test-credential-id",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7, // ES256
        counter: 0,
        createdAt: Date.now()
      }

      yield* mockCredentialStore.create(mockCredential)

      const stored = yield* mockCredentialStore.get("test-credential-id")
      expect(stored.userId).toBe(testUser.id)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should support multiple credentials per user", async () => {
    const program = Effect.gen(function* () {
      const credentials: WebAuthnCredential[] = [
        {
          id: "cred-1",
          userId: testUser.id,
          publicKey: crypto.randomBytes(65),
          algorithm: -7,
          counter: 0,
          createdAt: Date.now()
        },
        {
          id: "cred-2",
          userId: testUser.id,
          publicKey: crypto.randomBytes(65),
          algorithm: -7,
          counter: 0,
          createdAt: Date.now()
        }
      ]

      for (const cred of credentials) {
        yield* mockCredentialStore.create(cred)
      }

      const userCredentials = yield* mockCredentialStore.getByUserId(testUser.id)
      expect(userCredentials.length).toBe(2)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })

  it("should update credential counter", async () => {
    const program = Effect.gen(function* () {
      const mockCredential: WebAuthnCredential = {
        id: "test-cred",
        userId: testUser.id,
        publicKey: crypto.randomBytes(65),
        algorithm: -7,
        counter: 5,
        createdAt: Date.now()
      }

      yield* mockCredentialStore.create(mockCredential)

      const updated = { ...mockCredential, counter: 6 }
      yield* mockCredentialStore.update(updated)

      const retrieved = yield* mockCredentialStore.get("test-cred")
      expect(retrieved.counter).toBe(6)
    })

    await Effect.runPromise(Effect.provide(program, dependencies))
  })
})
