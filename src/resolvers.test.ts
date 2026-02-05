import { describe, it, expect, beforeEach } from "vitest"
import { Effect, Context } from "effect"
import * as Requests from "./requests.js"
import * as Resolvers from "./resolvers.js"
import { makeSessionManager, SessionStore, UserStore } from "./session.js"
import { PasswordHasher, PasswordHasherLive, makePasswordHasher } from "./password.js"
import type { Session, User, SessionConfig } from "./types.js"
import {
  SessionNotFoundError,
  UserNotFoundError,
  InvalidCredentialsError
} from "./errors.js"

// Mock stores for testing
const sessions = new Map<string, Session>()
const users = new Map<string, User>([
  ["user1", { id: "user1", attributes: { name: "Test User" } }]
])
const credentials = new Map<string, string>()

const mockSessionStore: SessionStore = {
  create: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session)
      return session
    }),
  get: (sessionId) =>
    Effect.gen(function* () {
      const session = sessions.get(sessionId)
      if (!session) {
        return yield* Effect.fail(
          new SessionNotFoundError({ message: "Not found", sessionId })
        )
      }
      return session
    }),
  update: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session)
      return session
    }),
  delete: (sessionId) =>
    Effect.sync(() => {
      sessions.delete(sessionId)
    }),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id)
        }
      }
    })
}

const mockUserStore: UserStore = {
  get: (userId) =>
    Effect.gen(function* () {
      const user = users.get(userId)
      if (!user) {
        return yield* Effect.fail(
          new UserNotFoundError({ message: "Not found", userId })
        )
      }
      return user
    }),
  getCredentials: (userId) =>
    Effect.gen(function* () {
      const hash = credentials.get(userId)
      if (!hash) {
        return yield* Effect.fail(
          new UserNotFoundError({ message: "Not found", userId })
        )
      }
      return hash
    })
}

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30,
    idlePeriod: 1000 * 60 * 60 * 24 * 14
  }
}

describe("Resolvers", () => {
  beforeEach(() => {
    sessions.clear()
    credentials.clear()
  })

  describe("HashPasswordResolver", () => {
    it("should hash a password using the resolver", async () => {
      const request = Requests.HashPasswordRequest({ password: "testPassword123" })
      const program = Effect.request(request, Resolvers.makeHashPasswordResolver)

      const result = await Effect.runPromise(
        Effect.provide(program, PasswordHasherLive)
      )

      expect(result.hash).toBeDefined()
      expect(result.algorithm).toBe("pbkdf2-sha256")
    })
  })

  describe("VerifyPasswordResolver", () => {
    it("should verify a password using the resolver", async () => {
      const program = Effect.gen(function* () {
        // First hash a password
        const hashRequest = Requests.HashPasswordRequest({ password: "testPassword123" })
        const hashed = yield* Effect.request(hashRequest, Resolvers.makeHashPasswordResolver)

        // Then verify it
        const verifyRequest = Requests.VerifyPasswordRequest({
          password: "testPassword123",
          hash: hashed.hash
        })
        return yield* Effect.request(verifyRequest, Resolvers.makeVerifyPasswordResolver)
      })

      const isValid = await Effect.runPromise(
        Effect.provide(program, PasswordHasherLive)
      )

      expect(isValid).toBe(true)
    })

    it("should reject incorrect password using the resolver", async () => {
      const program = Effect.gen(function* () {
        // First hash a password
        const hashRequest = Requests.HashPasswordRequest({ password: "correctPassword" })
        const hashed = yield* Effect.request(hashRequest, Resolvers.makeHashPasswordResolver)

        // Then verify with wrong password
        const verifyRequest = Requests.VerifyPasswordRequest({
          password: "wrongPassword",
          hash: hashed.hash
        })
        return yield* Effect.request(verifyRequest, Resolvers.makeVerifyPasswordResolver)
      })

      const isValid = await Effect.runPromise(
        Effect.provide(program, PasswordHasherLive)
      )

      expect(isValid).toBe(false)
    })
  })

  describe("VerifyCredentialsResolver", () => {
    it("should verify valid credentials", async () => {
      const program = Effect.gen(function* () {
        const hasher = makePasswordHasher()
        
        // Setup: hash a password and store it
        const hashed = yield* hasher.hash("userPassword123")
        credentials.set("user1", hashed.hash)

        // Verify credentials
        const request = Requests.VerifyCredentialsRequest({
          userId: "user1",
          password: "userPassword123"
        })
        return yield* Effect.request(request, Resolvers.makeVerifyCredentialsResolver)
      })

      const testContext = Context.merge(
        Context.make(UserStore, mockUserStore),
        PasswordHasherLive
      )

      const user = await Effect.runPromise(
        Effect.provide(program, testContext)
      )

      expect(user.id).toBe("user1")
    })

    it("should fail with invalid credentials", async () => {
      const program = Effect.gen(function* () {
        const hasher = makePasswordHasher()
        
        // Setup: hash a password and store it
        const hashed = yield* hasher.hash("correctPassword")
        credentials.set("user1", hashed.hash)

        // Try to verify with wrong password
        const request = Requests.VerifyCredentialsRequest({
          userId: "user1",
          password: "wrongPassword"
        })
        return yield* Effect.request(request, Resolvers.makeVerifyCredentialsResolver)
      })

      const testContext = Context.merge(
        Context.make(UserStore, mockUserStore),
        PasswordHasherLive
      )

      const result = await Effect.runPromise(
        Effect.either(Effect.provide(program, testContext))
      )

      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("InvalidCredentialsError")
      }
    })
  })
})

