import { describe, it, expect, beforeEach } from "vitest"
import { Context, Effect } from "effect"
import { makeEmailPasswordService, EmailPasswordStore } from "./EmailPassword.js"
import { makeSessionManager, SessionStore, SessionManager, UserStore } from "./Session.js"
import { PasswordHasherLive, makePasswordHasher } from "./Password.js"
import type { Session, User, SessionConfig } from "./Types.js"
import * as Errors from "./Errors.js"

const users = new Map<string, User>()
const usersByEmail = new Map<string, string>()
const passwordHashes = new Map<string, string>()
const sessions = new Map<string, Session>()

const sessionStore = {
	create: (session: Session) =>
		Effect.sync(() => {
			sessions.set(session.id, session)
			return session
		}),

	get: (sessionId: string) =>
		Effect.gen(function* () {
			const session = sessions.get(sessionId)
			if (!session) {
				return yield* Effect.fail(
					new Errors.SessionNotFoundError({
						message: "Session not found",
						sessionId
					})
				)
			}
			return session
		}),

	update: (session: Session) =>
		Effect.sync(() => {
			sessions.set(session.id, session)
			return session
		}),

	delete: (sessionId: string) =>
		Effect.sync(() => {
			sessions.delete(sessionId)
		}),

	deleteByUserId: (userId: string) =>
		Effect.sync(() => {
			for (const [id, session] of sessions.entries()) {
				if (session.userId === userId) {
					sessions.delete(id)
				}
			}
		})
}

const userStore = {
	get: (userId: string) =>
		Effect.gen(function* () {
			const user = users.get(userId)
			if (!user) {
				return yield* Effect.fail(
					new Errors.UserNotFoundError({
						message: "User not found",
						userId
					})
				)
			}
			return user
		}),

	getCredentials: (userId: string) =>
		Effect.gen(function* () {
			const hash = passwordHashes.get(userId)
			if (!hash) {
				return yield* Effect.fail(
					new Errors.UserNotFoundError({
						message: "User credentials not found",
						userId
					})
				)
			}
			return hash
		})
}

const emailPasswordStore = {
	getUserByEmail: (email: string) =>
		Effect.sync(() => {
			const userId = usersByEmail.get(email)
			return userId ? users.get(userId) ?? null : null
		}),

	createUser: ({ email, name, attributes }: { email: string; name?: string; attributes?: Record<string, unknown> }) =>
		Effect.sync(() => {
			const id = `user-${users.size + 1}`
			const user: User = {
				id,
				attributes: {
					email,
					...(name !== undefined && { name }),
					...(attributes ?? {})
				}
			}
			users.set(id, user)
			usersByEmail.set(email, id)
			return user
		}),

	getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

	setPasswordHash: (userId: string, hash: string) =>
		Effect.sync(() => {
			passwordHashes.set(userId, hash)
		})
}

const sessionConfig: SessionConfig = {
	sessionExpiresIn: {
		activePeriod: 1000 * 60 * 60 * 24,
		idlePeriod: 1000 * 60 * 60 * 12
	}
}

const makeTestContext = async () => {
	const sessionManager = await Effect.runPromise(
		Effect.provide(
			makeSessionManager(sessionConfig),
			Context.merge(
				Context.make(SessionStore, sessionStore),
				Context.make(UserStore, userStore)
			)
		)
	)

	return Context.merge(
		Context.make(SessionManager, sessionManager),
		Context.merge(
			Context.make(SessionStore, sessionStore),
			Context.merge(
				Context.make(UserStore, userStore),
				Context.merge(
					Context.make(EmailPasswordStore, emailPasswordStore),
					PasswordHasherLive
				)
			)
		)
	)
}

describe("EmailPasswordService", () => {
	beforeEach(() => {
		users.clear()
		usersByEmail.clear()
		passwordHashes.clear()
		sessions.clear()
	})

	it("should sign up and create a session by default", async () => {
		const testContext = await makeTestContext()

		const program = Effect.gen(function* () {
			const service = yield* makeEmailPasswordService()

			const result = yield* service.signUp({
				email: "Test@Example.com",
				password: "strong-password-123",
				name: "Tester"
			})

			expect(result.user.attributes.email).toBe("test@example.com")
			expect(result.session).toBeDefined()

			return result
		})

		const result = await Effect.runPromise(
			Effect.provide(program, testContext)
		)

		expect(result.session?.userId).toBe(result.user.id)
	})

	it("should sign in an existing user", async () => {
		const testContext = await makeTestContext()

		const hasher = makePasswordHasher()
		const hashResult = await Effect.runPromise(hasher.hash("sign-in-password"))

		const user: User = {
			id: "user-existing",
			attributes: {
				email: "existing@example.com",
				emailVerified: true
			}
		}

		users.set(user.id, user)
		usersByEmail.set("existing@example.com", user.id)
		passwordHashes.set(user.id, hashResult.hash)

		const program = Effect.gen(function* () {
			const service = yield* makeEmailPasswordService({
				requireEmailVerification: true
			})
			return yield* service.signIn({
				email: "existing@example.com",
				password: "sign-in-password"
			})
		})

		const result = await Effect.runPromise(
			Effect.provide(program, testContext)
		)

		expect(result.user.id).toBe(user.id)
		expect(result.session).toBeDefined()
	})

	it("should reject invalid credentials", async () => {
		const testContext = await makeTestContext()

		const hasher = makePasswordHasher()
		const hashResult = await Effect.runPromise(hasher.hash("correct-password"))

		const user: User = {
			id: "user-invalid-cred",
			attributes: {
				email: "invalid@example.com",
				emailVerified: true
			}
		}

		users.set(user.id, user)
		usersByEmail.set("invalid@example.com", user.id)
		passwordHashes.set(user.id, hashResult.hash)

		const program = Effect.gen(function* () {
			const service = yield* makeEmailPasswordService()
			return yield* Effect.either(
				service.signIn({
					email: "invalid@example.com",
					password: "wrong-password"
				})
			)
		})

		const result = await Effect.runPromise(
			Effect.provide(program, testContext)
		)

		expect(result._tag).toBe("Left")
		if (result._tag === "Left") {
			expect(result.left._tag).toBe("InvalidCredentialsError")
		}
	})

	it("should block sign-in for unverified email when required", async () => {
		const testContext = await makeTestContext()

		const hasher = makePasswordHasher()
		const hashResult = await Effect.runPromise(hasher.hash("password-123"))

		const user: User = {
			id: "user-unverified",
			attributes: {
				email: "unverified@example.com",
				emailVerified: false
			}
		}

		users.set(user.id, user)
		usersByEmail.set("unverified@example.com", user.id)
		passwordHashes.set(user.id, hashResult.hash)

		const program = Effect.gen(function* () {
			const service = yield* makeEmailPasswordService({
				requireEmailVerification: true
			})
			return yield* Effect.either(
				service.signIn({
					email: "unverified@example.com",
					password: "password-123"
				})
			)
		})

		const result = await Effect.runPromise(
			Effect.provide(program, testContext)
		)

		expect(result._tag).toBe("Left")
		if (result._tag === "Left") {
			expect(result.left._tag).toBe("EmailNotVerifiedError")
		}
	})
})
