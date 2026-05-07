import { beforeEach, describe, expect, it } from "vitest"
import { Context, Effect } from "effect"
import { makeAuthLifecycleService } from "./AuthLifecycle.js"
import { EmailPasswordStore } from "./EmailPassword.js"
import {
	type EmailVerification,
	EmailVerificationService,
	EmailVerificationStore,
	makeEmailVerificationService
} from "./EmailVerification.js"
import { makePasswordHasher, PasswordHasherLive } from "./Password.js"
import { makeSessionManager, SessionManager, SessionStore, UserStore } from "./Session.js"
import { makeUserService, UserService, UserServiceStore } from "./User.js"
import type { Session, SessionConfig, User } from "./Types.js"
import * as Errors from "./Errors.js"

const users = new Map<string, User>()
const usersByEmail = new Map<string, string>()
const passwordHashes = new Map<string, string>()
const sessions = new Map<string, Session>()
const verifications = new Map<string, EmailVerification>()
const sentEmails: Array<{ email: string; token: string }> = []

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
					emailVerified: false,
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

const emailVerificationStore = {
	create: (verification: EmailVerification) =>
		Effect.sync(() => {
			verifications.set(verification.token, verification)
			return verification
		}),

	get: (token: string) => Effect.sync(() => verifications.get(token) ?? null),

	delete: (token: string) =>
		Effect.sync(() => {
			verifications.delete(token)
		}),

	deleteByUserId: (userId: string) =>
		Effect.sync(() => {
			for (const [token, verification] of verifications.entries()) {
				if (verification.userId === userId) {
					verifications.delete(token)
				}
			}
		})
}

const userServiceStore = {
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

	getByEmail: (email: string) =>
		Effect.sync(() => {
			const userId = usersByEmail.get(email)
			return userId ? users.get(userId) ?? null : null
		}),

	update: (user: User) =>
		Effect.sync(() => {
			users.set(user.id, user)
			return user
		}),

	delete: (userId: string) =>
		Effect.sync(() => {
			users.delete(userId)
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

	const emailVerificationService = await Effect.runPromise(
		makeEmailVerificationService({
			sendEmail: (email, token) =>
				Effect.sync(() => {
					sentEmails.push({ email, token })
				})
		})
	)

	const userService = await Effect.runPromise(makeUserService())

	return Context.merge(
		Context.make(SessionManager, sessionManager),
		Context.merge(
			Context.make(SessionStore, sessionStore),
			Context.merge(
				Context.make(UserStore, userStore),
				Context.merge(
					Context.make(EmailPasswordStore, emailPasswordStore),
					Context.merge(
						Context.make(EmailVerificationStore, emailVerificationStore),
						Context.merge(
							Context.make(EmailVerificationService, emailVerificationService),
							Context.merge(
								Context.make(UserServiceStore, userServiceStore),
								Context.merge(
									Context.make(UserService, userService),
									PasswordHasherLive
								)
							)
						)
					)
				)
			)
		)
	)
}

describe("AuthLifecycleService", () => {
	beforeEach(() => {
		users.clear()
		usersByEmail.clear()
		passwordHashes.clear()
		sessions.clear()
		verifications.clear()
		sentEmails.splice(0, sentEmails.length)
	})

	it("should sign up and require verification when configured", async () => {
		const testContext = await makeTestContext()

		const program = Effect.gen(function* () {
			const service = yield* makeAuthLifecycleService({
				requireEmailVerification: true
			})

			return yield* service.signUp({
				email: "new@example.com",
				password: "strong-password-123",
				name: "New User"
			})
		})

		const result = await Effect.runPromise(Effect.provide(program, testContext))

		expect(result.needsEmailVerification).toBe(true)
		expect(result.session).toBeUndefined()
		expect(sentEmails.length).toBe(1)
		expect(sentEmails[0]?.email).toBe("new@example.com")
	})

	it("should return verification-needed on sign-in and resend when enabled", async () => {
		const testContext = await makeTestContext()

		const hasher = makePasswordHasher()
		const hashResult = await Effect.runPromise(hasher.hash("password-123"))

		const user: User = {
			id: "user-sign-in-unverified",
			attributes: {
				email: "signin@example.com",
				emailVerified: false
			}
		}

		users.set(user.id, user)
		usersByEmail.set("signin@example.com", user.id)
		passwordHashes.set(user.id, hashResult.hash)

		const program = Effect.gen(function* () {
			const service = yield* makeAuthLifecycleService({
				requireEmailVerification: true,
				sendOnSignIn: true
			})

			return yield* service.signIn({
				email: "signin@example.com",
				password: "password-123"
			})
		})

		const result = await Effect.runPromise(Effect.provide(program, testContext))

		expect(result.needsEmailVerification).toBe(true)
		expect(result.session).toBeUndefined()
		expect(result.user.id).toBe(user.id)
		expect(sentEmails.length).toBe(1)
		expect(sentEmails[0]?.email).toBe("signin@example.com")
	})

	it("should verify token and auto sign in", async () => {
		const testContext = await makeTestContext()

		const user: User = {
			id: "user-verify",
			attributes: {
				email: "verify@example.com",
				emailVerified: false
			}
		}

		users.set(user.id, user)
		usersByEmail.set("verify@example.com", user.id)

		const token = await Effect.runPromise(
			Effect.provide(
				Effect.gen(function* () {
					const verification = yield* EmailVerificationService
					const created = yield* verification.createVerification(user.id, "verify@example.com")
					return created.token
				}),
				testContext
			)
		)

		const program = Effect.gen(function* () {
			const service = yield* makeAuthLifecycleService({
				autoSignInAfterVerification: true
			})
			return yield* service.verifyEmail({ token })
		})

		const result = await Effect.runPromise(Effect.provide(program, testContext))

		expect(result.user.id).toBe(user.id)
		expect(result.session).toBeDefined()
		expect(result.needsEmailVerification).toBe(false)
		expect(users.get(user.id)?.attributes.emailVerified).toBe(true)
	})

	it("should sign in verified users normally", async () => {
		const testContext = await makeTestContext()

		const hasher = makePasswordHasher()
		const hashResult = await Effect.runPromise(hasher.hash("verified-password-123"))

		const user: User = {
			id: "user-verified",
			attributes: {
				email: "verified@example.com",
				emailVerified: true
			}
		}

		users.set(user.id, user)
		usersByEmail.set("verified@example.com", user.id)
		passwordHashes.set(user.id, hashResult.hash)

		const program = Effect.gen(function* () {
			const service = yield* makeAuthLifecycleService({
				requireEmailVerification: true
			})

			return yield* service.signIn({
				email: "verified@example.com",
				password: "verified-password-123"
			})
		})

		const result = await Effect.runPromise(Effect.provide(program, testContext))

		expect(result.needsEmailVerification).toBe(false)
		expect(result.session).toBeDefined()
		expect(result.user.id).toBe(user.id)
	})
})
