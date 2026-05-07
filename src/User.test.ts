import { beforeEach, describe, expect, it } from "vitest"
import { Context, Effect } from "effect"
import { UserServiceStore, makeUserService } from "./User.js"
import type { User } from "./Types.js"
import * as Errors from "./Errors.js"

const users = new Map<string, User>()
const usersByEmail = new Map<string, string>()

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

	getByEmail: (email: string) =>
		Effect.sync(() => {
			const userId = usersByEmail.get(email)
			return userId ? users.get(userId) ?? null : null
		}),

	update: (user: User) =>
		Effect.sync(() => {
			users.set(user.id, user)
			const rawEmail = user.attributes.email
			if (typeof rawEmail === "string" && rawEmail.length > 0) {
				usersByEmail.set(rawEmail.toLowerCase(), user.id)
			}
			return user
		}),

	delete: (userId: string) =>
		Effect.sync(() => {
			const existing = users.get(userId)
			if (existing) {
				const rawEmail = existing.attributes.email
				if (typeof rawEmail === "string" && rawEmail.length > 0) {
					usersByEmail.delete(rawEmail.toLowerCase())
				}
			}
			users.delete(userId)
		})
}

const makeTestContext = () => Context.make(UserServiceStore, userStore)

describe("UserService", () => {
	beforeEach(() => {
		users.clear()
		usersByEmail.clear()

		const seeded: User = {
			id: "user-1",
			attributes: {
				email: "user@example.com",
				name: "User One",
				role: "member"
			}
		}

		users.set(seeded.id, seeded)
		usersByEmail.set("user@example.com", seeded.id)
	})

	it("should get user by id", async () => {
		const program = Effect.gen(function* () {
			const service = yield* makeUserService()
			return yield* service.getUser("user-1")
		})

		const result = await Effect.runPromise(
			Effect.provide(program, makeTestContext())
		)

		expect(result.id).toBe("user-1")
		expect(result.attributes.email).toBe("user@example.com")
	})

	it("should get user by normalized email", async () => {
		const program = Effect.gen(function* () {
			const service = yield* makeUserService()
			return yield* service.getUserByEmail("  USER@EXAMPLE.COM  ")
		})

		const result = await Effect.runPromise(
			Effect.provide(program, makeTestContext())
		)

		expect(result.id).toBe("user-1")
	})

	it("should merge attributes when updating user", async () => {
		const program = Effect.gen(function* () {
			const service = yield* makeUserService()
			return yield* service.updateUserAttributes("user-1", {
				role: "admin",
				displayName: "Updated User"
			})
		})

		const result = await Effect.runPromise(
			Effect.provide(program, makeTestContext())
		)

		expect(result.attributes.email).toBe("user@example.com")
		expect(result.attributes.role).toBe("admin")
		expect(result.attributes.displayName).toBe("Updated User")
	})

	it("should mark user email as verified", async () => {
		const program = Effect.gen(function* () {
			const service = yield* makeUserService()
			return yield* service.markEmailVerified("user-1")
		})

		const result = await Effect.runPromise(
			Effect.provide(program, makeTestContext())
		)

		expect(result.attributes.emailVerified).toBe(true)
	})

	it("should delete user", async () => {
		const program = Effect.gen(function* () {
			const service = yield* makeUserService()
			yield* service.deleteUser("user-1")
			return yield* Effect.either(service.getUser("user-1"))
		})

		const result = await Effect.runPromise(
			Effect.provide(program, makeTestContext())
		)

		expect(result._tag).toBe("Left")
		if (result._tag === "Left") {
			expect(result.left._tag).toBe("UserNotFoundError")
		}
	})
})
