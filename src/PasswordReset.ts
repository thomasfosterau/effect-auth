import { Context, Effect, Layer } from "effect"
import * as crypto from "node:crypto"
import * as Errors from "./Errors.js"
import { PasswordHasherTag } from "./Password.js"
import type * as Types from "./Types.js"
import { SessionManagerTag } from "./Session.js"

export interface PasswordResetToken {
	readonly token: string
	readonly userId: string
	readonly email: string
	readonly createdAt: number
	readonly expiresAt: number
}

export interface PasswordResetStore {
	readonly create: (
		reset: PasswordResetToken
	) => Effect.Effect<PasswordResetToken, Errors.AuthError>
	readonly get: (
		token: string
	) => Effect.Effect<PasswordResetToken | null, Errors.AuthError>
	readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>
	readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>
}

export interface PasswordResetUserStore {
	readonly getUserByEmail: (
		email: string
	) => Effect.Effect<Types.User | null, Errors.AuthError>
	readonly setPasswordHash: (
		userId: string,
		hash: string
	) => Effect.Effect<void, Errors.AuthError>
}

export class PasswordResetStoreTag extends Context.Tag("@effect-auth/PasswordResetStore")<
	PasswordResetStoreTag,
	PasswordResetStore
>() { }

export const PasswordResetStore = PasswordResetStoreTag

export class PasswordResetUserStoreTag extends Context.Tag("@effect-auth/PasswordResetUserStore")<
	PasswordResetUserStoreTag,
	PasswordResetUserStore
>() { }

export const PasswordResetUserStore = PasswordResetUserStoreTag

export interface PasswordResetConfig {
	readonly expiresIn?: number
	readonly minPasswordLength?: number
	readonly maxPasswordLength?: number
	readonly revokeSessionsOnPasswordReset?: boolean
	readonly sendResetPassword: (
		email: string,
		token: string
	) => Effect.Effect<void, Errors.PasswordResetError>
}

export interface PasswordResetResult {
	readonly userId: string
	readonly email: string
	readonly reset: true
}

export interface PasswordResetService {
	readonly requestPasswordReset: (
		email: string
	) => Effect.Effect<void, Errors.AuthError | Errors.PasswordResetError, PasswordResetStoreTag | PasswordResetUserStoreTag>

	readonly resetPassword: (
		token: string,
		newPassword: string
	) => Effect.Effect<
		PasswordResetResult,
		Errors.AuthError | Errors.PasswordResetError | Errors.HashingError,
		PasswordResetStoreTag | PasswordResetUserStoreTag | PasswordHasherTag | SessionManagerTag
	>
}

export class PasswordResetServiceTag extends Context.Tag("@effect-auth/PasswordResetService")<
	PasswordResetServiceTag,
	PasswordResetService
>() { }

export const PasswordResetService = PasswordResetServiceTag

const normalizeEmail = (email: string): string => email.trim().toLowerCase()

const generateResetToken = (): Effect.Effect<string, Errors.AuthError> =>
	Effect.sync(() => crypto.randomBytes(32).toString("base64url"))

const validatePasswordLength = (
	newPassword: string,
	minPasswordLength: number,
	maxPasswordLength: number
): Effect.Effect<void, Errors.PasswordResetError> =>
	Effect.gen(function* () {
		if (newPassword.length < minPasswordLength) {
			return yield* Effect.fail(
				new Errors.PasswordResetError({
					message: `Password must be at least ${minPasswordLength} characters`
				})
			)
		}

		if (newPassword.length > maxPasswordLength) {
			return yield* Effect.fail(
				new Errors.PasswordResetError({
					message: `Password must be at most ${maxPasswordLength} characters`
				})
			)
		}
	})

export const makePasswordResetService = (
	config: PasswordResetConfig
): Effect.Effect<PasswordResetService, never> => {
	const expiresIn = config.expiresIn ?? 60 * 60 * 1000
	const minPasswordLength = config.minPasswordLength ?? 8
	const maxPasswordLength = config.maxPasswordLength ?? 128
	const revokeSessionsOnPasswordReset = config.revokeSessionsOnPasswordReset ?? false

	return Effect.sync(
		(): PasswordResetService => ({
			requestPasswordReset: (email: string) =>
				Effect.gen(function* () {
					const resetStore = yield* PasswordResetStoreTag
					const userStore = yield* PasswordResetUserStoreTag
					const normalizedEmail = normalizeEmail(email)

					if (!normalizedEmail) {
						return
					}

					const user = yield* userStore.getUserByEmail(normalizedEmail)

					// Do not reveal whether the user exists to reduce email enumeration risk.
					if (!user) {
						return
					}

					yield* resetStore.deleteByUserId(user.id)

					const token = yield* generateResetToken()
					const reset: PasswordResetToken = {
						token,
						userId: user.id,
						email: normalizedEmail,
						createdAt: Date.now(),
						expiresAt: Date.now() + expiresIn
					}

					yield* resetStore.create(reset)

					yield* Effect.catchAll(
						config.sendResetPassword(normalizedEmail, token),
						(error) =>
							Effect.fail(
								new Errors.PasswordResetError({
									message: `Failed to send reset password email to ${normalizedEmail}`,
									cause: error
								})
							)
					)
				}),

			resetPassword: (token: string, newPassword: string) =>
				Effect.gen(function* () {
					const resetStore = yield* PasswordResetStoreTag
					const userStore = yield* PasswordResetUserStoreTag
					const passwordHasher = yield* PasswordHasherTag

					if (!token) {
						return yield* Effect.fail(
							new Errors.PasswordResetError({
								message: "Invalid password reset token"
							})
						)
					}

					yield* validatePasswordLength(
						newPassword,
						minPasswordLength,
						maxPasswordLength
					)

					const reset = yield* resetStore.get(token)
					if (!reset) {
						return yield* Effect.fail(
							new Errors.PasswordResetError({
								message: "Invalid or expired password reset token"
							})
						)
					}

					if (Date.now() > reset.expiresAt) {
						yield* resetStore.delete(token)
						return yield* Effect.fail(
							new Errors.PasswordResetError({
								message: "Password reset token has expired"
							})
						)
					}

					const hashedPassword = yield* passwordHasher.hash(newPassword)
					yield* userStore.setPasswordHash(reset.userId, hashedPassword.hash)

					yield* resetStore.delete(token)

					if (revokeSessionsOnPasswordReset) {
						const sessionManager = yield* SessionManagerTag
						yield* sessionManager.invalidateUserSessions(reset.userId)
					}

					return {
						userId: reset.userId,
						email: reset.email,
						reset: true
					} satisfies PasswordResetResult
				})
		})
	)
}

export const PasswordResetServiceLayer = (config: PasswordResetConfig) =>
	Layer.effect(PasswordResetServiceTag, makePasswordResetService(config))
