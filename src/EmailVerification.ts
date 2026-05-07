/**
 * Email verification types for effect-auth
 */

import { Context, Effect, Layer } from "effect"
import { AuthError, EmailVerificationError, type RateLimitError } from "./Errors.js"

/**
 * Email verification token
 */
export interface EmailVerification {
  readonly token: string
  readonly userId: string
  readonly email: string
  readonly createdAt: number
  readonly expiresAt: number
}

/**
 * Email verification result
 */
export interface EmailVerificationResult {
  readonly userId: string
  readonly email: string
  readonly verified: boolean
}

/**
 * Storage interface for email verifications
 */
export interface EmailVerificationStore {
  readonly create: (
    verification: EmailVerification
  ) => Effect.Effect<EmailVerification, AuthError>
  readonly get: (
    token: string
  ) => Effect.Effect<EmailVerification | null, AuthError>
  readonly delete: (token: string) => Effect.Effect<void, AuthError>
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>
}

/**
 * Email verification service configuration
 */
export interface EmailVerificationConfig {
  readonly expiresIn?: number // Default: 24 hours
  readonly sendEmail: (
    to: string,
    token: string
  ) => Effect.Effect<void, EmailVerificationError>
}

/**
 * Email verification service
 */
export interface EmailVerificationService {
  readonly createVerification: (
    userId: string,
    email: string
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | EmailVerificationError,
    EmailVerificationStoreTag
  >

  readonly verifyToken: (
    token: string
  ) => Effect.Effect<
    EmailVerificationResult,
    EmailVerificationError | AuthError,
    EmailVerificationStoreTag
  >

  readonly resendVerification: (
    userId: string
  ) => Effect.Effect<
    void,
    AuthError | RateLimitError | EmailVerificationError,
    EmailVerificationStoreTag
  >
}

/**
 * Email verification service implementation
 *
 * Provides token-based email verification with secure random tokens,
 * configurable expiration, and rate limiting support.
 *
 * @module email-verification
 */
import * as crypto from "node:crypto"

/**
 * Email verification store context tag
 */
export class EmailVerificationStoreTag extends Context.Tag("@effect-auth/EmailVerificationStore")<
  EmailVerificationStoreTag,
  EmailVerificationStore
>() { }

// Public ergonomic alias
export const EmailVerificationStore = EmailVerificationStoreTag

export class EmailVerificationServiceTag extends Context.Tag("@effect-auth/EmailVerificationService")<
  EmailVerificationServiceTag,
  EmailVerificationService
>() { }

// Public ergonomic alias
export const EmailVerificationService = EmailVerificationServiceTag

/**
 * Generate a cryptographically secure verification token
 */
export const generateVerificationToken = (): Effect.Effect<string, AuthError> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"))

/**
 * Create an email verification service
 */
export const makeEmailVerificationService = (
  config: EmailVerificationConfig
): Effect.Effect<EmailVerificationService, never> => {
  const expiresIn = config.expiresIn ?? 24 * 60 * 60 * 1000 // 24 hours default

  return Effect.sync(
    (): EmailVerificationService => ({
      createVerification: (userId: string, email: string) =>
        Effect.gen(function* () {
          const store = yield* EmailVerificationStoreTag
          const token = yield* generateVerificationToken()

          const verification: EmailVerification = {
            token,
            userId,
            email,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn
          }

          yield* store.create(verification)

          // Send verification email
          yield* Effect.catchAll(
            config.sendEmail(email, token),
            (error) =>
              Effect.fail(
                new EmailVerificationError({
                  message: `Failed to send verification email to ${email}`,
                  cause: error
                })
              )
          )

          return {
            token,
            expiresAt: verification.expiresAt
          }
        }),

      verifyToken: (token: string) =>
        Effect.gen(function* () {
          const store = yield* EmailVerificationStoreTag

          const verification = yield* store.get(token)

          if (!verification) {
            return yield* Effect.fail(
              new EmailVerificationError({
                message: "Invalid or expired verification token"
              })
            )
          }

          // Check expiration
          if (Date.now() > verification.expiresAt) {
            yield* store.delete(token)
            return yield* Effect.fail(
              new EmailVerificationError({
                message: "Verification token has expired"
              })
            )
          }

          // Delete token after successful verification (one-time use)
          yield* store.delete(token)

          return {
            userId: verification.userId,
            email: verification.email,
            verified: true
          } satisfies EmailVerificationResult
        }),

      resendVerification: (_userId: string) =>
        Effect.fail(
          new EmailVerificationError({
            message:
              "resendVerification is not fully implemented: please use createVerification with the user's email address instead"
          })
        )
    })
  )
}

export const EmailVerificationServiceLayer = (
  config: EmailVerificationConfig
) =>
  Layer.effect(EmailVerificationServiceTag, makeEmailVerificationService(config))
