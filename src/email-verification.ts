/**
 * Email verification service implementation
 *
 * Provides token-based email verification with secure random tokens,
 * configurable expiration, and rate limiting support.
 *
 * @module email-verification
 */

import { Context, Effect } from "effect"
import * as crypto from "node:crypto"
import { AuthError, EmailVerificationError } from "./errors.js"
import type {
  EmailVerification,
  EmailVerificationStore as EmailVerificationStoreType,
  EmailVerificationService,
  EmailVerificationConfig,
  EmailVerificationResult
} from "./email-verification-types.js"

/**
 * Email verification store context tag
 */
export const EmailVerificationStoreTag = Context.GenericTag<EmailVerificationStoreType>(
  "@effect-auth/EmailVerificationStore"
)

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

      resendVerification: (userId: string) =>
        Effect.gen(function* () {
          // Note: This is a stub implementation. In a real application,
          // you would need to retrieve the user's email address and call
          // createVerification. For now, we fail with a descriptive error.
          return yield* Effect.fail(
            new EmailVerificationError({
              message:
                "resendVerification is not fully implemented: please use createVerification with the user's email address instead"
            })
          )
        })
    })
  )
}
