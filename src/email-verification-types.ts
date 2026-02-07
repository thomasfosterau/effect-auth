/**
 * Email verification types for effect-auth
 */

import * as Effect from "effect/Effect"
import type { AuthError, EmailVerificationError, RateLimitError } from "./errors.js"

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
  ) => Effect.Effect<{ token: string; expiresAt: number }, AuthError>

  readonly verifyToken: (
    token: string
  ) => Effect.Effect<EmailVerificationResult, EmailVerificationError | AuthError>

  readonly resendVerification: (
    userId: string
  ) => Effect.Effect<void, AuthError | RateLimitError>
}
