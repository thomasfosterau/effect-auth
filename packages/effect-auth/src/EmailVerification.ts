/**
 * Email verification types for effect-auth
 */

import { Context, Effect, Layer } from "effect";
import { AuthError, EmailVerificationError, type RateLimitError } from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";

/**
 * Email verification token
 */
export interface EmailVerification {
  readonly token: string;
  readonly userId: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Email verification result
 */
export interface EmailVerificationResult {
  readonly userId: string;
  readonly email: string;
  readonly verified: boolean;
}

/**
 * Storage interface for email verifications
 */
export interface EmailVerificationStoreShape {
  readonly create: (verification: EmailVerification) => Effect.Effect<EmailVerification, AuthError>;
  readonly get: (token: string) => Effect.Effect<EmailVerification | null, AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>;
}

/**
 * Email verification service configuration
 */
export interface EmailVerificationConfig {
  readonly expiresIn?: number; // Default: 24 hours
  readonly sendEmail: (to: string, token: string) => Effect.Effect<void, EmailVerificationError>;
}

/**
 * Email verification service
 */
export interface EmailVerificationServiceShape {
  readonly createVerification: (
    userId: string,
    email: string,
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | EmailVerificationError | HookError,
    EmailVerificationStore | Hooks
  >;

  readonly verifyToken: (
    token: string,
  ) => Effect.Effect<
    EmailVerificationResult,
    EmailVerificationError | AuthError | HookError,
    EmailVerificationStore | Hooks
  >;

  /**
   * Invalidate any outstanding verification tokens for the user and send a
   * fresh one. Combine with the rate-limiter (e.g.
   * `RateLimitPresets.emailVerification`) to prevent abuse.
   */
  readonly resendVerification: (
    userId: string,
    email: string,
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | RateLimitError | EmailVerificationError | HookError,
    EmailVerificationStore | Hooks
  >;
}

/**
 * Email verification service implementation
 *
 * Provides token-based email verification with secure random tokens,
 * configurable expiration, and rate limiting support.
 *
 * @module email-verification
 */
import * as crypto from "node:crypto";

/**
 * Email verification store context tag
 */
export class EmailVerificationStore extends Context.Service<
  EmailVerificationStore,
  EmailVerificationStoreShape
>()("@effect-auth/EmailVerificationStore") {}

export class EmailVerificationService extends Context.Service<
  EmailVerificationService,
  EmailVerificationServiceShape
>()("@effect-auth/EmailVerificationService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailVerificationConfig) =>
    Layer.effect(EmailVerificationService, makeEmailVerificationService(config));
}

/**
 * Generate a cryptographically secure verification token
 */
export const generateVerificationToken = (): Effect.Effect<string, AuthError> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"));

/**
 * Create an email verification service
 */
export const makeEmailVerificationService = (
  config: EmailVerificationConfig,
): Effect.Effect<EmailVerificationServiceShape, never> => {
  const expiresIn = config.expiresIn ?? 24 * 60 * 60 * 1000; // 24 hours default

  const createVerification = (rawUserId: string, rawEmail: string) =>
    Effect.gen(function* () {
      const hooks = yield* Hooks;
      const { userId, email } = yield* hooks.beforeCreateVerification({
        userId: rawUserId,
        email: rawEmail,
      });

      const store = yield* EmailVerificationStore;
      const token = yield* generateVerificationToken();

      const verification: EmailVerification = {
        token,
        userId,
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + expiresIn,
      };

      yield* store.create(verification);

      // Send verification email
      yield* Effect.catch(config.sendEmail(email, token), (error) =>
        Effect.fail(
          new EmailVerificationError({
            message: `Failed to send verification email to ${email}`,
            cause: error,
          }),
        ),
      );

      yield* hooks.afterCreateVerification({ userId, email });

      return {
        token,
        expiresAt: verification.expiresAt,
      };
    });

  return Effect.sync(
    (): EmailVerificationServiceShape => ({
      createVerification,

      verifyToken: (rawToken: string) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const { token } = yield* hooks.beforeVerifyEmail({ token: rawToken });

          const store = yield* EmailVerificationStore;

          const verification = yield* store.get(token);

          if (!verification) {
            return yield* Effect.fail(
              new EmailVerificationError({
                message: "Invalid or expired verification token",
              }),
            );
          }

          // Check expiration
          if (Date.now() > verification.expiresAt) {
            yield* store.delete(token);
            return yield* Effect.fail(
              new EmailVerificationError({
                message: "Verification token has expired",
              }),
            );
          }

          // Delete token after successful verification (one-time use)
          yield* store.delete(token);

          const result = {
            userId: verification.userId,
            email: verification.email,
            verified: true,
          } satisfies EmailVerificationResult;

          return yield* hooks.afterVerifyEmail(result);
        }),

      resendVerification: (userId: string, email: string) =>
        Effect.gen(function* () {
          const store = yield* EmailVerificationStore;
          // Invalidate outstanding tokens so only the latest one is usable.
          yield* store.deleteByUserId(userId);
          return yield* createVerification(userId, email);
        }),
    }),
  );
};
