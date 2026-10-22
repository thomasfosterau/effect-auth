/**
 * Email verification types for effect-auth
 */

import { Context, Crypto, Effect, Layer } from "effect";
import { AuthError, EmailVerificationError, type RateLimitError } from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";

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
 * Email verification service configuration
 */
export interface EmailVerificationConfig {
  readonly expiresIn?: number; // Default: 24 hours
  readonly sendEmail: (to: string, token: string) => Effect.Effect<void, EmailVerificationError>;
}

/**
 * Email verification service implementation
 *
 * Provides token-based email verification with secure random tokens,
 * configurable expiration, and rate limiting support.
 *
 * @module email-verification
 */
import { hashToken } from "../TokenHash.ts";
import { randomBase64UrlToken } from "../RandomToken.ts";

/**
 * Storage interface for email verifications
 */
export class EmailVerificationStore extends Context.Service<
  EmailVerificationStore,
  {
    readonly create: (
      verification: EmailVerification,
    ) => Effect.Effect<EmailVerification, AuthError>;
    readonly get: (token: string) => Effect.Effect<EmailVerification | null, AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, AuthError>;
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/EmailVerificationStore") {}

/**
 * Email verification service
 */
export class EmailVerificationService extends Context.Service<
  EmailVerificationService,
  {
    readonly createVerification: (
      userId: string,
      email: string,
    ) => Effect.Effect<
      { token: string; expiresAt: number },
      AuthError | EmailVerificationError | HookError
    >;

    readonly verifyToken: (
      token: string,
    ) => Effect.Effect<EmailVerificationResult, EmailVerificationError | AuthError | HookError>;

    /**
     * Validate a token (run `beforeVerifyEmail` hook, check expiry) without
     * burning it. Returns the raw `EmailVerification` record so callers can
     * perform additional checks (e.g. email-change guard) before committing the
     * durable state change. Call `burnToken` afterward to complete the flow.
     */
    readonly peekToken: (
      rawToken: string,
    ) => Effect.Effect<EmailVerification, EmailVerificationError | AuthError | HookError>;

    /**
     * Delete the token from the store and fire the `afterVerifyEmail` hook.
     * Intended to be called AFTER the durable state change (e.g.
     * `markEmailVerified`) has succeeded, so a store failure before that point
     * leaves the token valid and the user can retry.
     *
     * The `token` parameter is the stored hash, as returned in
     * `EmailVerification.token` by `peekToken`.
     */
    readonly burnToken: (
      token: string,
      result: EmailVerificationResult,
    ) => Effect.Effect<EmailVerificationResult, AuthError | HookError>;

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
      AuthError | RateLimitError | EmailVerificationError | HookError
    >;
  }
>()("@effect-auth/EmailVerificationService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailVerificationConfig) =>
    Layer.effect(EmailVerificationService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Generate a cryptographically secure verification token
 */
export const generateVerificationToken = (
  crypto: Crypto.Crypto,
): Effect.Effect<string, AuthError> =>
  randomBase64UrlToken(crypto, "Failed to generate verification token");

/**
 * Create an email verification service
 */
export const make = (
  config: EmailVerificationConfig,
): Effect.Effect<
  typeof EmailVerificationService.Service,
  never,
  EmailVerificationStore | Hooks | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 24 * 60 * 60 * 1000; // 24 hours default
    const store = yield* EmailVerificationStore;
    const hooks = yield* Hooks;
    const crypto = yield* Crypto.Crypto;

    const createVerification = Effect.fn("EmailVerificationService.createVerification")(function* (
      rawUserId: string,
      rawEmail: string,
    ) {
      const { userId, email } = yield* hooks.beforeCreateVerification({
        userId: rawUserId,
        email: rawEmail,
      });

      const rawToken = yield* generateVerificationToken(crypto);

      const verification: EmailVerification = {
        // Store the hash — the raw token is delivered to the user via sendEmail.
        token: hashToken(rawToken),
        userId,
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + expiresIn,
      };

      yield* store.create(verification);

      // Send verification email with the raw token.
      yield* Effect.catch(config.sendEmail(email, rawToken), (error) =>
        Effect.fail(
          new EmailVerificationError({
            message: `Failed to send verification email to ${email}`,
            cause: error,
          }),
        ),
      );

      yield* hooks.afterCreateVerification({ userId, email });

      return {
        token: rawToken,
        expiresAt: verification.expiresAt,
      };
    });

    return {
      createVerification,

      verifyToken: Effect.fn("EmailVerificationService.verifyToken")(function* (rawToken: string) {
        // Hook receives the raw token from the URL; hash after any hook transform.
        const { token } = yield* hooks.beforeVerifyEmail({ token: rawToken });

        const tokenHash = hashToken(token);

        const verification = yield* store.get(tokenHash);

        if (!verification) {
          return yield* new EmailVerificationError({
            message: "Invalid or expired verification token",
          });
        }

        // Check expiration
        if (Date.now() > verification.expiresAt) {
          yield* store.delete(tokenHash);
          return yield* new EmailVerificationError({
            message: "Verification token has expired",
          });
        }

        // Delete token after successful verification (one-time use)
        yield* store.delete(tokenHash);

        const result = {
          userId: verification.userId,
          email: verification.email,
          verified: true,
        } satisfies EmailVerificationResult;

        return yield* hooks.afterVerifyEmail(result);
      }),

      peekToken: Effect.fn("EmailVerificationService.peekToken")(function* (rawToken: string) {
        const { token } = yield* hooks.beforeVerifyEmail({ token: rawToken });
        const tokenHash = hashToken(token);
        const verification = yield* store.get(tokenHash);
        if (!verification) {
          return yield* new EmailVerificationError({
            message: "Invalid or expired verification token",
          });
        }
        if (Date.now() > verification.expiresAt) {
          yield* store.delete(tokenHash);
          return yield* new EmailVerificationError({
            message: "Verification token has expired",
          });
        }
        return verification;
      }),

      burnToken: Effect.fn("EmailVerificationService.burnToken")(function* (
        token: string,
        result: EmailVerificationResult,
      ) {
        yield* store.delete(token);
        return yield* hooks.afterVerifyEmail(result);
      }),

      resendVerification: Effect.fn("EmailVerificationService.resendVerification")(function* (
        userId: string,
        email: string,
      ) {
        // Invalidate outstanding tokens so only the latest one is usable.
        yield* store.deleteByUserId(userId);
        return yield* createVerification(userId, email);
      }),
    };
  });
