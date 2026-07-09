/**
 * Email OTP sign-in and verification for effect-auth.
 *
 * Implements one-time numeric codes delivered by email (better-auth
 * "email OTP" parity) for three purposes: sign-in, email verification, and
 * password reset. Only a SHA-256 hash of the code is stored; codes are
 * single-use, expire, and are attempt-limited. Comparison is constant-time.
 *
 * @module email-otp
 */
import { randomInt } from "node:crypto";
import { Context, Data, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { SessionService } from "../session/SessionService.ts";
import { constantTimeHashEqual, hashToken } from "../TokenHash.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";

/**
 * Email OTP error
 */
export class EmailOTPError extends Data.TaggedError("EmailOTPError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * The purposes an email OTP can be issued for
 */
export type EmailOTPPurpose = "sign-in" | "email-verification" | "forget-password";

/**
 * Stored email OTP record. Only the SHA-256 hash of the code is persisted.
 */
export interface EmailOTPRecord {
  readonly email: string;
  readonly otpHash: string;
  readonly purpose: EmailOTPPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Storage interface for email OTPs. There is at most one active OTP per
 * email + purpose pair; `upsert` replaces any existing record for the pair.
 */
export interface EmailOTPStoreShape {
  readonly upsert: (record: EmailOTPRecord) => Effect.Effect<EmailOTPRecord, Errors.AuthError>;
  readonly get: (
    email: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<EmailOTPRecord | null, Errors.AuthError>;
  readonly delete: (
    email: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    email: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<number, Errors.AuthError>;
}

/**
 * Input for creating a user during email OTP sign-in
 */
export interface EmailOTPCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
}

/**
 * User store interface for email OTP sign-in
 */
export interface EmailOTPUserStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: EmailOTPCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
}

/**
 * Email OTP store context tag
 */
export class EmailOTPStore extends Context.Service<EmailOTPStore, EmailOTPStoreShape>()(
  "@effect-auth/EmailOtpStore",
) {}

/**
 * Email OTP user store context tag
 */
export class EmailOTPUserStore extends Context.Service<EmailOTPUserStore, EmailOTPUserStoreShape>()(
  "@effect-auth/EmailOtpUserStore",
) {}

/**
 * Email OTP service configuration
 */
export interface EmailOTPConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  /**
   * Minimum interval (ms) between successive send requests for the same email
   * + purpose pair. When an outstanding OTP created within this window already
   * exists, `send` fails with {@link Errors.ResendTooSoonError}. Off by
   * default. Complements the global RateLimit.
   */
  readonly resendCooldown?: number;
  readonly sendVerificationOTP: (
    email: string,
    otp: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Options for email OTP sign-in
 */
export interface EmailOTPSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Result of a successful email OTP sign-in
 */
export interface EmailOTPAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

/**
 * Result of a successful generic OTP check
 */
export interface EmailOTPCheckResult {
  readonly email: string;
  readonly verified: true;
}

/**
 * Email OTP service
 */
export interface EmailOTPServiceShape {
  /**
   * Generate an OTP for the given email + purpose (replacing any outstanding
   * one) and send it. Only a SHA-256 hash of the code is stored.
   *
   * Anti-enumeration: for `"sign-in"` with sign-up disabled and no matching
   * user, and for `"forget-password"` with no matching user, this succeeds
   * silently without sending anything.
   *
   * When `resendCooldown` is configured and an outstanding OTP for the email +
   * purpose was created within the cooldown window, fails with
   * {@link Errors.ResendTooSoonError} containing the remaining wait time.
   */
  readonly send: (
    email: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<
    void,
    Errors.AuthError | EmailOTPError | Errors.ResendTooSoonError,
    EmailOTPStore | EmailOTPUserStore
  >;

  /**
   * Verify a `"sign-in"` OTP and create a session. Users created here are
   * marked `emailVerified: true` (the OTP proves ownership of the email).
   */
  readonly signIn: (
    email: string,
    otp: string,
    options?: EmailOTPSignInOptions,
  ) => Effect.Effect<
    EmailOTPAuthResult,
    EmailOTPError | Errors.AuthError | HookError,
    EmailOTPStore | EmailOTPUserStore | SessionService | Hooks
  >;

  /**
   * Verify an OTP for any purpose (single use) without creating a session.
   * Intended for `"email-verification"` and `"forget-password"` flows to
   * consume before performing their own follow-up work.
   */
  readonly check: (
    email: string,
    otp: string,
    purpose: EmailOTPPurpose,
  ) => Effect.Effect<EmailOTPCheckResult, EmailOTPError | Errors.AuthError, EmailOTPStore>;
}

export class EmailOTPService extends Context.Service<EmailOTPService, EmailOTPServiceShape>()(
  "@effect-auth/EmailOtpService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailOTPConfig) =>
    Layer.effect(EmailOTPService, makeEmailOTPService(config));
}

/** @deprecated Use {@link hashToken} from `"effect-auth"` instead. */
export const hashOTP = hashToken;

/**
 * Generate a numeric OTP with crypto-secure randomness (one uniform
 * `crypto.randomInt` draw per digit).
 */
export const generateOTP = (length: number): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => {
    let otp = "";
    for (let i = 0; i < length; i++) {
      otp += randomInt(0, 10).toString();
    }
    return otp;
  });

/**
 * Create an email OTP service
 */
export const makeEmailOTPService = (
  config: EmailOTPConfig,
): Effect.Effect<EmailOTPServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000; // 5 minutes default
  const maxAttempts = config.maxAttempts ?? 3;
  const disableSignUp = config.disableSignUp ?? false;

  const invalidOTP = () =>
    Effect.fail(
      new EmailOTPError({
        message: "Invalid or expired OTP",
      }),
    );

  /**
   * Core verification: expiry, attempt limiting, constant-time hash
   * comparison, and one-time-use consumption on success.
   */
  const verifyOTP = (
    email: string,
    otp: string,
    purpose: EmailOTPPurpose,
  ): Effect.Effect<void, EmailOTPError | Errors.AuthError, EmailOTPStore> =>
    Effect.gen(function* () {
      const store = yield* EmailOTPStore;

      if (!email || !otp) {
        return yield* invalidOTP();
      }

      const record = yield* store.get(email, purpose);
      if (!record) {
        return yield* invalidOTP();
      }

      // Check expiration
      if (Date.now() > record.expiresAt) {
        yield* store.delete(email, purpose);
        return yield* Effect.fail(
          new EmailOTPError({
            message: "OTP has expired",
          }),
        );
      }

      // Defensive: a record that already exhausted its attempts is unusable.
      if (record.attempts >= maxAttempts) {
        yield* store.delete(email, purpose);
        return yield* Effect.fail(
          new EmailOTPError({
            message: "Too many attempts",
          }),
        );
      }

      if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
        const attempts = yield* store.incrementAttempts(email, purpose);
        if (attempts >= maxAttempts) {
          yield* store.delete(email, purpose);
          return yield* Effect.fail(
            new EmailOTPError({
              message: "Too many attempts",
            }),
          );
        }
        return yield* invalidOTP();
      }

      // Consume the OTP (one-time use)
      yield* store.delete(email, purpose);
    });

  return Effect.sync(
    (): EmailOTPServiceShape => ({
      send: (rawEmail: string, purpose: EmailOTPPurpose) =>
        Effect.gen(function* () {
          const store = yield* EmailOTPStore;
          const userStore = yield* EmailOTPUserStore;

          const email = normalizeEmail(rawEmail);
          if (!email) {
            return;
          }

          // Do not reveal whether the user exists to reduce email enumeration
          // risk: succeed silently (without sending) for sign-in when sign-up
          // is disabled and no user exists, and for forget-password when no
          // user exists. Sign-in with sign-up enabled always sends (the user
          // is created at verification time).
          if (purpose === "sign-in" && disableSignUp) {
            const user = yield* userStore.getUserByEmail(email);
            if (!user) {
              return;
            }
          }

          if (purpose === "forget-password") {
            const user = yield* userStore.getUserByEmail(email);
            if (!user) {
              return;
            }
          }

          // Resend cooldown: reject if an outstanding OTP was created within
          // the configured window. The identifier (email) is already known to
          // the caller, so this is not an enumeration risk.
          if (config.resendCooldown !== undefined) {
            const existing = yield* store.get(email, purpose);
            if (existing !== null) {
              const elapsed = Date.now() - existing.createdAt;
              if (elapsed < config.resendCooldown) {
                return yield* Effect.fail(
                  new Errors.ResendTooSoonError({
                    message: "Please wait before requesting another OTP",
                    retryAfter: config.resendCooldown - elapsed,
                  }),
                );
              }
            }
          }

          const otp = yield* generateOTP(otpLength);
          const record: EmailOTPRecord = {
            email,
            otpHash: hashToken(otp),
            purpose,
            attempts: 0,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn,
          };

          // One active OTP per email + purpose: replaces any outstanding one.
          yield* store.upsert(record);

          yield* Effect.catch(config.sendVerificationOTP(email, otp, purpose), (error) =>
            Effect.fail(
              new EmailOTPError({
                message: `Failed to send OTP to ${email}`,
                cause: error,
              }),
            ),
          );
        }),

      signIn: (rawEmail: string, otp: string, options?: EmailOTPSignInOptions) =>
        Effect.gen(function* () {
          const userStore = yield* EmailOTPUserStore;
          const sessionManager = yield* SessionService;

          const email = normalizeEmail(rawEmail);

          yield* verifyOTP(email, otp, "sign-in");

          let user = yield* userStore.getUserByEmail(email);
          if (!user) {
            if (disableSignUp) {
              return yield* Effect.fail(
                new EmailOTPError({
                  message: "Sign-up is disabled",
                }),
              );
            }

            // A verified OTP proves ownership of the email.
            user = yield* userStore.createUser({
              email,
              emailVerified: true,
            });
          }

          const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

          return {
            user,
            session,
          } satisfies EmailOTPAuthResult;
        }),

      check: (rawEmail: string, otp: string, purpose: EmailOTPPurpose) =>
        Effect.gen(function* () {
          const email = normalizeEmail(rawEmail);

          yield* verifyOTP(email, otp, purpose);

          return {
            email,
            verified: true,
          } satisfies EmailOTPCheckResult;
        }),
    }),
  );
};
