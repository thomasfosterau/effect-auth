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
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { SessionManager } from "./Session.js";
import { constantTimeHashEqual, hashToken } from "./TokenHash.js";
import type * as Types from "./Types.js";
import { normalizeEmail } from "./utils.js";

/**
 * Email OTP error
 */
export class EmailOtpError extends Data.TaggedError("EmailOtpError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * The purposes an email OTP can be issued for
 */
export type EmailOtpPurpose = "sign-in" | "email-verification" | "forget-password";

/**
 * Stored email OTP record. Only the SHA-256 hash of the code is persisted.
 */
export interface EmailOtpRecord {
  readonly email: string;
  readonly otpHash: string;
  readonly purpose: EmailOtpPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Storage interface for email OTPs. There is at most one active OTP per
 * email + purpose pair; `upsert` replaces any existing record for the pair.
 */
export interface EmailOtpStoreShape {
  readonly upsert: (record: EmailOtpRecord) => Effect.Effect<EmailOtpRecord, Errors.AuthError>;
  readonly get: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<EmailOtpRecord | null, Errors.AuthError>;
  readonly delete: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<number, Errors.AuthError>;
}

/**
 * Input for creating a user during email OTP sign-in
 */
export interface EmailOtpCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
}

/**
 * User store interface for email OTP sign-in
 */
export interface EmailOtpUserStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: EmailOtpCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
}

/**
 * Email OTP store context tag
 */
export class EmailOtpStore extends Context.Service<EmailOtpStore, EmailOtpStoreShape>()(
  "@effect-auth/EmailOtpStore",
) {}

/**
 * Email OTP user store context tag
 */
export class EmailOtpUserStore extends Context.Service<EmailOtpUserStore, EmailOtpUserStoreShape>()(
  "@effect-auth/EmailOtpUserStore",
) {}

/**
 * Email OTP service configuration
 */
export interface EmailOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  readonly sendVerificationOtp: (
    email: string,
    otp: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Options for email OTP sign-in
 */
export interface EmailOtpSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Result of a successful email OTP sign-in
 */
export interface EmailOtpAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

/**
 * Result of a successful generic OTP check
 */
export interface EmailOtpCheckResult {
  readonly email: string;
  readonly verified: true;
}

/**
 * Email OTP service
 */
export interface EmailOtpServiceShape {
  /**
   * Generate an OTP for the given email + purpose (replacing any outstanding
   * one) and send it. Only a SHA-256 hash of the code is stored.
   *
   * Anti-enumeration: for `"sign-in"` with sign-up disabled and no matching
   * user, and for `"forget-password"` with no matching user, this succeeds
   * silently without sending anything.
   */
  readonly send: (
    email: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError | EmailOtpError, EmailOtpStore | EmailOtpUserStore>;

  /**
   * Verify a `"sign-in"` OTP and create a session. Users created here are
   * marked `emailVerified: true` (the OTP proves ownership of the email).
   */
  readonly signIn: (
    email: string,
    otp: string,
    options?: EmailOtpSignInOptions,
  ) => Effect.Effect<
    EmailOtpAuthResult,
    EmailOtpError | Errors.AuthError | HookError,
    EmailOtpStore | EmailOtpUserStore | SessionManager | Hooks
  >;

  /**
   * Verify an OTP for any purpose (single use) without creating a session.
   * Intended for `"email-verification"` and `"forget-password"` flows to
   * consume before performing their own follow-up work.
   */
  readonly check: (
    email: string,
    otp: string,
    purpose: EmailOtpPurpose,
  ) => Effect.Effect<EmailOtpCheckResult, EmailOtpError | Errors.AuthError, EmailOtpStore>;
}

export class EmailOtpService extends Context.Service<EmailOtpService, EmailOtpServiceShape>()(
  "@effect-auth/EmailOtpService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailOtpConfig) =>
    Layer.effect(EmailOtpService, makeEmailOtpService(config));
}

/** @deprecated Use {@link hashToken} from `"effect-auth"` instead. */
export const hashOtp = hashToken;

/**
 * Generate a numeric OTP with crypto-secure randomness (one uniform
 * `crypto.randomInt` draw per digit).
 */
export const generateOtp = (length: number): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => {
    let otp = "";
    for (let i = 0; i < length; i++) {
      otp += crypto.randomInt(0, 10).toString();
    }
    return otp;
  });

/**
 * Create an email OTP service
 */
export const makeEmailOtpService = (
  config: EmailOtpConfig,
): Effect.Effect<EmailOtpServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000; // 5 minutes default
  const maxAttempts = config.maxAttempts ?? 3;
  const disableSignUp = config.disableSignUp ?? false;

  const invalidOtp = () =>
    Effect.fail(
      new EmailOtpError({
        message: "Invalid or expired OTP",
      }),
    );

  /**
   * Core verification: expiry, attempt limiting, constant-time hash
   * comparison, and one-time-use consumption on success.
   */
  const verifyOtp = (
    email: string,
    otp: string,
    purpose: EmailOtpPurpose,
  ): Effect.Effect<void, EmailOtpError | Errors.AuthError, EmailOtpStore> =>
    Effect.gen(function* () {
      const store = yield* EmailOtpStore;

      if (!email || !otp) {
        return yield* invalidOtp();
      }

      const record = yield* store.get(email, purpose);
      if (!record) {
        return yield* invalidOtp();
      }

      // Check expiration
      if (Date.now() > record.expiresAt) {
        yield* store.delete(email, purpose);
        return yield* Effect.fail(
          new EmailOtpError({
            message: "OTP has expired",
          }),
        );
      }

      // Defensive: a record that already exhausted its attempts is unusable.
      if (record.attempts >= maxAttempts) {
        yield* store.delete(email, purpose);
        return yield* Effect.fail(
          new EmailOtpError({
            message: "Too many attempts",
          }),
        );
      }

      if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
        const attempts = yield* store.incrementAttempts(email, purpose);
        if (attempts >= maxAttempts) {
          yield* store.delete(email, purpose);
          return yield* Effect.fail(
            new EmailOtpError({
              message: "Too many attempts",
            }),
          );
        }
        return yield* invalidOtp();
      }

      // Consume the OTP (one-time use)
      yield* store.delete(email, purpose);
    });

  return Effect.sync(
    (): EmailOtpServiceShape => ({
      send: (rawEmail: string, purpose: EmailOtpPurpose) =>
        Effect.gen(function* () {
          const store = yield* EmailOtpStore;
          const userStore = yield* EmailOtpUserStore;

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

          const otp = yield* generateOtp(otpLength);
          const record: EmailOtpRecord = {
            email,
            otpHash: hashToken(otp),
            purpose,
            attempts: 0,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn,
          };

          // One active OTP per email + purpose: replaces any outstanding one.
          yield* store.upsert(record);

          yield* Effect.catch(config.sendVerificationOtp(email, otp, purpose), (error) =>
            Effect.fail(
              new EmailOtpError({
                message: `Failed to send OTP to ${email}`,
                cause: error,
              }),
            ),
          );
        }),

      signIn: (rawEmail: string, otp: string, options?: EmailOtpSignInOptions) =>
        Effect.gen(function* () {
          const userStore = yield* EmailOtpUserStore;
          const sessionManager = yield* SessionManager;

          const email = normalizeEmail(rawEmail);

          yield* verifyOtp(email, otp, "sign-in");

          let user = yield* userStore.getUserByEmail(email);
          if (!user) {
            if (disableSignUp) {
              return yield* Effect.fail(
                new EmailOtpError({
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
          } satisfies EmailOtpAuthResult;
        }),

      check: (rawEmail: string, otp: string, purpose: EmailOtpPurpose) =>
        Effect.gen(function* () {
          const email = normalizeEmail(rawEmail);

          yield* verifyOtp(email, otp, purpose);

          return {
            email,
            verified: true,
          } satisfies EmailOtpCheckResult;
        }),
    }),
  );
};
