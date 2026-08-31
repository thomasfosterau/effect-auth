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
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { claimIdentifier, IdentifierStore, makeIdentifier } from "../Identifier.ts";
import { UserStore } from "../UserStore.ts";
import type { HookError } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../SessionService.ts";
import { constantTimeHashEqual, hashToken } from "../TokenHash.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";

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
 * Input for creating a user during email OTP sign-in
 */
/**
 * Profile fields for a user created during OTP sign-in. The email itself is
 * recorded as a verified `Identifier` by the service.
 */
export interface EmailOtpCreateUserInput {
  readonly name?: string;
}

/**
 * Storage interface for email OTPs. There is at most one active OTP per
 * email + purpose pair; `upsert` replaces any existing record for the pair.
 */
export class EmailOtpStore extends Context.Service<
  EmailOtpStore,
  {
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
>()("@effect-auth/EmailOtpStore") {}

/**
 * User store interface for email OTP sign-in
 */
export class EmailOtpUserStore extends Context.Service<
  EmailOtpUserStore,
  {
    readonly createUser: (
      input: EmailOtpCreateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError>;
  }
>()("@effect-auth/EmailOtpUserStore") {}

/**
 * Email OTP service configuration
 */
export interface EmailOtpConfig {
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
export class EmailOtpService extends Context.Service<
  EmailOtpService,
  {
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
      purpose: EmailOtpPurpose,
    ) => Effect.Effect<void, Errors.AuthError | EmailOtpError | Errors.ResendTooSoonError>;

    /**
     * Verify a `"sign-in"` OTP and create a session. Users created here are
     * marked `emailVerified: true` (the OTP proves ownership of the email).
     */
    readonly signIn: (
      email: string,
      otp: string,
      options?: EmailOtpSignInOptions,
    ) => Effect.Effect<EmailOtpAuthResult, EmailOtpError | Errors.AuthError | HookError>;

    /**
     * Verify an OTP for any purpose (single use) without creating a session.
     * Intended for `"email-verification"` and `"forget-password"` flows to
     * consume before performing their own follow-up work.
     */
    readonly check: (
      email: string,
      otp: string,
      purpose: EmailOtpPurpose,
    ) => Effect.Effect<EmailOtpCheckResult, EmailOtpError | Errors.AuthError>;
  }
>()("@effect-auth/EmailOtpService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailOtpConfig) =>
    Layer.effect(EmailOtpService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/** @deprecated Use {@link hashToken} from `"effect-auth"` instead. */
export const hashOtp = hashToken;

/**
 * Generate a numeric OTP with crypto-secure randomness (one unbiased
 * `randomIntBetween` draw per digit — no modulo bias).
 */
export const generateOtp = (crypto: Crypto.Crypto, length: number): Effect.Effect<string> =>
  Effect.gen(function* () {
    let otp = "";
    for (let i = 0; i < length; i++) {
      const digit = yield* crypto.randomIntBetween(0, 10, { halfOpen: true });
      otp += digit.toString();
    }
    return otp;
  });

/**
 * Create an email OTP service
 */
export const make = (
  config: EmailOtpConfig,
): Effect.Effect<
  typeof EmailOtpService.Service,
  never,
  EmailOtpStore | EmailOtpUserStore | IdentifierStore | UserStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const otpLength = config.otpLength ?? 6;
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000; // 5 minutes default
    const maxAttempts = config.maxAttempts ?? 3;
    const disableSignUp = config.disableSignUp ?? false;

    const store = yield* EmailOtpStore;
    const userStore = yield* EmailOtpUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

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
    ): Effect.Effect<void, EmailOtpError | Errors.AuthError> =>
      Effect.gen(function* () {
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

    return {
      send: Effect.fn("EmailOtpService.send")(function* (
        rawEmail: string,
        purpose: EmailOtpPurpose,
      ) {
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
          const identifier = yield* identifiers.getByValue("email", email);
          if (!identifier) {
            return;
          }
        }

        if (purpose === "forget-password") {
          const identifier = yield* identifiers.getByValue("email", email);
          if (!identifier) {
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

        const otp = yield* generateOtp(crypto, otpLength);
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

      signIn: Effect.fn("EmailOtpService.signIn")(function* (
        rawEmail: string,
        otp: string,
        options?: EmailOtpSignInOptions,
      ) {
        const email = normalizeEmail(rawEmail);

        yield* verifyOtp(email, otp, "sign-in");

        const identifier = yield* identifiers.getByValue("email", email);
        let user = identifier === null ? null : yield* users.get(identifier.userId);
        if (identifier !== null && user === null) {
          return yield* Effect.fail(new EmailOtpError({ message: "Account is unavailable" }));
        }
        if (!user) {
          if (disableSignUp) {
            return yield* Effect.fail(
              new EmailOtpError({
                message: "Sign-up is disabled",
              }),
            );
          }

          // A verified OTP proves ownership of the email.
          user = yield* userStore.createUser({});
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId: user.id,
              type: "email",
              value: email,
              verified: true,
              verifiedAt: new Date(),
            }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new EmailOtpError({ message: "This email is already in use" })),
            ),
          );
        } else if (identifier !== null && !identifier.verified) {
          // The OTP proves ownership — promote the identifier to verified.
          yield* identifiers.setVerified(identifier.id, new Date());
        }

        const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

        return {
          user,
          session,
        } satisfies EmailOtpAuthResult;
      }),

      check: Effect.fn("EmailOtpService.check")(function* (
        rawEmail: string,
        otp: string,
        purpose: EmailOtpPurpose,
      ) {
        const email = normalizeEmail(rawEmail);

        yield* verifyOtp(email, otp, purpose);

        return {
          email,
          verified: true,
        } satisfies EmailOtpCheckResult;
      }),
    };
  });
