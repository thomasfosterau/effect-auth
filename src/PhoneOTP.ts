/**
 * Phone number authentication via SMS one-time passwords.
 *
 * Mirrors `EmailOTP.ts` (hashed OTP at rest, attempt limiting, purpose scoping,
 * anti-enumeration) — only the channel (SMS) and the user-lookup key (phone
 * number) differ. Two purposes are supported: `sign-in` and
 * `phone-verification`.
 *
 * Convention: phone identity lives in `attributes.phoneNumber` /
 * `attributes.phoneNumberVerified` (there is no first-class `User.phoneNumber`
 * column). Use {@link getPhoneNumber} to read it.
 *
 * E.164 normalization is application policy: the default `normalizePhoneNumber`
 * only trims whitespace. Apps should plug a real E.164 normalizer via config.
 */
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { SessionService } from "./session/SessionService.ts";

/** Error raised by phone OTP verification failures. */
export class PhoneOTPError extends Data.TaggedError("PhoneOTPError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** The purposes a phone OTP can be issued for. */
export type PhoneOTPPurpose = "sign-in" | "phone-verification";

/** Stored phone OTP record. Only the SHA-256 hash of the code is persisted. */
export interface PhoneOTPRecord {
  readonly phoneNumber: string;
  readonly otpHash: string;
  readonly purpose: PhoneOTPPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Persistence for phone OTPs, keyed by the (normalized phoneNumber, purpose)
 * pair; `upsert` replaces any existing record for the pair.
 */
export class PhoneOTPStore extends Context.Service<
  PhoneOTPStore,
  {
    readonly upsert: (record: PhoneOTPRecord) => Effect.Effect<PhoneOTPRecord, Errors.AuthError>;
    readonly get: (
      phoneNumber: string,
      purpose: PhoneOTPPurpose,
    ) => Effect.Effect<PhoneOTPRecord | null, Errors.AuthError>;
    readonly delete: (
      phoneNumber: string,
      purpose: PhoneOTPPurpose,
    ) => Effect.Effect<void, Errors.AuthError>;
    readonly incrementAttempts: (
      phoneNumber: string,
      purpose: PhoneOTPPurpose,
    ) => Effect.Effect<number, Errors.AuthError>;
  }
>()("@effect-auth/PhoneOTPStore") {}

/** Input for creating a user from a verified phone number. */
export interface PhoneOTPCreateUserInput {
  readonly phoneNumber: string;
  readonly phoneNumberVerified: boolean;
  readonly name?: string;
}

/**
 * User lookup/creation keyed by phone number. Implementers store the number in
 * `attributes.phoneNumber` and the verification flag in
 * `attributes.phoneNumberVerified`.
 */
export class PhoneOTPUserStore extends Context.Service<
  PhoneOTPUserStore,
  {
    readonly getUserByPhoneNumber: (
      phoneNumber: string,
    ) => Effect.Effect<Types.User | null, Errors.AuthError>;
    readonly createUser: (
      input: PhoneOTPCreateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError>;
    readonly setPhoneNumberVerified: (
      userId: string,
      phoneNumber: string,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;
  }
>()("@effect-auth/PhoneOTPUserStore") {}

export interface PhoneOTPConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  /**
   * Minimum interval (ms) between successive send requests for the same phone
   * number + purpose pair. When an outstanding OTP created within this window
   * already exists, `send` fails with {@link Errors.ResendTooSoonError}. Off
   * by default; recommend 60_000 (60 s) for SMS to limit carrier cost and
   * DoS exposure. Complements the global RateLimit.
   */
  readonly resendCooldown?: number;
  readonly sendOTP: (
    phoneNumber: string,
    otp: string,
    purpose: PhoneOTPPurpose,
  ) => Effect.Effect<void, unknown>;
  /**
   * Normalize a raw phone number before storage/lookup. Default trims
   * whitespace only — plug a real E.164 normalizer here.
   */
  readonly normalizePhoneNumber?: (raw: string) => Effect.Effect<string, Errors.AuthError>;
}

export interface PhoneOTPSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface PhoneOTPAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

export interface PhoneOTPServiceShape {
  /**
   * Generate an OTP for the given phone number + purpose (replacing any
   * outstanding one) and send it. Only a SHA-256 hash of the code is stored.
   * Anti-enumeration: for `sign-in` with sign-up disabled and no user, this
   * succeeds silently without sending.
   *
   * When `resendCooldown` is configured and an outstanding OTP for the phone +
   * purpose was created within the cooldown window, fails with
   * {@link Errors.ResendTooSoonError} containing the remaining wait time.
   */
  readonly send: (
    phoneNumber: string,
    purpose: PhoneOTPPurpose,
  ) => Effect.Effect<
    void,
    PhoneOTPError | Errors.AuthError | Errors.ResendTooSoonError,
    PhoneOTPStore | PhoneOTPUserStore
  >;

  /**
   * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
   * `phoneNumberVerified: true` user when none exists (unless `disableSignUp`).
   */
  readonly signIn: (
    phoneNumber: string,
    otp: string,
    options?: PhoneOTPSignInOptions,
  ) => Effect.Effect<
    PhoneOTPAuthResult,
    PhoneOTPError | Errors.AuthError | HookError,
    PhoneOTPStore | PhoneOTPUserStore | SessionService | Hooks
  >;

  /**
   * Verify a `phone-verification` OTP (single use) for an existing user and
   * mark their phone number verified.
   */
  readonly verifyPhoneNumber: (
    userId: string,
    phoneNumber: string,
    otp: string,
  ) => Effect.Effect<
    Types.User,
    PhoneOTPError | Errors.AuthError | Errors.UserNotFoundError,
    PhoneOTPStore | PhoneOTPUserStore
  >;
}

export class PhoneOTPService extends Context.Service<PhoneOTPService, PhoneOTPServiceShape>()(
  "@effect-auth/PhoneOtpService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PhoneOTPConfig) =>
    Layer.effect(PhoneOTPService, makePhoneOTPService(config));
}

/** Read the phone number from a user's attributes, or `null`. */
export const getPhoneNumber = (user: Types.User): string | null => {
  const value = user.attributes["phoneNumber"];
  return typeof value === "string" ? value : null;
};

/** Generate a numeric OTP with crypto-secure randomness. */
const generateOTP = (length: number): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => {
    let otp = "";
    for (let i = 0; i < length; i++) otp += crypto.randomInt(0, 10).toString();
    return otp;
  });

export const makePhoneOTPService = (
  config: PhoneOTPConfig,
): Effect.Effect<PhoneOTPServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
  const maxAttempts = config.maxAttempts ?? 3;
  const disableSignUp = config.disableSignUp ?? false;

  const normalize = (raw: string): Effect.Effect<string, Errors.AuthError> =>
    config.normalizePhoneNumber !== undefined
      ? config.normalizePhoneNumber(raw)
      : Effect.succeed(raw.trim());

  const invalidOTP = () => Effect.fail(new PhoneOTPError({ message: "Invalid or expired OTP" }));

  const verifyOTP = (
    phoneNumber: string,
    otp: string,
    purpose: PhoneOTPPurpose,
  ): Effect.Effect<void, PhoneOTPError | Errors.AuthError, PhoneOTPStore> =>
    Effect.gen(function* () {
      const store = yield* PhoneOTPStore;

      if (!phoneNumber || !otp) {
        return yield* invalidOTP();
      }

      const record = yield* store.get(phoneNumber, purpose);
      if (!record) {
        return yield* invalidOTP();
      }

      if (Date.now() > record.expiresAt) {
        yield* store.delete(phoneNumber, purpose);
        return yield* Effect.fail(new PhoneOTPError({ message: "OTP has expired" }));
      }

      if (record.attempts >= maxAttempts) {
        yield* store.delete(phoneNumber, purpose);
        return yield* Effect.fail(new PhoneOTPError({ message: "Too many attempts" }));
      }

      if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
        const attempts = yield* store.incrementAttempts(phoneNumber, purpose);
        if (attempts >= maxAttempts) {
          yield* store.delete(phoneNumber, purpose);
          return yield* Effect.fail(new PhoneOTPError({ message: "Too many attempts" }));
        }
        return yield* invalidOTP();
      }

      // Consume the OTP (one-time use).
      yield* store.delete(phoneNumber, purpose);
    });

  return Effect.sync(
    (): PhoneOTPServiceShape => ({
      send: (rawPhoneNumber, purpose) =>
        Effect.gen(function* () {
          const store = yield* PhoneOTPStore;
          const userStore = yield* PhoneOTPUserStore;

          const phoneNumber = yield* normalize(rawPhoneNumber);
          if (!phoneNumber) {
            return;
          }

          // Anti-enumeration: sign-in with sign-up disabled and no user, and
          // phone-verification with no user, succeed silently without sending.
          if (purpose === "sign-in" && disableSignUp) {
            const user = yield* userStore.getUserByPhoneNumber(phoneNumber);
            if (!user) {
              return;
            }
          }

          // Resend cooldown: reject if an outstanding OTP was created within
          // the configured window. The identifier (phone number) is already
          // known to the caller, so this is not an enumeration risk.
          if (config.resendCooldown !== undefined) {
            const existing = yield* store.get(phoneNumber, purpose);
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
          const record: PhoneOTPRecord = {
            phoneNumber,
            otpHash: hashToken(otp),
            purpose,
            attempts: 0,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn,
          };

          yield* store.upsert(record);

          yield* Effect.catch(config.sendOTP(phoneNumber, otp, purpose), (error) =>
            Effect.fail(
              new PhoneOTPError({ message: `Failed to send OTP to ${phoneNumber}`, cause: error }),
            ),
          );
        }),

      signIn: (rawPhoneNumber, otp, options) =>
        Effect.gen(function* () {
          const userStore = yield* PhoneOTPUserStore;
          const sessionManager = yield* SessionService;

          const phoneNumber = yield* normalize(rawPhoneNumber);

          yield* verifyOTP(phoneNumber, otp, "sign-in");

          let user = yield* userStore.getUserByPhoneNumber(phoneNumber);
          if (!user) {
            if (disableSignUp) {
              return yield* Effect.fail(new PhoneOTPError({ message: "Sign-up is disabled" }));
            }
            // A verified OTP proves ownership of the phone number.
            user = yield* userStore.createUser({ phoneNumber, phoneNumberVerified: true });
          }

          const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

          return { user, session } satisfies PhoneOTPAuthResult;
        }),

      verifyPhoneNumber: (userId, rawPhoneNumber, otp) =>
        Effect.gen(function* () {
          const userStore = yield* PhoneOTPUserStore;
          const phoneNumber = yield* normalize(rawPhoneNumber);

          yield* verifyOTP(phoneNumber, otp, "phone-verification");

          return yield* userStore.setPhoneNumberVerified(userId, phoneNumber);
        }),
    }),
  );
};
