/**
 * Phone number authentication via SMS one-time passwords.
 *
 * Mirrors `EmailOtp.ts` (hashed OTP at rest, attempt limiting, purpose scoping,
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
import * as Errors from "./Errors.js";
import type * as Types from "./Types.js";
import { SessionManager } from "./Session.js";
import { Hooks, type HookError } from "./Hooks.js";

/** Error raised by phone OTP verification failures. */
export class PhoneOtpError extends Data.TaggedError("PhoneOtpError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** The purposes a phone OTP can be issued for. */
export type PhoneOtpPurpose = "sign-in" | "phone-verification";

/** Stored phone OTP record. Only the SHA-256 hash of the code is persisted. */
export interface PhoneOtpRecord {
  readonly phoneNumber: string;
  readonly otpHash: string;
  readonly purpose: PhoneOtpPurpose;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Persistence for phone OTPs, keyed by the (normalized phoneNumber, purpose)
 * pair; `upsert` replaces any existing record for the pair.
 */
export interface PhoneOtpStoreShape {
  readonly upsert: (record: PhoneOtpRecord) => Effect.Effect<PhoneOtpRecord, Errors.AuthError>;
  readonly get: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<PhoneOtpRecord | null, Errors.AuthError>;
  readonly delete: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<number, Errors.AuthError>;
}

/** Input for creating a user from a verified phone number. */
export interface PhoneOtpCreateUserInput {
  readonly phoneNumber: string;
  readonly phoneNumberVerified: boolean;
  readonly name?: string;
}

/**
 * User lookup/creation keyed by phone number. Implementers store the number in
 * `attributes.phoneNumber` and the verification flag in
 * `attributes.phoneNumberVerified`.
 */
export interface PhoneOtpUserStoreShape {
  readonly getUserByPhoneNumber: (
    phoneNumber: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: PhoneOtpCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
  readonly setPhoneNumberVerified: (
    userId: string,
    phoneNumber: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;
}

export class PhoneOtpStore extends Context.Service<PhoneOtpStore, PhoneOtpStoreShape>()(
  "@effect-auth/PhoneOtpStore",
) {}

export class PhoneOtpUserStore extends Context.Service<PhoneOtpUserStore, PhoneOtpUserStoreShape>()(
  "@effect-auth/PhoneOtpUserStore",
) {}

export interface PhoneOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  readonly disableSignUp?: boolean; // Default: false
  readonly sendOtp: (
    phoneNumber: string,
    otp: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, unknown>;
  /**
   * Normalize a raw phone number before storage/lookup. Default trims
   * whitespace only — plug a real E.164 normalizer here.
   */
  readonly normalizePhoneNumber?: (raw: string) => Effect.Effect<string, Errors.AuthError>;
}

export interface PhoneOtpSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface PhoneOtpAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

export interface PhoneOtpServiceShape {
  /**
   * Generate an OTP for the given phone number + purpose (replacing any
   * outstanding one) and send it. Only a SHA-256 hash of the code is stored.
   * Anti-enumeration: for `sign-in` with sign-up disabled and no user, this
   * succeeds silently without sending.
   */
  readonly send: (
    phoneNumber: string,
    purpose: PhoneOtpPurpose,
  ) => Effect.Effect<void, PhoneOtpError | Errors.AuthError, PhoneOtpStore | PhoneOtpUserStore>;

  /**
   * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
   * `phoneNumberVerified: true` user when none exists (unless `disableSignUp`).
   */
  readonly signIn: (
    phoneNumber: string,
    otp: string,
    options?: PhoneOtpSignInOptions,
  ) => Effect.Effect<
    PhoneOtpAuthResult,
    PhoneOtpError | Errors.AuthError | HookError,
    PhoneOtpStore | PhoneOtpUserStore | SessionManager | Hooks
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
    PhoneOtpError | Errors.AuthError | Errors.UserNotFoundError,
    PhoneOtpStore | PhoneOtpUserStore
  >;
}

export class PhoneOtpService extends Context.Service<PhoneOtpService, PhoneOtpServiceShape>()(
  "@effect-auth/PhoneOtpService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PhoneOtpConfig) =>
    Layer.effect(PhoneOtpService, makePhoneOtpService(config));
}

/** Read the phone number from a user's attributes, or `null`. */
export const getPhoneNumber = (user: Types.User): string | null => {
  const value = user.attributes["phoneNumber"];
  return typeof value === "string" ? value : null;
};

/** SHA-256 hex digest of an OTP code. */
const hashOtp = (otp: string): string => crypto.createHash("sha256").update(otp).digest("hex");

const constantTimeHashEqual = (a: string, b: string): boolean => {
  const bufferA = Buffer.from(a, "hex");
  const bufferB = Buffer.from(b, "hex");
  if (bufferA.length !== bufferB.length) return false;
  return crypto.timingSafeEqual(bufferA, bufferB);
};

/** Generate a numeric OTP with crypto-secure randomness. */
const generateOtp = (length: number): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => {
    let otp = "";
    for (let i = 0; i < length; i++) otp += crypto.randomInt(0, 10).toString();
    return otp;
  });

export const makePhoneOtpService = (
  config: PhoneOtpConfig,
): Effect.Effect<PhoneOtpServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
  const maxAttempts = config.maxAttempts ?? 3;
  const disableSignUp = config.disableSignUp ?? false;

  const normalize = (raw: string): Effect.Effect<string, Errors.AuthError> =>
    config.normalizePhoneNumber !== undefined
      ? config.normalizePhoneNumber(raw)
      : Effect.succeed(raw.trim());

  const invalidOtp = () => Effect.fail(new PhoneOtpError({ message: "Invalid or expired OTP" }));

  const verifyOtp = (
    phoneNumber: string,
    otp: string,
    purpose: PhoneOtpPurpose,
  ): Effect.Effect<void, PhoneOtpError | Errors.AuthError, PhoneOtpStore> =>
    Effect.gen(function* () {
      const store = yield* PhoneOtpStore;

      if (!phoneNumber || !otp) {
        return yield* invalidOtp();
      }

      const record = yield* store.get(phoneNumber, purpose);
      if (!record) {
        return yield* invalidOtp();
      }

      if (Date.now() > record.expiresAt) {
        yield* store.delete(phoneNumber, purpose);
        return yield* Effect.fail(new PhoneOtpError({ message: "OTP has expired" }));
      }

      if (record.attempts >= maxAttempts) {
        yield* store.delete(phoneNumber, purpose);
        return yield* Effect.fail(new PhoneOtpError({ message: "Too many attempts" }));
      }

      if (!constantTimeHashEqual(record.otpHash, hashOtp(otp))) {
        const attempts = yield* store.incrementAttempts(phoneNumber, purpose);
        if (attempts >= maxAttempts) {
          yield* store.delete(phoneNumber, purpose);
          return yield* Effect.fail(new PhoneOtpError({ message: "Too many attempts" }));
        }
        return yield* invalidOtp();
      }

      // Consume the OTP (one-time use).
      yield* store.delete(phoneNumber, purpose);
    });

  return Effect.sync(
    (): PhoneOtpServiceShape => ({
      send: (rawPhoneNumber, purpose) =>
        Effect.gen(function* () {
          const store = yield* PhoneOtpStore;
          const userStore = yield* PhoneOtpUserStore;

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

          const otp = yield* generateOtp(otpLength);
          const record: PhoneOtpRecord = {
            phoneNumber,
            otpHash: hashOtp(otp),
            purpose,
            attempts: 0,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn,
          };

          yield* store.upsert(record);

          yield* Effect.catch(config.sendOtp(phoneNumber, otp, purpose), (error) =>
            Effect.fail(
              new PhoneOtpError({ message: `Failed to send OTP to ${phoneNumber}`, cause: error }),
            ),
          );
        }),

      signIn: (rawPhoneNumber, otp, options) =>
        Effect.gen(function* () {
          const userStore = yield* PhoneOtpUserStore;
          const sessionManager = yield* SessionManager;

          const phoneNumber = yield* normalize(rawPhoneNumber);

          yield* verifyOtp(phoneNumber, otp, "sign-in");

          let user = yield* userStore.getUserByPhoneNumber(phoneNumber);
          if (!user) {
            if (disableSignUp) {
              return yield* Effect.fail(new PhoneOtpError({ message: "Sign-up is disabled" }));
            }
            // A verified OTP proves ownership of the phone number.
            user = yield* userStore.createUser({ phoneNumber, phoneNumberVerified: true });
          }

          const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

          return { user, session } satisfies PhoneOtpAuthResult;
        }),

      verifyPhoneNumber: (userId, rawPhoneNumber, otp) =>
        Effect.gen(function* () {
          const userStore = yield* PhoneOtpUserStore;
          const phoneNumber = yield* normalize(rawPhoneNumber);

          yield* verifyOtp(phoneNumber, otp, "phone-verification");

          return yield* userStore.setPhoneNumberVerified(userId, phoneNumber);
        }),
    }),
  );
};
