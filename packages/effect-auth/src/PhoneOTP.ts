/**
 * Phone number authentication via SMS one-time passwords.
 *
 * Mirrors `EmailOTP.ts` (hashed OTP at rest, attempt limiting, purpose scoping,
 * anti-enumeration) — only the channel (SMS) and the user-lookup key (phone
 * number) differ. Two purposes are supported: `sign-in` and
 * `phone-verification`.
 *
 * Phone identity lives in a `phone` `Identifier` (globally unique, E.164 by
 * app policy) — there is no `User.phoneNumber` field or attribute convention.
 * Use {@link getPhoneNumber} to read a user's phone identifier.
 *
 * E.164 normalization is application policy: the default `normalizePhoneNumber`
 * only trims whitespace. Apps should plug a real E.164 normalizer via config.
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { claimIdentifier, IdentifierStore, makeIdentifier } from "./Identifier.ts";
import { UserStore } from "./session/UserStore.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { type HookError } from "./Hooks.ts";
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

/**
 * Profile fields for a user created during phone OTP sign-in. The phone number
 * itself is recorded as a verified `phone` `Identifier` by the service.
 */
export interface PhoneOTPCreateUserInput {
  readonly name?: string;
}

/** User creation seam for phone-OTP sign-up. */
export class PhoneOTPUserStore extends Context.Service<
  PhoneOTPUserStore,
  {
    readonly createUser: (
      input: PhoneOTPCreateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError>;
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

export class PhoneOTPService extends Context.Service<
  PhoneOTPService,
  {
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
    ) => Effect.Effect<void, PhoneOTPError | Errors.AuthError | Errors.ResendTooSoonError>;

    /**
     * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
     * user with a verified `phone` identifier when none exists (unless `disableSignUp`).
     */
    readonly signIn: (
      phoneNumber: string,
      otp: string,
      options?: PhoneOTPSignInOptions,
    ) => Effect.Effect<PhoneOTPAuthResult, PhoneOTPError | Errors.AuthError | HookError>;

    /**
     * Verify a `phone-verification` OTP (single use) for an existing user and
     * mark their phone number verified.
     */
    readonly verifyPhoneNumber: (
      userId: string,
      phoneNumber: string,
      otp: string,
    ) => Effect.Effect<Types.User, PhoneOTPError | Errors.AuthError | Errors.UserNotFoundError>;
  }
>()("@effect-auth/PhoneOTPService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PhoneOTPConfig) =>
    Layer.effect(PhoneOTPService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Resolve a user's phone number from their `phone` identifier, or `null`.
 * Prefers a verified phone identifier; falls back to the earliest unverified
 * one.
 */
export const getPhoneNumber = (
  identifierStore: typeof IdentifierStore.Service,
  userId: string,
): Effect.Effect<string | null, Errors.AuthError> =>
  Effect.map(identifierStore.listByUser(userId), (all) => {
    const phones = all
      .filter((id) => id.type === "phone")
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    return (phones.find((id) => id.verified) ?? phones[0])?.value ?? null;
  });

export const make = (
  config: PhoneOTPConfig,
): Effect.Effect<
  typeof PhoneOTPService.Service,
  never,
  PhoneOTPStore | PhoneOTPUserStore | IdentifierStore | UserStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const otpLength = config.otpLength ?? 6;
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
    const maxAttempts = config.maxAttempts ?? 3;
    const disableSignUp = config.disableSignUp ?? false;

    const store = yield* PhoneOTPStore;
    const userStore = yield* PhoneOTPUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    /** Generate a numeric OTP with crypto-secure, unbiased randomness. */
    const generateOTP = (length: number): Effect.Effect<string> =>
      Effect.gen(function* () {
        let otp = "";
        for (let i = 0; i < length; i++) {
          const digit = yield* crypto.randomIntBetween(0, 10, { halfOpen: true });
          otp += digit.toString();
        }
        return otp;
      });

    const normalize = (raw: string): Effect.Effect<string, Errors.AuthError> =>
      config.normalizePhoneNumber !== undefined
        ? config.normalizePhoneNumber(raw)
        : Effect.succeed(raw.trim());

    const invalidOTP = () => Effect.fail(new PhoneOTPError({ message: "Invalid or expired OTP" }));

    const verifyOTP = (
      phoneNumber: string,
      otp: string,
      purpose: PhoneOTPPurpose,
    ): Effect.Effect<void, PhoneOTPError | Errors.AuthError> =>
      Effect.gen(function* () {
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

    return {
      send: Effect.fn("PhoneOTPService.send")(function* (
        rawPhoneNumber: string,
        purpose: PhoneOTPPurpose,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);
        if (!phoneNumber) {
          return;
        }

        // Anti-enumeration: sign-in with sign-up disabled and no user, and
        // phone-verification with no user, succeed silently without sending.
        if (purpose === "sign-in" && disableSignUp) {
          const identifier = yield* identifiers.getByValue("phone", phoneNumber);
          if (!identifier) {
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

      signIn: Effect.fn("PhoneOTPService.signIn")(function* (
        rawPhoneNumber: string,
        otp: string,
        options?: PhoneOTPSignInOptions,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);

        yield* verifyOTP(phoneNumber, otp, "sign-in");

        const identifier = yield* identifiers.getByValue("phone", phoneNumber);
        let user = identifier === null ? null : yield* users.get(identifier.userId);
        if (identifier !== null && user === null) {
          return yield* Effect.fail(new PhoneOTPError({ message: "Account is unavailable" }));
        }
        if (!user) {
          if (disableSignUp) {
            return yield* Effect.fail(new PhoneOTPError({ message: "Sign-up is disabled" }));
          }
          // A verified OTP proves ownership of the phone number.
          user = yield* userStore.createUser({});
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId: user.id,
              type: "phone",
              value: phoneNumber,
              verified: true,
              verifiedAt: new Date(),
            }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new PhoneOTPError({ message: "This phone number is already in use" })),
            ),
          );
        } else if (identifier !== null && !identifier.verified) {
          // The OTP proves ownership — promote the identifier to verified.
          yield* identifiers.setVerified(identifier.id, new Date());
        }

        const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

        return { user, session } satisfies PhoneOTPAuthResult;
      }),

      verifyPhoneNumber: Effect.fn("PhoneOTPService.verifyPhoneNumber")(function* (
        userId: string,
        rawPhoneNumber: string,
        otp: string,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);

        yield* verifyOTP(phoneNumber, otp, "phone-verification");

        // Attach (or verify) the phone identifier for this user.
        const existing = yield* identifiers.getByValue("phone", phoneNumber);
        if (existing !== null && existing.userId !== userId) {
          return yield* Effect.fail(
            new PhoneOTPError({ message: "This phone number is already in use" }),
          );
        }
        if (existing === null) {
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId,
              type: "phone",
              value: phoneNumber,
              verified: true,
              verifiedAt: new Date(),
            }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new PhoneOTPError({ message: "This phone number is already in use" })),
            ),
          );
        } else if (!existing.verified) {
          yield* identifiers.setVerified(existing.id, new Date());
        }

        const user = yield* users.get(userId);
        if (user === null) {
          return yield* Effect.fail(
            new Errors.UserNotFoundError({ message: "User not found", userId }),
          );
        }
        return user;
      }),
    };
  });
