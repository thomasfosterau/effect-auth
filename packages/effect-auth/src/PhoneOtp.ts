/**
 * Phone number authentication via SMS one-time passwords.
 *
 * Mirrors `EmailOtp.ts` (hashed OTP at rest, attempt limiting, purpose scoping,
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
import {
  Array as Arr,
  Clock,
  Context,
  Crypto,
  Data,
  DateTime,
  Duration,
  Effect,
  Layer,
  Order,
} from "effect";
import * as Errors from "./Errors.ts";
import {
  claimIdentifier,
  IdentifierStore,
  makeIdentifier,
  refusalAuthError,
} from "./Identifier.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "./UserStore.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { makeDetachedSend } from "./DeliveryScheduler.ts";
import { type HookError } from "./Hooks.ts";
import { SessionService } from "./SessionService.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";

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
export class PhoneOtpStore extends Context.Service<
  PhoneOtpStore,
  {
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
>()("@effect-auth/PhoneOtpStore") {}

/**
 * Fields for a user created during phone OTP sign-in. The phone number itself
 * is recorded as a verified `phone` `Identifier` by the service, and
 * `identifier` carries it to the store as well.
 */
export interface PhoneOtpCreateUserInput {
  readonly name?: string;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier | undefined;
}

/** User creation seam for phone-OTP sign-up. */
export class PhoneOtpUserStore extends Context.Service<
  PhoneOtpUserStore,
  {
    /**
     * Create a user. `created` in the result is `true` only when this call
     * inserted the user; a user that already existed (as a find-or-create on
     * the address returns) reports `false`, and sign-up then fails without
     * writing to it. The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly createUser: (
      input: PhoneOtpCreateUserInput,
    ) => Effect.Effect<CreateUserResult, Errors.AuthError>;
  }
>()("@effect-auth/PhoneOtpUserStore") {}

/** Why an OTP verification failed: no record, a wrong code, expiry or the attempt limit. */
type VerifyFailure = "missing" | "mismatch" | "expired" | "attempts";

/** The generic answer to a failed verification. */
const invalidOtpMessage = "Invalid or expired OTP";

/** The message each verification failure answers where existence isn't hidden. */
const failureMessages: Record<VerifyFailure, string> = {
  missing: invalidOtpMessage,
  mismatch: invalidOtpMessage,
  expired: "OTP has expired",
  attempts: "Too many attempts",
};

/**
 * Configuration for {@link PhoneOtpService}.
 */
export interface PhoneOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  /**
   * Refuse to create a user at `sign-in`. Off by default. When set, `sign-in`
   * hides whether a number has an account: see {@link PhoneOtpService} `send`
   * and `signIn`.
   */
  readonly disableSignUp?: boolean;
  /**
   * Minimum interval (ms) between successive send requests for the same phone
   * number + purpose pair. When an outstanding OTP created within this window
   * already exists, `send` fails with {@link Errors.ResendTooSoonError}. Off
   * by default; recommend 60_000 (60 s) for SMS to limit carrier cost and
   * DoS exposure. Complements the global RateLimit. It applies to every
   * number alike, whether or not it has an account, so the error reveals
   * nothing about which numbers are registered. With sign-up disabled, a
   * `sign-in` request for a number with no account stores an undelivered
   * marker record, so if that number gains an account within the window,
   * its first `sign-in` send is delayed by up to the cooldown.
   */
  readonly resendCooldown?: number;
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

/** Options for {@link PhoneOtpService.signIn}. */
export interface PhoneOtpSignInOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/** The user and session issued by a phone OTP sign-in. */
export interface PhoneOtpAuthResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

/**
 * Sign-in and phone-number verification by SMS one-time code. Codes are stored hashed, with an attempt limit.
 *
 * Requires `PhoneOtpStore`, `PhoneOtpUserStore`, `UserStore`, `IdentifierStore` and `SessionService`.
 */
export class PhoneOtpService extends Context.Service<
  PhoneOtpService,
  {
    /**
     * Generate an OTP for the given phone number + purpose (replacing any
     * outstanding one) and send it. Only a SHA-256 hash of the code is stored.
     * Anti-enumeration: for `sign-in` with sign-up disabled and no user, this
     * succeeds without sending. It stores an undelivered marker record in
     * place of the code: the record holds the hash of a random 32-byte secret
     * that is never sent, so no code redeems it, and it expires and counts
     * attempts exactly as a code's record does. `signIn` then sees the same
     * record states for a number with and without an account.
     *
     * When `resendCooldown` is configured and an outstanding OTP for the phone +
     * purpose was created within the cooldown window, fails with
     * {@link Errors.ResendTooSoonError} containing the remaining wait time.
     * The marker record makes the cooldown apply to a number with no account
     * as well, so a repeat within the window fails the same way for a known
     * and an unknown number.
     */
    readonly send: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<void, PhoneOtpError | Errors.AuthError | Errors.ResendTooSoonError>;

    /**
     * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
     * user with a verified `phone` identifier when none exists (unless `disableSignUp`).
     *
     * A code that fails verification fails with {@link PhoneOtpError}. With
     * sign-up disabled, each such failure answers `"Invalid or expired OTP"`,
     * whether the code was wrong, had expired or reached `maxAttempts`, so the
     * answer is the same for a number with and without an outstanding code.
     * With sign-up enabled, an expired code answers `"OTP has expired"` and
     * the attempt limit answers `"Too many attempts"`.
     */
    readonly signIn: (
      phoneNumber: string,
      otp: string,
      options?: PhoneOtpSignInOptions,
    ) => Effect.Effect<PhoneOtpAuthResult, PhoneOtpError | Errors.AuthError | HookError>;

    /**
     * Verify a `phone-verification` OTP (single use) for an existing user and
     * mark their phone number verified.
     */
    readonly verifyPhoneNumber: (
      userId: string,
      phoneNumber: string,
      otp: string,
    ) => Effect.Effect<Types.User, PhoneOtpError | Errors.AuthError | Errors.UserNotFoundError>;
  }
>()("@effect-auth/PhoneOtpService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PhoneOtpConfig) =>
    Layer.effect(PhoneOtpService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
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
    const phones = Arr.sort(
      all.filter((id) => id.type === "phone"),
      Order.mapInput(Order.Number, (id: (typeof all)[number]) => id.createdAt.getTime()),
    );
    return (phones.find((id) => id.verified) ?? phones[0])?.value ?? null;
  });

export const make = (
  config: PhoneOtpConfig,
): Effect.Effect<
  typeof PhoneOtpService.Service,
  never,
  PhoneOtpStore | PhoneOtpUserStore | IdentifierStore | UserStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const otpLength = config.otpLength ?? 6;
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
    const maxAttempts = config.maxAttempts ?? 3;
    const disableSignUp = config.disableSignUp ?? false;

    const store = yield* PhoneOtpStore;
    const userStore = yield* PhoneOtpUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;
    const detached = yield* makeDetachedSend;

    /** Generate a numeric OTP with crypto-secure, unbiased randomness. */
    const generateOtp = (length: number): Effect.Effect<string> =>
      Effect.map(
        Effect.replicateEffect(
          crypto.randomIntBetween(0, 10, { halfOpen: true }),
          // The iteration count of `for (let i = 0; i < length; i++)`.
          Math.max(0, Math.ceil(length)),
          { concurrency: 1 },
        ),
        (digits) => digits.map((digit) => digit.toString()).join(""),
      );

    /**
     * The secret behind an unknown number's marker record: 32 random bytes,
     * base64url-encoded. It is hashed into the marker record and then
     * discarded.
     */
    const generateMarkerSecret: Effect.Effect<string, Errors.AuthError> = randomBase64UrlToken(
      crypto,
      "Failed to generate OTP marker",
    );

    const normalize = (raw: string): Effect.Effect<string, Errors.AuthError> =>
      config.normalizePhoneNumber !== undefined
        ? config.normalizePhoneNumber(raw)
        : Effect.succeed(raw.trim());

    /**
     * Whether `send` hides, for this purpose, whether the number has an
     * account. It then answers alike for both, and verification must too.
     */
    const hidesAccount = (purpose: PhoneOtpPurpose): boolean =>
      purpose === "sign-in" && disableSignUp;

    /**
     * Fail a verification. Where `send` hides whether the number has an
     * account, every reason answers the generic message. The marker record
     * already gives a known and an unknown number the same record states; the
     * generic message also makes one that holds a record answer as one that
     * holds none, so expiry and the attempt limit can't show whether a code
     * was requested for it. The reason stays on the span for operators.
     */
    const rejectOtp = (purpose: PhoneOtpPurpose, reason: VerifyFailure) =>
      Effect.annotateCurrentSpan("auth.otp.failure", reason).pipe(
        Effect.andThen(
          Effect.fail(
            new PhoneOtpError({
              message: hidesAccount(purpose) ? invalidOtpMessage : failureMessages[reason],
            }),
          ),
        ),
      );

    const verifyOtp = (
      phoneNumber: string,
      otp: string,
      purpose: PhoneOtpPurpose,
    ): Effect.Effect<void, PhoneOtpError | Errors.AuthError> =>
      Effect.gen(function* () {
        if (!phoneNumber || !otp) {
          return yield* rejectOtp(purpose, "missing");
        }

        const record = yield* store.get(phoneNumber, purpose);
        if (!record) {
          return yield* rejectOtp(purpose, "missing");
        }

        if ((yield* Clock.currentTimeMillis) > record.expiresAt) {
          yield* store.delete(phoneNumber, purpose);
          return yield* rejectOtp(purpose, "expired");
        }

        if (record.attempts >= maxAttempts) {
          yield* store.delete(phoneNumber, purpose);
          return yield* rejectOtp(purpose, "attempts");
        }

        if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
          const attempts = yield* store.incrementAttempts(phoneNumber, purpose);
          if (attempts >= maxAttempts) {
            yield* store.delete(phoneNumber, purpose);
            return yield* rejectOtp(purpose, "attempts");
          }
          return yield* rejectOtp(purpose, "mismatch");
        }

        // Consume the OTP (one-time use).
        yield* store.delete(phoneNumber, purpose);
      });

    return {
      send: Effect.fn("PhoneOtpService.send")(function* (
        rawPhoneNumber: string,
        purpose: PhoneOtpPurpose,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);
        if (!phoneNumber) {
          return;
        }

        // Anti-enumeration: sign-in with sign-up disabled and no user
        // succeeds without sending.
        const deliver = hidesAccount(purpose)
          ? (yield* identifiers.getByValue("phone", phoneNumber)) !== null
          : true;

        // Resend cooldown: reject if an outstanding OTP was created within
        // the configured window. It runs for a number with no account too,
        // whose earlier request stored an undelivered record below, so a known
        // and an unknown number get the same answer inside the window.
        if (config.resendCooldown !== undefined) {
          const existing = yield* store.get(phoneNumber, purpose);
          if (existing !== null) {
            const elapsed = (yield* Clock.currentTimeMillis) - existing.createdAt;
            if (elapsed < config.resendCooldown) {
              return yield* new Errors.ResendTooSoonError({
                message: "Please wait before requesting another OTP",
                retryAfter: Duration.millis(config.resendCooldown - elapsed),
              });
            }
          }
        }

        // A number with no account gets a marker record, whose hash is of a
        // random 32-byte secret rather than of a code: no `otpLength`-digit
        // guess can match it, and the secret is never sent. It is written
        // whether or not a cooldown is set, with the same attempts and expiry
        // as a code's record, so both branches do the same store work here
        // and verification later sees the same record states. Both values are
        // drawn on every send, so the random work is the same too.
        const otp = yield* generateOtp(otpLength);
        const markerSecret = yield* generateMarkerSecret;
        const record: PhoneOtpRecord = {
          phoneNumber,
          otpHash: hashToken(deliver ? otp : markerSecret),
          purpose,
          attempts: 0,
          createdAt: yield* Clock.currentTimeMillis,
          expiresAt: (yield* Clock.currentTimeMillis) + expiresIn,
        };

        yield* store.upsert(record);

        if (!deliver) {
          return;
        }

        // With sign-up disabled, only a known number gets a code, so an inline
        // send would answer it later, and fail it when the vendor does: the
        // send goes off the response path (#196).
        if (hidesAccount(purpose)) {
          return yield* detached(`phone-otp:${purpose}`, config.sendOtp(phoneNumber, otp, purpose));
        }
        yield* Effect.catch(config.sendOtp(phoneNumber, otp, purpose), (error) =>
          Effect.fail(
            new PhoneOtpError({ message: `Failed to send OTP to ${phoneNumber}`, cause: error }),
          ),
        );
      }),

      signIn: Effect.fn("PhoneOtpService.signIn")(function* (
        rawPhoneNumber: string,
        otp: string,
        options?: PhoneOtpSignInOptions,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);

        yield* verifyOtp(phoneNumber, otp, "sign-in");

        const identifier = yield* identifiers.getByValue("phone", phoneNumber);
        let user = identifier === null ? null : yield* users.get(identifier.userId);
        if (identifier !== null && user === null) {
          return yield* new PhoneOtpError({ message: "Account is unavailable" });
        }
        if (!user) {
          if (disableSignUp) {
            return yield* new PhoneOtpError({ message: "Sign-up is disabled" });
          }
          // A verified OTP proves ownership of the phone number.
          const created = yield* createUserWithIdentifier(
            identifiers,
            {
              type: "phone",
              value: phoneNumber,
              verified: true,
              verifiedAt: yield* DateTime.nowAsDate,
            },
            (identifier) => userStore.createUser({ identifier }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new PhoneOtpError({ message: "This phone number is already in use" })),
            ),
          );
          user = created.user;
        } else if (identifier !== null && !identifier.verified) {
          // The OTP proves ownership — promote the identifier to verified.
          yield* identifiers.setVerified(identifier.id, yield* DateTime.nowAsDate);
        }

        const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

        return { user, session } satisfies PhoneOtpAuthResult;
      }),

      verifyPhoneNumber: Effect.fn("PhoneOtpService.verifyPhoneNumber")(function* (
        userId: string,
        rawPhoneNumber: string,
        otp: string,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);

        yield* verifyOtp(phoneNumber, otp, "phone-verification");

        // Attach (or verify) the phone identifier for this user.
        const existing = yield* identifiers.getByValue("phone", phoneNumber);
        if (existing !== null && existing.userId !== userId) {
          return yield* new PhoneOtpError({ message: "This phone number is already in use" });
        }
        if (existing === null) {
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId,
              type: "phone",
              value: phoneNumber,
              verified: true,
              verifiedAt: yield* DateTime.nowAsDate,
            }),
          ).pipe(
            Effect.catchTags({
              IdentifierTakenError: () =>
                Effect.fail(new PhoneOtpError({ message: "This phone number is already in use" })),
              IdentifierRefusedError: (error) => Effect.fail(refusalAuthError(error)),
            }),
          );
        } else if (!existing.verified) {
          yield* identifiers.setVerified(existing.id, yield* DateTime.nowAsDate);
        }

        const user = yield* users.get(userId);
        if (user === null) {
          return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
        }
        return user;
      }),
    };
  });
