/**
 * Phone sign-in and verification by SMS one-time code: the `EmailOtp` flows
 * over a `phone` identifier ({@link getPhoneNumber}). E.164 normalization is
 * the application's; the default `normalizePhoneNumber` only trims.
 */
import { Context, Data, DateTime, Effect, Layer, Order } from "effect";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import { Digest, Mac, SecureRandom } from "effect/crypto";
import * as Errors from "./Errors.ts";
import { sessionOrChallenge, type SessionOrChallenge } from "./email/EmailPassword.ts";
import {
  claimIdentifier,
  IdentifierStore,
  findIdentifierOwner,
  lookupIdentifier,
  makeIdentifier,
  refusalAuthError,
} from "./Identifier.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "./UserStore.ts";
import * as OtpCode from "./OtpCode.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as RootSecret from "./RootSecret.ts";
import type { RateLimitStore } from "./RateLimit.ts";
import { makeRecipientSendGate } from "./RecipientSendLimit.ts";
import type * as Types from "./Types.ts";
import { makeDetachedSend } from "./DeliveryScheduler.ts";
import { deliverCode } from "./CodeDelivery.ts";
import { Hooks, type HookError, type SendCodeOptions } from "./Hooks.ts";
import { SessionService } from "./SessionService.ts";
import { definedKeys } from "./DefinedKeys.ts";

/** Error raised by phone OTP verification failures. */
export class PhoneOtpError extends Data.TaggedError("PhoneOtpError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** The purposes a phone OTP can be issued for. */
export type PhoneOtpPurpose = "sign-in" | "phone-verification";

/** Stored phone OTP record. Only the peppered hash of the code (HMAC-SHA256 under the root secret) is persisted. */
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
 * pair; `upsert` replaces any existing record for the pair. Each pair also
 * has a failure budget (`getFailures`, `recordFailure`, `clearFailures`) that
 * outlives its OTP records, so a resend never resets the wrong codes counted
 * against the number.
 */
export class PhoneOtpStore extends Context.Service<
  PhoneOtpStore,
  {
    readonly upsert: (record: PhoneOtpRecord) => Effect.Effect<PhoneOtpRecord, Errors.AuthError>;
    readonly get: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<Option.Option<PhoneOtpRecord>, Errors.AuthError>;
    readonly delete: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<void, Errors.AuthError>;
    /**
     * Count one attempt against the pair's code, atomically, and return the
     * new count, or `None` when the pair has no code. The service
     * counts before it compares, so of concurrent guesses each gets its own
     * count and at most `maxAttempts` are ever compared: two calls must never
     * return the same number. On SQL this is one `UPDATE … RETURNING`.
     */
    readonly incrementAttempts: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<Option.Option<number>, Errors.AuthError>;
    /**
     * The pair's failure budget, or `None` when it has none. It is
     * kept apart from the OTP record: `upsert` and `delete` leave it as it
     * was.
     */
    readonly getFailures: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<Option.Option<Types.OtpFailures>, Errors.AuthError>;
    /**
     * Count one wrong code against the pair, at `at` (epoch ms), and return
     * the budget after it: `count` from 1, `lastFailureAt` set to `at`. One
     * atomic step where the backend allows, so concurrent wrong codes are all
     * counted.
     */
    readonly recordFailure: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
      at: number,
    ) => Effect.Effect<Types.OtpFailures, Errors.AuthError>;
    /** Forget the pair's failure budget (after a successful verification); a no-op when it has none. */
    readonly clearFailures: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
    ) => Effect.Effect<void, Errors.AuthError>;
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
  readonly identifier?: NewUserIdentifier;
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

/**
 * Configuration for {@link PhoneOtpService}.
 */
export interface PhoneOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  /**
   * Wrong codes one OTP accepts before it is deleted. Default 3. A resend
   * issues a new OTP with its own attempts; what bounds the guesses at a
   * number across resends is {@link PhoneOtpConfig.backoff}.
   */
  readonly maxAttempts?: number;
  /**
   * The failure backoff: every wrong code is also counted against the
   * phone number + purpose pair, and a resend never resets that count. Once
   * it reaches `freeFailures` (default 5), `send` fails with
   * {@link Errors.ResendTooSoonError} until `baseDelay` (default one minute),
   * doubled for each further wrong code and capped at `maxDelay` (default one
   * day), has passed since the latest one. A successful verification resets
   * the count. There is no lockout: once the delay has passed a send succeeds,
   * so an attacker can slow a number's owner down, not lock them out. It
   * applies alike to a number with and without an account.
   */
  readonly backoff?: Types.OtpBackoffConfig;
  /**
   * Refuse to create a user at `sign-in`. Off by default. When set, `sign-in`
   * hides whether a number has an account: see {@link PhoneOtpService} `send`
   * and `signIn`.
   */
  readonly disableSignUp?: boolean;
  /**
   * Minimum interval (ms) between successive send requests for the same phone
   * number + purpose pair. When an outstanding OTP created within this window
   * already exists, `send` fails with {@link Errors.ResendTooSoonError}.
   * Default 60 000 (60 s), which also limits carrier cost and DoS exposure;
   * `0` turns it off. Complements the global RateLimit and
   * {@link PhoneOtpConfig.backoff}. It applies to every
   * number alike, whether or not it has an account, so the error reveals
   * nothing about which numbers are registered. With sign-up disabled, a
   * `sign-in` request for a number with no account stores an undelivered
   * marker record, so if that number gains an account within the window,
   * its first `sign-in` send is delayed by up to the cooldown.
   */
  readonly resendCooldown?: number;
  /**
   * The per-recipient send cap: at most `max` sends to one number for
   * one purpose within `windowMs`, counted through the `RateLimitStore`,
   * which bounds SMS toll fraud against one number from many clients.
   * Default 5 an hour; `false` turns it off. A send past it fails with
   * {@link Errors.RateLimitError}. It counts every send the resend cooldown
   * and the backoff let through, for a number with and without an account
   * alike, so the refusal reveals nothing about which numbers are registered.
   * `phone-verification` sends count too, though a signed-in user asks for
   * them: `send` does not tell the two apart.
   */
  readonly recipientSendLimit?: Types.RecipientSendLimit | false;
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
  readonly sessionAttributes?: Types.Attributes;
}

/** The user and session issued by a phone OTP sign-in. */
export type PhoneOtpAuthResult = { readonly user: Types.User } & SessionOrChallenge;

/**
 * Sign-in and phone-number verification by SMS one-time code. Codes are stored hashed, with an attempt limit.
 *
 * Requires `PhoneOtpStore`, `PhoneOtpUserStore`, `UserStore`, `IdentifierStore`, `SessionService`, `Hooks` and `RateLimitStore` (the per-recipient send cap).
 */
export class PhoneOtpService extends Context.Service<
  PhoneOtpService,
  {
    /**
     * Generate an OTP for the given phone number + purpose (replacing any
     * outstanding one) and send it. Only a peppered hash of the code is stored.
     * Anti-enumeration: for `sign-in` with sign-up disabled and no user, this
     * succeeds without sending. It stores an undelivered marker record in
     * place of the code: the record holds the hash of a random 32-byte secret
     * that is never sent, so no code redeems it, and it expires and counts
     * attempts exactly as a code's record does. `signIn` then sees the same
     * record states for a number with and without an account.
     *
     * When an outstanding OTP for the phone + purpose was created within the
     * `resendCooldown` window, or the pair's wrong codes put it in the
     * `backoff` delay, fails with {@link Errors.ResendTooSoonError} containing
     * the remaining wait time.
     * The marker record makes the cooldown apply to a number with no account
     * as well, so a repeat within the window fails the same way for a known
     * and an unknown number.
     *
     * Past the `recipientSendLimit` cap (default 5 sends per number and
     * purpose an hour), fails with {@link Errors.RateLimitError}, for a
     * known and an unknown number alike.
     *
     * The `beforeSendCode` hook runs first, before the number is looked up,
     * with `options.captchaToken` (`CaptchaPlugin` guards it).
     */
    readonly send: (
      phoneNumber: string,
      purpose: PhoneOtpPurpose,
      options?: SendCodeOptions,
    ) => Effect.Effect<
      void,
      PhoneOtpError | Errors.AuthError | Errors.ResendTooSoonError | HookError
    >;

    /**
     * Verify a `sign-in` OTP (single use) and sign the user in, creating a new
     * user with a verified `phone` identifier when none exists (unless `disableSignUp`).
     *
     * A code that fails verification fails with {@link PhoneOtpError}. With
     * sign-up disabled, each such failure answers `"Invalid or expired OTP"`,
     * whether the code was wrong, had expired or reached `maxAttempts`, so the
     * answer is the same for a number with and without an outstanding code.
     * With sign-up enabled, an expired code answers `"OTP has expired"` and
     * the attempt limit answers `"Too many attempts"`. A wrong code counts
     * against the number's `backoff`; a correct one resets it.
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
    ) => Effect.Effect<
      Types.User,
      PhoneOtpError | Errors.AuthError | Errors.UserNotFoundError | HookError
    >;
  }
>()("@effect-auth/PhoneOtpService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PhoneOtpConfig) =>
    Layer.effect(PhoneOtpService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Resolve a user's phone number from their `phone` identifier, or `None`.
 * Prefers a verified phone identifier; falls back to the earliest unverified
 * one.
 */
export const getPhoneNumber = (
  identifierStore: typeof IdentifierStore.Service,
  userId: string,
): Effect.Effect<Option.Option<string>, Errors.AuthError> =>
  Effect.map(identifierStore.listByUser(userId), (all) => {
    const phones = Arr.sort(
      all.filter((id) => id.type === "phone"),
      Order.mapInput(Order.Number, (id: (typeof all)[number]) => id.createdAt.getTime()),
    );
    return Option.map(
      Option.orElse(
        Arr.findFirst(phones, (id) => id.verified),
        () => Arr.head(phones),
      ),
      (id) => id.value,
    );
  });

export const make = (
  config: PhoneOtpConfig,
): Effect.Effect<
  typeof PhoneOtpService.Service,
  never,
  | PhoneOtpStore
  | PhoneOtpUserStore
  | IdentifierStore
  | UserStore
  | Hooks
  | SessionService
  | RateLimitStore
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Mac.Mac
  | RootSecret.RootSecret
> =>
  Effect.gen(function* () {
    const codes = OtpCode.resolveCodeConfig(config);
    const { disableSignUp } = codes;

    const store = yield* PhoneOtpStore;
    const userStore = yield* PhoneOtpUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const hooks = yield* Hooks;
    const crypto = yield* SecureRandom.SecureRandom;
    const hashCode = yield* RootSecret.pepperHasher;
    const detached = yield* makeDetachedSend;
    const recipientSendGate = yield* makeRecipientSendGate(config.recipientSendLimit);

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

    const rejectOtp = OtpCode.makeReject(hidesAccount, (message) => new PhoneOtpError({ message }));

    const verifyOtp = (
      phoneNumber: string,
      otp: string,
      purpose: PhoneOtpPurpose,
    ): Effect.Effect<void, PhoneOtpError | Errors.AuthError> =>
      OtpCode.verifyCode(store, {
        address: phoneNumber,
        code: otp,
        purpose,
        maxAttempts: codes.maxAttempts,
        reject: rejectOtp,
        hash: hashCode,
      });

    return {
      send: Effect.fn("PhoneOtpService.send")(function* (
        rawPhoneNumber: string,
        purpose: PhoneOtpPurpose,
        options?: SendCodeOptions,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);
        if (!phoneNumber) {
          return yield* Effect.void;
        }

        // The send gate (captcha) runs before the number is looked
        // up, so it answers alike for every number.
        yield* hooks.beforeSendCode(
          definedKeys({
            method: "phone-otp",
            purpose,
            address: phoneNumber,
            captchaToken: options?.captchaToken,
          }),
        );

        // Anti-enumeration: sign-in with sign-up disabled and no user
        // succeeds without sending.
        const deliver = hidesAccount(purpose)
          ? Option.isSome(yield* lookupIdentifier(identifiers, "phone", phoneNumber))
          : true;

        // Resend cooldown and failure backoff. Both run for a number
        // with no account too, whose earlier request stored an undelivered
        // marker record below and whose wrong codes are counted alike, so a
        // known and an unknown number get the same answer.
        yield* OtpCode.gateSend(store, phoneNumber, purpose, codes);

        // The per-recipient cap, counted whatever the lookup found.
        yield* recipientSendGate(`phone-otp:${purpose}`, phoneNumber);

        // A number with no account gets a marker record that no code
        // redeems (see `issueCode`).
        const { code: otp, record: fields } = yield* OtpCode.issueCode(
          crypto,
          hashCode,
          codes,
          deliver,
        );
        const record: PhoneOtpRecord = { phoneNumber, purpose, ...fields };

        yield* store.upsert(record);

        // With sign-up disabled, only a known number gets a code, so its send
        // goes off the response path.
        return yield* deliverCode(detached, {
          purpose: `phone-otp:${purpose}`,
          code: otp,
          send: (code) => config.sendOtp(phoneNumber, code, purpose),
          onFailure: (error) =>
            new PhoneOtpError({ message: `Failed to send OTP to ${phoneNumber}`, cause: error }),
          deliver,
          hidesAccount: hidesAccount(purpose),
        });
      }),

      signIn: Effect.fn("PhoneOtpService.signIn")(function* (
        rawPhoneNumber: string,
        otp: string,
        options?: PhoneOtpSignInOptions,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);

        const owned = yield* findIdentifierOwner(
          identifiers,
          users.get,
          "phone",
          phoneNumber,
          () => new PhoneOtpError({ message: "Account is unavailable" }),
        );
        yield* hooks.beforeAuthenticate(
          definedKeys({
            method: "phone-otp",
            identifier: { type: "phone", value: phoneNumber },
            userId: Option.getOrUndefined(Option.map(owned, (o) => o.user.id)),
          }),
        );

        yield* verifyOtp(phoneNumber, otp, "sign-in");

        let user: Types.User;
        if (Option.isNone(owned)) {
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
        } else {
          user = owned.value.user;
          if (!owned.value.identifier.verified) {
            // The OTP proves ownership — promote the identifier to verified.
            yield* identifiers.setVerified(owned.value.identifier.id, yield* DateTime.nowAsDate);
          }
        }

        const issued = yield* sessionOrChallenge(
          sessionManager,
          user,
          "phone-otp",
          options?.sessionAttributes,
        );
        return { user, ...issued } satisfies PhoneOtpAuthResult;
      }),

      verifyPhoneNumber: Effect.fn("PhoneOtpService.verifyPhoneNumber")(function* (
        userId: string,
        rawPhoneNumber: string,
        otp: string,
      ) {
        const phoneNumber = yield* normalize(rawPhoneNumber);
        // The signed-in user proves a number: the gate keys on them.
        yield* hooks.beforeAuthenticate({
          method: "phone-otp",
          identifier: { type: "phone", value: phoneNumber },
          userId,
        });

        yield* verifyOtp(phoneNumber, otp, "phone-verification");

        // Attach (or verify) the phone identifier for this user.
        const existing = yield* lookupIdentifier(identifiers, "phone", phoneNumber);
        if (Option.exists(existing, (found) => found.userId !== userId)) {
          return yield* new PhoneOtpError({ message: "This phone number is already in use" });
        }
        if (Option.isNone(existing)) {
          const verifiedAt = yield* DateTime.nowAsDate;
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId,
              type: "phone",
              value: phoneNumber,
              verified: true,
              verifiedAt,
              now: verifiedAt,
            }),
          ).pipe(
            Effect.catchTags({
              IdentifierTakenError: () =>
                Effect.fail(new PhoneOtpError({ message: "This phone number is already in use" })),
              IdentifierRefusedError: (error) => Effect.fail(refusalAuthError(error)),
            }),
          );
        } else if (!existing.value.verified) {
          yield* identifiers.setVerified(existing.value.id, yield* DateTime.nowAsDate);
        }

        const foundUser = yield* users.get(userId);
        if (Option.isNone(foundUser)) {
          return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
        }
        const user = foundUser.value;
        return user;
      }),
    };
  });
