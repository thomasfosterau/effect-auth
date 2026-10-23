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
import { IdentifierStore } from "../Identifier.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "../UserStore.ts";
import { makeDetachedSend } from "../DeliveryScheduler.ts";
import type { HookError } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { randomBase64UrlToken } from "../RandomToken.ts";
import { SessionService } from "../SessionService.ts";
import { EmailPasswordStore } from "./EmailPassword.ts";
import { proveAddress } from "../FirstProof.ts";
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
 * Fields for a user created during OTP sign-in. The email itself is recorded as
 * a verified `Identifier` by the service, and `identifier` carries it to the
 * store as well.
 */
export interface EmailOtpCreateUserInput {
  readonly name?: string;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier | undefined;
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
    /**
     * Create a user. `created` in the result is `true` only when this call
     * inserted the user; a user that already existed (as a find-or-create on
     * the address returns) reports `false`, and sign-up then fails without
     * writing to it. The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly createUser: (
      input: EmailOtpCreateUserInput,
    ) => Effect.Effect<CreateUserResult, Errors.AuthError>;
  }
>()("@effect-auth/EmailOtpUserStore") {}

/**
 * Email OTP service configuration
 */
export interface EmailOtpConfig {
  readonly otpLength?: number; // Default: 6 digits
  readonly expiresIn?: number; // Default: 5 minutes
  readonly maxAttempts?: number; // Default: 3
  /**
   * Refuse to create a user at `"sign-in"`. Off by default. When set,
   * `"sign-in"` hides whether an email has an account, as `"forget-password"`
   * always does: see {@link EmailOtpService} `send` and `signIn`.
   */
  readonly disableSignUp?: boolean;
  /**
   * Minimum interval (ms) between successive send requests for the same email
   * + purpose pair. When an outstanding OTP created within this window already
   * exists, `send` fails with {@link Errors.ResendTooSoonError}. Off by
   * default. Complements the global RateLimit. It applies to every email
   * alike, whether or not it has an account, so the error reveals nothing
   * about which emails are registered. Where `send` hides whether an account
   * exists (`"sign-in"` with sign-up disabled, and `"forget-password"`), a
   * request for an email with no account stores an undelivered marker
   * record, so if that email gains an account within the window, its first
   * send for that purpose is delayed by up to the cooldown.
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
 * Email OTP service.
 *
 * Requires `EmailOtpStore`, `EmailOtpUserStore`, `IdentifierStore`, `UserStore`, `SessionService`, `EmailPasswordStore` and `Crypto`.
 *
 * Promoting an address held unverified to verified first clears the
 * account's password and revokes its sessions, through `EmailPasswordStore`
 * (#440): the account was created by a sign-up that proved nothing about the
 * address, so its password may be someone else's.
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
     * without sending anything. It stores an undelivered marker record in
     * place of the code: the record holds the hash of a random 32-byte secret
     * that is never sent, so no code redeems it, and it expires and counts
     * attempts exactly as a code's record does. `signIn` and `check` then
     * see the same record states for an email with and without an account.
     *
     * When `resendCooldown` is configured and an outstanding OTP for the email +
     * purpose was created within the cooldown window, fails with
     * {@link Errors.ResendTooSoonError} containing the remaining wait time.
     * The marker record makes the cooldown apply to an email with no account
     * as well, so a repeat within the window fails the same way for a known
     * and an unknown email.
     */
    readonly send: (
      email: string,
      purpose: EmailOtpPurpose,
    ) => Effect.Effect<void, Errors.AuthError | EmailOtpError | Errors.ResendTooSoonError>;

    /**
     * Verify a `"sign-in"` OTP and create a session. Users created here are
     * marked `emailVerified: true` (the OTP proves ownership of the email).
     *
     * A code that fails verification fails with {@link EmailOtpError}. With
     * sign-up disabled, each such failure answers `"Invalid or expired OTP"`,
     * whether the code was wrong, had expired or reached `maxAttempts`, so the
     * answer is the same for an email with and without an outstanding code.
     * With sign-up enabled, an expired code answers `"OTP has expired"` and
     * the attempt limit answers `"Too many attempts"`.
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
     *
     * A code that fails verification fails with {@link EmailOtpError}. Where
     * `send` hides whether the email has an account (`"forget-password"`, and
     * `"sign-in"` with sign-up disabled), each such failure answers
     * `"Invalid or expired OTP"`, as `signIn` does. Otherwise an expired code
     * answers `"OTP has expired"` and the attempt limit answers
     * `"Too many attempts"`.
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
 * SHA-256 hex digest of an OTP; an alias of {@link hashToken}.
 *
 * @deprecated Use {@link hashToken} from `@thomasfosterau/effect-auth` instead.
 */
export const hashOtp = hashToken;

/**
 * Generate a numeric OTP with crypto-secure randomness (one unbiased
 * `randomIntBetween` draw per digit — no modulo bias).
 */
export const generateOtp = (crypto: Crypto.Crypto, length: number): Effect.Effect<string> =>
  Effect.replicateEffect(crypto.randomIntBetween(0, 10, { halfOpen: true }), length, {
    concurrency: 1,
  }).pipe(Effect.map((digits) => digits.join("")));

/**
 * The secret behind an unknown address's marker record: 32 random bytes,
 * base64url-encoded. It is hashed into the marker record and then discarded.
 */
const generateMarkerSecret = (crypto: Crypto.Crypto): Effect.Effect<string, Errors.AuthError> =>
  randomBase64UrlToken(crypto, "Failed to generate OTP marker");

/**
 * Create an email OTP service
 */
export const make = (
  config: EmailOtpConfig,
): Effect.Effect<
  typeof EmailOtpService.Service,
  never,
  | EmailOtpStore
  | EmailOtpUserStore
  | IdentifierStore
  | UserStore
  | SessionService
  | EmailPasswordStore
  | Crypto.Crypto
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
    const passwords = yield* EmailPasswordStore;
    const crypto = yield* Crypto.Crypto;
    const detached = yield* makeDetachedSend;

    /**
     * Whether `send` hides, for this purpose, whether the email has an
     * account. It then answers alike for both, and verification must too.
     */
    const hidesAccount = (purpose: EmailOtpPurpose): boolean =>
      (purpose === "sign-in" && disableSignUp) || purpose === "forget-password";

    /**
     * Fail a verification. Where `send` hides whether the email has an
     * account, every reason answers the generic message. The marker record
     * already gives a known and an unknown email the same record states; the
     * generic message also makes one that holds a record answer as one that
     * holds none, so expiry and the attempt limit can't show whether a code
     * was requested for it. The reason stays on the span for operators.
     */
    const rejectOtp = (purpose: EmailOtpPurpose, reason: VerifyFailure) =>
      Effect.annotateCurrentSpan("auth.otp.failure", reason).pipe(
        Effect.andThen(
          Effect.fail(
            new EmailOtpError({
              message: hidesAccount(purpose) ? invalidOtpMessage : failureMessages[reason],
            }),
          ),
        ),
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
          return yield* rejectOtp(purpose, "missing");
        }

        const record = yield* store.get(email, purpose);
        if (!record) {
          return yield* rejectOtp(purpose, "missing");
        }

        // Check expiration
        if (Date.now() > record.expiresAt) {
          yield* store.delete(email, purpose);
          return yield* rejectOtp(purpose, "expired");
        }

        // Defensive: a record that already exhausted its attempts is unusable.
        if (record.attempts >= maxAttempts) {
          yield* store.delete(email, purpose);
          return yield* rejectOtp(purpose, "attempts");
        }

        if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
          const attempts = yield* store.incrementAttempts(email, purpose);
          if (attempts >= maxAttempts) {
            yield* store.delete(email, purpose);
            return yield* rejectOtp(purpose, "attempts");
          }
          return yield* rejectOtp(purpose, "mismatch");
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
        // risk: succeed without sending for sign-in when sign-up is disabled
        // and no user exists, and for forget-password when no user exists.
        // Sign-in with sign-up enabled always sends (the user is created at
        // verification time).
        const deliver = hidesAccount(purpose)
          ? (yield* identifiers.getByValue("email", email)) !== null
          : true;

        // Resend cooldown: reject if an outstanding OTP was created within
        // the configured window. It runs for an address with no account too,
        // whose earlier request stored an undelivered record below, so a known
        // and an unknown address get the same answer inside the window.
        if (config.resendCooldown !== undefined) {
          const existing = yield* store.get(email, purpose);
          if (existing !== null) {
            const elapsed = Date.now() - existing.createdAt;
            if (elapsed < config.resendCooldown) {
              return yield* new Errors.ResendTooSoonError({
                message: "Please wait before requesting another OTP",
                retryAfter: config.resendCooldown - elapsed,
              });
            }
          }
        }

        // An address with no account gets a marker record, whose hash is of a
        // random 32-byte secret rather than of a code: no `otpLength`-digit
        // guess can match it, and the secret is never sent. It is written
        // whether or not a cooldown is set, with the same attempts and expiry
        // as a code's record, so both branches do the same store work here
        // and verification later sees the same record states. Both values are
        // drawn on every send, so the random work is the same too.
        const otp = yield* generateOtp(crypto, otpLength);
        const markerSecret = yield* generateMarkerSecret(crypto);
        const record: EmailOtpRecord = {
          email,
          otpHash: hashToken(deliver ? otp : markerSecret),
          purpose,
          attempts: 0,
          createdAt: Date.now(),
          expiresAt: Date.now() + expiresIn,
        };

        // One active OTP per email + purpose: replaces any outstanding one.
        yield* store.upsert(record);

        if (!deliver) {
          return;
        }

        // Where only a known address gets a code (sign-in with sign-up
        // disabled, forget-password), an inline send would answer it later,
        // and fail it when the vendor does: the send goes off the response
        // path. Elsewhere a failed send is the caller's to see (#196).
        if (hidesAccount(purpose)) {
          return yield* detached(
            `email-otp:${purpose}`,
            config.sendVerificationOtp(email, otp, purpose),
          );
        }
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
          return yield* new EmailOtpError({ message: "Account is unavailable" });
        }
        if (!user) {
          if (disableSignUp) {
            return yield* new EmailOtpError({
              message: "Sign-up is disabled",
            });
          }

          // A verified OTP proves ownership of the email.
          const created = yield* createUserWithIdentifier(
            identifiers,
            { type: "email", value: email, verified: true, verifiedAt: new Date() },
            (identifier) => userStore.createUser({ identifier }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new EmailOtpError({ message: "This email is already in use" })),
            ),
          );
          user = created.user;
        } else if (identifier !== null && !identifier.verified) {
          // The OTP proves ownership — promote the identifier to verified,
          // first clearing the password and sessions an earlier, unproven
          // sign-up left on the account (#440).
          yield* proveAddress({ identifiers, passwords, sessions: sessionManager }, identifier);
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
