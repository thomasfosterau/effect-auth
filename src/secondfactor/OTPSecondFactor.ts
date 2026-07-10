/**
 * OTP-based second-factor gate for effect-auth.
 *
 * After first-factor success, `begin` sends a numeric OTP to the user (via
 * email, SMS, or any other channel supplied through `sendOTP`) and returns a
 * pending challenge token. `verify` redeems the token + OTP to create a
 * session.
 *
 * Reuses the generation, hashing, and attempt-limiting logic from the
 * EmailOTP / PhoneOTP engines (`generateOTP`, `hashToken`,
 * `constantTimeHashEqual`) without duplicating delivery or store concerns.
 *
 * Can serve as an **alternative** to TOTP (use `OTPSecondFactorGateLayer`
 * instead of `TwoFactorGateLayer`) or in **addition** to it by pairing with
 * `TrustedDevice.gate` from the TrustedDevice module.
 *
 * @module otp-second-factor
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { generateOTP } from "../email/EmailOTP.ts";
import { SecondFactorGate, type SecondFactorChallenge } from "../email/EmailPassword.ts";
import { type HookError } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../session/SessionService.ts";
import { constantTimeHashEqual, hashToken } from "../TokenHash.ts";
import { TrustedDeviceService } from "../session/TrustedDevice.ts";
import * as TrustedDevice from "../session/TrustedDevice.ts";
import type * as Types from "../Types.ts";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class OTPSecondFactorError extends Data.TaggedError("OTPSecondFactorError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

// ---------------------------------------------------------------------------
// Record + Store
// ---------------------------------------------------------------------------

/**
 * Pending OTP second-factor challenge. A new record is created by `begin` and
 * consumed (deleted) by a successful `verify`. Only the hash of the OTP is
 * stored; the plaintext is delivered out-of-band to the user.
 */
export interface OTPSecondFactorRecord {
  /** Raw challenge token returned to the client; used as the store key. */
  readonly pendingToken: string;
  readonly userId: string;
  /** SHA-256 hash of the plaintext OTP (`hashToken(otp)`). */
  readonly otpHash: string;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export class OTPSecondFactorStore extends Context.Service<
  OTPSecondFactorStore,
  {
    readonly create: (
      record: OTPSecondFactorRecord,
    ) => Effect.Effect<OTPSecondFactorRecord, Errors.AuthError>;
    readonly get: (
      pendingToken: string,
    ) => Effect.Effect<OTPSecondFactorRecord | null, Errors.AuthError>;
    readonly update: (
      record: OTPSecondFactorRecord,
    ) => Effect.Effect<OTPSecondFactorRecord, Errors.AuthError>;
    readonly delete: (pendingToken: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/OTPSecondFactorStore") {}

// ---------------------------------------------------------------------------
// Config + Service
// ---------------------------------------------------------------------------

export interface OTPSecondFactorConfig {
  /** OTP digit length. Default: 6. */
  readonly otpLength?: number;
  /** Challenge lifetime in milliseconds. Default: 5 minutes. */
  readonly expiresIn?: number;
  /** Max verification attempts before the challenge is invalidated. Default: 3. */
  readonly maxAttempts?: number;
  /**
   * Send the OTP to the user. Receives the full `User` record so the
   * implementation can route by email (`user.email`), phone number
   * (`user.attributes.phoneNumber`), etc. Plug your `EmailOTPService.send` or
   * `PhoneOTPService.send` call here.
   */
  readonly sendOTP: (user: Types.User, otp: string) => Effect.Effect<void, Errors.AuthError>;
}

export interface OTPSecondFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface OTPSecondFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}

export class OTPSecondFactorService extends Context.Service<
  OTPSecondFactorService,
  {
    /**
     * Begin a second-factor OTP challenge. Generates an OTP, stores it
     * (hashed), sends it via `sendOTP`, and returns a `SecondFactorChallenge`
     * with the pending token for the client to submit alongside the OTP.
     */
    readonly begin: (
      user: Types.User,
    ) => Effect.Effect<SecondFactorChallenge, OTPSecondFactorError | Errors.AuthError>;

    /**
     * Verify the OTP for a pending challenge. On success: consumes the
     * challenge (one-time use) and creates a session.
     */
    readonly verify: (
      pendingToken: string,
      otp: string,
      options?: OTPSecondFactorVerifyOptions,
    ) => Effect.Effect<
      OTPSecondFactorVerifyResult,
      OTPSecondFactorError | Errors.AuthError | HookError
    >;
  }
>()("@effect-auth/OTPSecondFactorService") {
  static readonly layer = (config: OTPSecondFactorConfig) =>
    Layer.effect(OTPSecondFactorService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const make = (
  config: OTPSecondFactorConfig,
): Effect.Effect<
  typeof OTPSecondFactorService.Service,
  never,
  OTPSecondFactorStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const otpLength = config.otpLength ?? 6;
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
    const maxAttempts = config.maxAttempts ?? 3;

    const store = yield* OTPSecondFactorStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    const invalidOTP = () =>
      Effect.fail(new OTPSecondFactorError({ message: "Invalid or expired OTP" }));

    const generatePendingToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate pending token", cause }),
        ),
      );

    return {
      begin: Effect.fn("OTPSecondFactorService.begin")(function* (user: Types.User) {
        const otp = yield* generateOTP(crypto, otpLength);
        const pendingToken = yield* generatePendingToken();
        const now = Date.now();

        const record: OTPSecondFactorRecord = {
          pendingToken,
          userId: user.id,
          otpHash: hashToken(otp),
          attempts: 0,
          createdAt: now,
          expiresAt: now + expiresIn,
        };

        yield* store.create(record);

        yield* Effect.catch(config.sendOTP(user, otp), (err) =>
          Effect.fail(
            new OTPSecondFactorError({
              message: "Failed to send second-factor OTP",
              cause: err,
            }),
          ),
        );

        return {
          token: pendingToken,
          expiresAt: record.expiresAt,
        } satisfies SecondFactorChallenge;
      }),

      verify: Effect.fn("OTPSecondFactorService.verify")(function* (
        pendingToken: string,
        otp: string,
        options?: OTPSecondFactorVerifyOptions,
      ) {
        if (!pendingToken || !otp) {
          return yield* invalidOTP();
        }

        const record = yield* store.get(pendingToken);
        if (!record) {
          return yield* invalidOTP();
        }

        if (Date.now() > record.expiresAt) {
          yield* store.delete(pendingToken);
          return yield* Effect.fail(new OTPSecondFactorError({ message: "OTP has expired" }));
        }

        if (record.attempts >= maxAttempts) {
          yield* store.delete(pendingToken);
          return yield* Effect.fail(new OTPSecondFactorError({ message: "Too many attempts" }));
        }

        if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
          const updated = { ...record, attempts: record.attempts + 1 };
          yield* store.update(updated);
          if (updated.attempts >= maxAttempts) {
            yield* store.delete(pendingToken);
            return yield* Effect.fail(new OTPSecondFactorError({ message: "Too many attempts" }));
          }
          return yield* invalidOTP();
        }

        // Consume the pending challenge (one-time use)
        yield* store.delete(pendingToken);

        const session = yield* sessionManager.createSession(
          record.userId,
          options?.sessionAttributes,
        );

        return {
          userId: record.userId,
          session,
        } satisfies OTPSecondFactorVerifyResult;
      }),
    };
  });

// ---------------------------------------------------------------------------
// Gate layer: OTP-only second factor
// ---------------------------------------------------------------------------

/**
 * Gate layer that requires an OTP second factor for every sign-in.
 *
 * `required(user)` always returns `true`. `begin(user)` generates and sends
 * an OTP via the configured `sendOTP`. The client then calls
 * `OTPSecondFactorService.verify(pendingToken, otp)` to redeem it.
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   OTPSecondFactorGateLayer.pipe(
 *     Layer.provide(OTPSecondFactorService.layer({
 *       sendOTP: (user, otp) => mailer.send(user.email, `Your code: ${otp}`),
 *     }).pipe(Layer.provide(otpSecondFactorStore))),
 *   ),
 * )
 * ```
 */
export const OTPSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  OTPSecondFactorService
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const service = yield* OTPSecondFactorService;

    const gate: typeof SecondFactorGate.Service = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        service
          .begin(user)
          .pipe(
            Effect.catchTag("OTPSecondFactorError", (err) =>
              Effect.fail(new Errors.AuthError({ message: err.message })),
            ),
          ),
    };
    return gate;
  }),
);

// ---------------------------------------------------------------------------
// Convenience gate: trusted device + OTP second factor
// ---------------------------------------------------------------------------

/**
 * Gate layer combining trusted-device short-circuit with OTP second factor.
 *
 * When a valid device token is present in `TrustedDeviceCookieRef`, sign-in
 * skips the second factor entirely. Otherwise an OTP is sent via `sendOTP`
 * and the user must verify it with `OTPSecondFactorService.verify`.
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   TrustedDeviceWithOTPSecondFactorGateLayer.pipe(
 *     Layer.provide(TrustedDeviceService.layer({ secret: "..." }).pipe(Layer.provide(trustedDeviceStore))),
 *     Layer.provide(OTPSecondFactorService.layer({ sendOTP: ... }).pipe(Layer.provide(otpSecondFactorStore))),
 *   ),
 * )
 * ```
 */
export const TrustedDeviceWithOTPSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TrustedDeviceService | OTPSecondFactorService
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const tdService = yield* TrustedDeviceService;
    const otpService = yield* OTPSecondFactorService;

    const otpGate: typeof SecondFactorGate.Service = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        otpService
          .begin(user)
          .pipe(
            Effect.catchTag("OTPSecondFactorError", (err) =>
              Effect.fail(new Errors.AuthError({ message: err.message })),
            ),
          ),
    };

    return TrustedDevice.gate(tdService, otpGate);
  }),
);
