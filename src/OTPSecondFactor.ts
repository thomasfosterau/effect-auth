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
 * `makeTrustedDeviceGateShape` from the TrustedDevice module.
 *
 * @module otp-second-factor
 */
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import { generateOTP } from "./email/EmailOTP.ts";
import {
  SecondFactorGate,
  type SecondFactorChallenge,
  type SecondFactorGateShape,
} from "./email/EmailPassword.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { SessionService } from "./session/SessionService.ts";
import { constantTimeHashEqual, hashToken } from "./TokenHash.ts";
import {
  TrustedDeviceService,
  TrustedDeviceStore,
  makeTrustedDeviceGateShape,
} from "./session/TrustedDevice.ts";
import type * as Types from "./Types.ts";

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

export interface OTPSecondFactorStoreShape {
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

export class OTPSecondFactorStore extends Context.Service<
  OTPSecondFactorStore,
  OTPSecondFactorStoreShape
>()("@effect-auth/OtpSecondFactorStore") {}

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

export interface OTPSecondFactorServiceShape {
  /**
   * Begin a second-factor OTP challenge. Generates an OTP, stores it
   * (hashed), sends it via `sendOTP`, and returns a `SecondFactorChallenge`
   * with the pending token for the client to submit alongside the OTP.
   */
  readonly begin: (
    user: Types.User,
  ) => Effect.Effect<
    SecondFactorChallenge,
    OTPSecondFactorError | Errors.AuthError,
    OTPSecondFactorStore
  >;

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
    OTPSecondFactorError | Errors.AuthError | HookError,
    OTPSecondFactorStore | SessionService | Hooks
  >;
}

export class OTPSecondFactorService extends Context.Service<
  OTPSecondFactorService,
  OTPSecondFactorServiceShape
>()("@effect-auth/OtpSecondFactorService") {
  static readonly layer = (config: OTPSecondFactorConfig) =>
    Layer.effect(OTPSecondFactorService, makeOTPSecondFactorService(config));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const makeOTPSecondFactorService = (
  config: OTPSecondFactorConfig,
): Effect.Effect<OTPSecondFactorServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
  const maxAttempts = config.maxAttempts ?? 3;

  const invalidOTP = () =>
    Effect.fail(new OTPSecondFactorError({ message: "Invalid or expired OTP" }));

  return Effect.sync(
    (): OTPSecondFactorServiceShape => ({
      begin: (user: Types.User) =>
        Effect.gen(function* () {
          const store = yield* OTPSecondFactorStore;
          const otp = yield* generateOTP(otpLength);
          const pendingToken = crypto.randomBytes(32).toString("base64url");
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

      verify: (pendingToken: string, otp: string, options?: OTPSecondFactorVerifyOptions) =>
        Effect.gen(function* () {
          const store = yield* OTPSecondFactorStore;

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

          const sessionManager = yield* SessionService;
          const session = yield* sessionManager.createSession(
            record.userId,
            options?.sessionAttributes,
          );

          return {
            userId: record.userId,
            session,
          } satisfies OTPSecondFactorVerifyResult;
        }),
    }),
  );
};

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
 *     })),
 *     Layer.provide(otpSecondFactorStore),
 *   ),
 * )
 * ```
 */
export const OTPSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  OTPSecondFactorService | OTPSecondFactorStore
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const service = yield* OTPSecondFactorService;
    const stores = yield* Effect.context<OTPSecondFactorStore>();

    const gate: SecondFactorGateShape = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        service.begin(user).pipe(
          Effect.provide(stores),
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
 *     Layer.provide(TrustedDeviceService.layer({ secret: "..." })),
 *     Layer.provide(trustedDeviceStore),
 *     Layer.provide(OTPSecondFactorService.layer({ sendOTP: ... })),
 *     Layer.provide(otpSecondFactorStore),
 *   ),
 * )
 * ```
 */
export const TrustedDeviceWithOTPSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TrustedDeviceService | TrustedDeviceStore | OTPSecondFactorService | OTPSecondFactorStore
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const tdService = yield* TrustedDeviceService;
    const otpService = yield* OTPSecondFactorService;
    const tdStores = yield* Effect.context<TrustedDeviceStore>();
    const otpStores = yield* Effect.context<OTPSecondFactorStore>();

    const otpGate: SecondFactorGateShape = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        otpService.begin(user).pipe(
          Effect.provide(otpStores),
          Effect.catchTag("OTPSecondFactorError", (err) =>
            Effect.fail(new Errors.AuthError({ message: err.message })),
          ),
        ),
    };

    return makeTrustedDeviceGateShape(tdService, tdStores, otpGate);
  }),
);
