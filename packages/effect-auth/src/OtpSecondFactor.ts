/**
 * OTP-based second-factor gate for effect-auth.
 *
 * After first-factor success, `begin` sends a numeric OTP to the user (via
 * email, SMS, or any other channel supplied through `sendOtp`) and returns a
 * pending challenge token. `verify` redeems the token + OTP to create a
 * session.
 *
 * Reuses the generation, hashing, and attempt-limiting logic from the
 * EmailOtp / PhoneOtp engines (`generateOtp`, `hashToken`,
 * `constantTimeHashEqual`) without duplicating delivery or store concerns.
 *
 * Can serve as an **alternative** to TOTP (use `OtpSecondFactorGateLayer`
 * instead of `TwoFactorGateLayer`) or in **addition** to it by pairing with
 * `makeTrustedDeviceGateShape` from the TrustedDevice module.
 *
 * @module otp-second-factor
 */
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.js";
import { generateOtp } from "./EmailOtp.js";
import {
  SecondFactorGate,
  type SecondFactorChallenge,
  type SecondFactorGateShape,
} from "./EmailPassword.js";
import { Hooks, type HookError } from "./Hooks.js";
import { SessionManager } from "./Session.js";
import { constantTimeHashEqual, hashToken } from "./TokenHash.js";
import {
  TrustedDeviceService,
  TrustedDeviceStore,
  makeTrustedDeviceGateShape,
} from "./TrustedDevice.js";
import type * as Types from "./Types.js";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class OtpSecondFactorError extends Data.TaggedError("OtpSecondFactorError")<{
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
export interface OtpSecondFactorRecord {
  /** Raw challenge token returned to the client; used as the store key. */
  readonly pendingToken: string;
  readonly userId: string;
  /** SHA-256 hash of the plaintext OTP (`hashToken(otp)`). */
  readonly otpHash: string;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface OtpSecondFactorStoreShape {
  readonly create: (
    record: OtpSecondFactorRecord,
  ) => Effect.Effect<OtpSecondFactorRecord, Errors.AuthError>;
  readonly get: (
    pendingToken: string,
  ) => Effect.Effect<OtpSecondFactorRecord | null, Errors.AuthError>;
  readonly update: (
    record: OtpSecondFactorRecord,
  ) => Effect.Effect<OtpSecondFactorRecord, Errors.AuthError>;
  readonly delete: (pendingToken: string) => Effect.Effect<void, Errors.AuthError>;
}

export class OtpSecondFactorStore extends Context.Service<
  OtpSecondFactorStore,
  OtpSecondFactorStoreShape
>()("@effect-auth/OtpSecondFactorStore") {}

// ---------------------------------------------------------------------------
// Config + Service
// ---------------------------------------------------------------------------

export interface OtpSecondFactorConfig {
  /** OTP digit length. Default: 6. */
  readonly otpLength?: number;
  /** Challenge lifetime in milliseconds. Default: 5 minutes. */
  readonly expiresIn?: number;
  /** Max verification attempts before the challenge is invalidated. Default: 3. */
  readonly maxAttempts?: number;
  /**
   * Send the OTP to the user. Receives the full `User` record so the
   * implementation can route by email (`user.email`), phone number
   * (`user.attributes.phoneNumber`), etc. Plug your `EmailOtpService.send` or
   * `PhoneOtpService.send` call here.
   */
  readonly sendOtp: (user: Types.User, otp: string) => Effect.Effect<void, Errors.AuthError>;
}

export interface OtpSecondFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface OtpSecondFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}

export interface OtpSecondFactorServiceShape {
  /**
   * Begin a second-factor OTP challenge. Generates an OTP, stores it
   * (hashed), sends it via `sendOtp`, and returns a `SecondFactorChallenge`
   * with the pending token for the client to submit alongside the OTP.
   */
  readonly begin: (
    user: Types.User,
  ) => Effect.Effect<
    SecondFactorChallenge,
    OtpSecondFactorError | Errors.AuthError,
    OtpSecondFactorStore
  >;

  /**
   * Verify the OTP for a pending challenge. On success: consumes the
   * challenge (one-time use) and creates a session.
   */
  readonly verify: (
    pendingToken: string,
    otp: string,
    options?: OtpSecondFactorVerifyOptions,
  ) => Effect.Effect<
    OtpSecondFactorVerifyResult,
    OtpSecondFactorError | Errors.AuthError | HookError,
    OtpSecondFactorStore | SessionManager | Hooks
  >;
}

export class OtpSecondFactorService extends Context.Service<
  OtpSecondFactorService,
  OtpSecondFactorServiceShape
>()("@effect-auth/OtpSecondFactorService") {
  static readonly layer = (config: OtpSecondFactorConfig) =>
    Layer.effect(OtpSecondFactorService, makeOtpSecondFactorService(config));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const makeOtpSecondFactorService = (
  config: OtpSecondFactorConfig,
): Effect.Effect<OtpSecondFactorServiceShape, never> => {
  const otpLength = config.otpLength ?? 6;
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
  const maxAttempts = config.maxAttempts ?? 3;

  const invalidOtp = () =>
    Effect.fail(new OtpSecondFactorError({ message: "Invalid or expired OTP" }));

  return Effect.sync(
    (): OtpSecondFactorServiceShape => ({
      begin: (user: Types.User) =>
        Effect.gen(function* () {
          const store = yield* OtpSecondFactorStore;
          const otp = yield* generateOtp(otpLength);
          const pendingToken = crypto.randomBytes(32).toString("base64url");
          const now = Date.now();

          const record: OtpSecondFactorRecord = {
            pendingToken,
            userId: user.id,
            otpHash: hashToken(otp),
            attempts: 0,
            createdAt: now,
            expiresAt: now + expiresIn,
          };

          yield* store.create(record);

          yield* Effect.catch(config.sendOtp(user, otp), (err) =>
            Effect.fail(
              new OtpSecondFactorError({
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

      verify: (pendingToken: string, otp: string, options?: OtpSecondFactorVerifyOptions) =>
        Effect.gen(function* () {
          const store = yield* OtpSecondFactorStore;

          if (!pendingToken || !otp) {
            return yield* invalidOtp();
          }

          const record = yield* store.get(pendingToken);
          if (!record) {
            return yield* invalidOtp();
          }

          if (Date.now() > record.expiresAt) {
            yield* store.delete(pendingToken);
            return yield* Effect.fail(new OtpSecondFactorError({ message: "OTP has expired" }));
          }

          if (record.attempts >= maxAttempts) {
            yield* store.delete(pendingToken);
            return yield* Effect.fail(new OtpSecondFactorError({ message: "Too many attempts" }));
          }

          if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
            const updated = { ...record, attempts: record.attempts + 1 };
            yield* store.update(updated);
            if (updated.attempts >= maxAttempts) {
              yield* store.delete(pendingToken);
              return yield* Effect.fail(new OtpSecondFactorError({ message: "Too many attempts" }));
            }
            return yield* invalidOtp();
          }

          // Consume the pending challenge (one-time use)
          yield* store.delete(pendingToken);

          const sessionManager = yield* SessionManager;
          const session = yield* sessionManager.createSession(
            record.userId,
            options?.sessionAttributes,
          );

          return {
            userId: record.userId,
            session,
          } satisfies OtpSecondFactorVerifyResult;
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
 * an OTP via the configured `sendOtp`. The client then calls
 * `OtpSecondFactorService.verify(pendingToken, otp)` to redeem it.
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   OtpSecondFactorGateLayer.pipe(
 *     Layer.provide(OtpSecondFactorService.layer({
 *       sendOtp: (user, otp) => mailer.send(user.email, `Your code: ${otp}`),
 *     })),
 *     Layer.provide(otpSecondFactorStore),
 *   ),
 * )
 * ```
 */
export const OtpSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  OtpSecondFactorService | OtpSecondFactorStore
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const service = yield* OtpSecondFactorService;
    const stores = yield* Effect.context<OtpSecondFactorStore>();

    const gate: SecondFactorGateShape = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        service.begin(user).pipe(
          Effect.provide(stores),
          Effect.catchTag("OtpSecondFactorError", (err) =>
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
 * skips the second factor entirely. Otherwise an OTP is sent via `sendOtp`
 * and the user must verify it with `OtpSecondFactorService.verify`.
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   TrustedDeviceWithOtpSecondFactorGateLayer.pipe(
 *     Layer.provide(TrustedDeviceService.layer({ secret: "..." })),
 *     Layer.provide(trustedDeviceStore),
 *     Layer.provide(OtpSecondFactorService.layer({ sendOtp: ... })),
 *     Layer.provide(otpSecondFactorStore),
 *   ),
 * )
 * ```
 */
export const TrustedDeviceWithOtpSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TrustedDeviceService | TrustedDeviceStore | OtpSecondFactorService | OtpSecondFactorStore
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const tdService = yield* TrustedDeviceService;
    const otpService = yield* OtpSecondFactorService;
    const tdStores = yield* Effect.context<TrustedDeviceStore>();
    const otpStores = yield* Effect.context<OtpSecondFactorStore>();

    const otpGate: SecondFactorGateShape = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        otpService.begin(user).pipe(
          Effect.provide(otpStores),
          Effect.catchTag("OtpSecondFactorError", (err) =>
            Effect.fail(new Errors.AuthError({ message: err.message })),
          ),
        ),
    };

    return makeTrustedDeviceGateShape(tdService, tdStores, otpGate);
  }),
);
