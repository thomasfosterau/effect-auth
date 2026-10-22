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
 * instead of `MultiFactorGateLayer`) or in **addition** to it by pairing with
 * `TrustedDevice.gate` from the TrustedDevice module.
 *
 * @module otp-second-factor
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { generateOtp } from "../email/EmailOtp.ts";
import { SecondFactorGate, type SecondFactorChallenge } from "../email/EmailPassword.ts";
import { type HookError } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../SessionService.ts";
import { constantTimeHashEqual, hashToken } from "../TokenHash.ts";
import { TrustedDeviceService } from "../TrustedDevice.ts";
import * as TrustedDevice from "../TrustedDevice.ts";
import type * as Types from "../Types.ts";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/**
 * Failure of the OTP second factor: an expired, unknown or exhausted challenge, a wrong code, or a failed send.
 */
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

/** The store {@link OtpSecondFactorService} keeps pending OTP challenges in (codes hashed). */
export class OtpSecondFactorStore extends Context.Service<
  OtpSecondFactorStore,
  {
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
>()("@effect-auth/OtpSecondFactorStore") {}

// ---------------------------------------------------------------------------
// Config + Service
// ---------------------------------------------------------------------------

/**
 * Configuration for {@link OtpSecondFactorService}.
 */
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

/** Options for {@link OtpSecondFactorService.verify}: attributes for the session it issues. */
export interface OtpSecondFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/** The user id and session issued when the OTP second factor succeeds. */
export interface OtpSecondFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}

/**
 * An email or SMS one-time code as the second factor: issues a challenge after the password step and completes sign-in when the code matches.
 *
 * Requires `OtpSecondFactorStore` and `SessionService`.
 */
export class OtpSecondFactorService extends Context.Service<
  OtpSecondFactorService,
  {
    /**
     * Begin a second-factor OTP challenge. Generates an OTP, stores it
     * (hashed), sends it via `sendOtp`, and returns a `SecondFactorChallenge`
     * with the pending token for the client to submit alongside the OTP.
     */
    readonly begin: (
      user: Types.User,
    ) => Effect.Effect<SecondFactorChallenge, OtpSecondFactorError | Errors.AuthError>;

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
      OtpSecondFactorError | Errors.AuthError | HookError
    >;
  }
>()("@effect-auth/OtpSecondFactorService") {
  static readonly layer = (config: OtpSecondFactorConfig) =>
    Layer.effect(OtpSecondFactorService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const make = (
  config: OtpSecondFactorConfig,
): Effect.Effect<
  typeof OtpSecondFactorService.Service,
  never,
  OtpSecondFactorStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const otpLength = config.otpLength ?? 6;
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000;
    const maxAttempts = config.maxAttempts ?? 3;

    const store = yield* OtpSecondFactorStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    const invalidOtp = () =>
      Effect.fail(new OtpSecondFactorError({ message: "Invalid or expired OTP" }));

    const generatePendingToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate pending token", cause }),
        ),
      );

    return {
      begin: Effect.fn("OtpSecondFactorService.begin")(function* (user: Types.User) {
        const otp = yield* generateOtp(crypto, otpLength);
        const pendingToken = yield* generatePendingToken();
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

      verify: Effect.fn("OtpSecondFactorService.verify")(function* (
        pendingToken: string,
        otp: string,
        options?: OtpSecondFactorVerifyOptions,
      ) {
        if (!pendingToken || !otp) {
          return yield* invalidOtp();
        }

        const record = yield* store.get(pendingToken);
        if (!record) {
          return yield* invalidOtp();
        }

        if (Date.now() > record.expiresAt) {
          yield* store.delete(pendingToken);
          return yield* new OtpSecondFactorError({ message: "OTP has expired" });
        }

        if (record.attempts >= maxAttempts) {
          yield* store.delete(pendingToken);
          return yield* new OtpSecondFactorError({ message: "Too many attempts" });
        }

        if (!constantTimeHashEqual(record.otpHash, hashToken(otp))) {
          const updated = { ...record, attempts: record.attempts + 1 };
          yield* store.update(updated);
          if (updated.attempts >= maxAttempts) {
            yield* store.delete(pendingToken);
            return yield* new OtpSecondFactorError({ message: "Too many attempts" });
          }
          return yield* invalidOtp();
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
        } satisfies OtpSecondFactorVerifyResult;
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
 * an OTP via the configured `sendOtp`. The client then calls
 * `OtpSecondFactorService.verify(pendingToken, otp)` to redeem it.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { Hooks, SessionService } from "@thomasfosterau/effect-auth"
 * import { EmailPasswordService } from "@thomasfosterau/effect-auth/email"
 * import {
 *   OtpSecondFactorGateLayer,
 *   OtpSecondFactorService,
 *   type OtpSecondFactorConfig,
 *   type OtpSecondFactorStore,
 * } from "@thomasfosterau/effect-auth/multifactor"
 * import { PasswordHasher } from "@thomasfosterau/effect-auth/password"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * // The app's store adapter and OTP delivery callback, passed in.
 * export const makeServices = (
 *   otpSecondFactorStore: Layer.Layer<OtpSecondFactorStore>,
 *   sendOtp: OtpSecondFactorConfig["sendOtp"],
 * ) =>
 *   Layer.mergeAll(
 *     EmailPasswordService.layer(),
 *     // provideMerge keeps OtpSecondFactorService in the output, for `verify`.
 *     OtpSecondFactorGateLayer.pipe(
 *       Layer.provideMerge(
 *         OtpSecondFactorService.layer({ sendOtp }).pipe(Layer.provide(otpSecondFactorStore)),
 *       ),
 *     ),
 *   )
 *
 * // Built here over the in-memory reference stores and a sender that records
 * // the code; an app passes its own adapters and mailer.
 * const sent: Array<string> = []
 * const sendOtp: OtpSecondFactorConfig["sendOtp"] = (_user, otp) => Effect.sync(() => void sent.push(otp))
 * const services = makeServices(Testing.memoryStores, sendOtp).pipe(
 *   Layer.provideMerge(
 *     SessionService.layer({ sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 } }),
 *   ),
 *   Layer.provideMerge(Layer.mergeAll(Testing.memoryStores, PasswordHasher.layer(), Hooks.Default)),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const emailPassword = yield* EmailPasswordService
 *   const credentials = { email: "ada@example.com", password: "correct horse battery staple" }
 *   yield* emailPassword.signUp(credentials)
 *   // Every sign-in now stops at a second factor, and the code goes out.
 *   const signedIn = yield* emailPassword.signIn(credentials)
 *   assert.equal(signedIn.session, undefined)
 *   const challenge = signedIn.secondFactor
 *   assert.ok(challenge !== undefined && sent.length === 1)
 *   // The code that was sent redeems the challenge for a session.
 *   const verified = yield* (yield* OtpSecondFactorService).verify(challenge.token, sent[0]!)
 *   assert.equal(verified.session.userId, signedIn.user.id)
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(services)))
 * ```
 */
export const OtpSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  OtpSecondFactorService
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const service = yield* OtpSecondFactorService;

    const gate: typeof SecondFactorGate.Service = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        service
          .begin(user)
          .pipe(
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
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Redacted } from "effect"
 * import {
 *   Hooks,
 *   SessionService,
 *   TrustedDeviceService,
 *   type TrustedDeviceStore,
 * } from "@thomasfosterau/effect-auth"
 * import { EmailPasswordService } from "@thomasfosterau/effect-auth/email"
 * import {
 *   OtpSecondFactorService,
 *   TrustedDeviceWithOtpSecondFactorGateLayer,
 *   type OtpSecondFactorConfig,
 *   type OtpSecondFactorStore,
 * } from "@thomasfosterau/effect-auth/multifactor"
 * import { PasswordHasher } from "@thomasfosterau/effect-auth/password"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * // The app's storage adapters and OTP delivery callback, passed in.
 * export const makeServices = (
 *   trustedDeviceStore: Layer.Layer<TrustedDeviceStore>,
 *   otpSecondFactorStore: Layer.Layer<OtpSecondFactorStore>,
 *   sendOtp: OtpSecondFactorConfig["sendOtp"],
 * ) =>
 *   Layer.mergeAll(
 *     EmailPasswordService.layer(),
 *     TrustedDeviceWithOtpSecondFactorGateLayer.pipe(
 *       Layer.provide(
 *         TrustedDeviceService.layer({ secret: Redacted.make("example-trusted-device-secret") }).pipe(
 *           Layer.provide(trustedDeviceStore),
 *         ),
 *       ),
 *       // provideMerge keeps OtpSecondFactorService in the output, for `verify`.
 *       Layer.provideMerge(
 *         OtpSecondFactorService.layer({ sendOtp }).pipe(Layer.provide(otpSecondFactorStore)),
 *       ),
 *     ),
 *   )
 *
 * // Built here over the in-memory reference stores and a sender that records
 * // the code; an app passes its own adapters and mailer.
 * const sent: Array<string> = []
 * const sendOtp: OtpSecondFactorConfig["sendOtp"] = (_user, otp) => Effect.sync(() => void sent.push(otp))
 * const services = makeServices(Testing.memoryStores, Testing.memoryStores, sendOtp).pipe(
 *   Layer.provideMerge(
 *     SessionService.layer({ sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 } }),
 *   ),
 *   Layer.provideMerge(Layer.mergeAll(Testing.memoryStores, PasswordHasher.layer(), Hooks.Default)),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const emailPassword = yield* EmailPasswordService
 *   const credentials = { email: "ada@example.com", password: "correct horse battery staple" }
 *   yield* emailPassword.signUp(credentials)
 *   // No trusted-device cookie: the sign-in stops at a second factor, and the code goes out.
 *   const signedIn = yield* emailPassword.signIn(credentials)
 *   assert.equal(signedIn.session, undefined)
 *   const challenge = signedIn.secondFactor
 *   assert.ok(challenge !== undefined && sent.length === 1)
 *   // The code that was sent redeems the challenge for a session.
 *   const verified = yield* (yield* OtpSecondFactorService).verify(challenge.token, sent[0]!)
 *   assert.equal(verified.session.userId, signedIn.user.id)
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(services)))
 * ```
 */
export const TrustedDeviceWithOtpSecondFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TrustedDeviceService | OtpSecondFactorService
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const tdService = yield* TrustedDeviceService;
    const otpService = yield* OtpSecondFactorService;

    const otpGate: typeof SecondFactorGate.Service = {
      required: (_user) => Effect.succeed(true),
      begin: (user) =>
        otpService
          .begin(user)
          .pipe(
            Effect.catchTag("OtpSecondFactorError", (err) =>
              Effect.fail(new Errors.AuthError({ message: err.message })),
            ),
          ),
    };

    return TrustedDevice.gate(tdService, otpGate);
  }),
);
