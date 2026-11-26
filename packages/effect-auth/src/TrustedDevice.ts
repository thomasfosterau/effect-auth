/**
 * Trusted-device tokens that skip second-factor challenges, off by default. The
 * cookie is `<rawToken>.<hmac>`; the HMAC is checked first and only the token's
 * digest is stored. A password change or reset and disabling multi-factor
 * revoke every device. The gate reads the cookie from {@link
 * TrustedDeviceCookieRef}.
 *
 * @example Providing the device cookie per request
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect } from "effect"
 * import { TrustedDeviceCookieRef } from "@thomasfosterau/effect-auth"
 *
 * // The incoming request, with its cookie reader.
 * const request = {
 *   cookie: (name: string): string | undefined => (name === "device" ? "device-token-123" : undefined),
 * }
 *
 * const withDeviceCookie = Effect.provide(
 *   Context.make(TrustedDeviceCookieRef, request.cookie("device")),
 * )
 *
 * const program = Effect.gen(function* () {
 *   assert.equal(yield* TrustedDeviceCookieRef, "device-token-123")
 * }).pipe(withDeviceCookie)
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module trusted-device
 */
import { Clock, Config, Context, Effect, Layer, Redacted } from "effect";
import * as Option from "effect/Option";
import { Digest, Mac, SecureRandom } from "effect/crypto";
import { Hex } from "effect/encoding";
import * as Cipher from "./Cipher.ts";
import * as Errors from "./Errors.ts";
import { SecondFactorGate } from "./email/EmailPassword.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { constantTimeHashEqual, tokenHasher } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { MultiFactorService } from "./multifactor/MultiFactor.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";
import { type TrustedDeviceRecord, TrustedDeviceStore } from "./TrustedDeviceStore.ts";

export { type TrustedDeviceRecord, TrustedDeviceStore } from "./TrustedDeviceStore.ts";

// ---------------------------------------------------------------------------
// Per-request Context.Reference
// ---------------------------------------------------------------------------

/**
 * Per-request `Context.Reference` carrying the trusted-device cookie value
 * supplied by the HTTP handler. Defaults to `undefined` (no cookie present).
 * Override it at the request boundary before running sign-in:
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect } from "effect"
 * import { TrustedDeviceCookieRef } from "@thomasfosterau/effect-auth"
 *
 * // The incoming request, with its cookie reader.
 * const req = {
 *   cookie: (name: string): string | undefined =>
 *     name === "device-token" ? "device-token-123" : undefined,
 * }
 *
 * const withDeviceCookie = Effect.provide(
 *   Context.make(TrustedDeviceCookieRef, req.cookie("device-token")),
 * )
 *
 * const program = Effect.gen(function* () {
 *   assert.equal(yield* TrustedDeviceCookieRef, "device-token-123")
 * }).pipe(withDeviceCookie)
 *
 * await Effect.runPromise(program)
 * ```
 *
 * Because `Context.Reference` carries a `defaultValue`, yielding it has
 * R = never — no explicit provision required in the gate.
 */
export const TrustedDeviceCookieRef: Context.Reference<string | undefined> = Context.Reference<
  string | undefined
>("@effect-auth/TrustedDeviceCookieRef", { defaultValue: () => undefined });

// ---------------------------------------------------------------------------
// Config + Service
// ---------------------------------------------------------------------------

/**
 * Configuration for {@link TrustedDeviceService}.
 */
export interface TrustedDeviceConfig {
  /**
   * Max age for trusted-device tokens in milliseconds.
   * Default: 30 days.
   */
  readonly maxAge?: number;
  /**
   * HMAC-SHA256 signing secret. Keep server-side and rotate periodically.
   * Rotating the secret automatically invalidates all outstanding device tokens.
   */
  readonly secret: Redacted.Redacted;
}

/** The cookie value and expiry of a newly trusted device. */
export interface TrustedDeviceIssueResult {
  /** Raw cookie value to set (`rawToken.hmac`). */
  readonly cookieValue: string;
  readonly expiresAt: number;
}

/**
 * Remembers a device that completed a second factor, so later sign-ins from it can skip the factor until the HMAC-signed cookie expires or is revoked. Never use it to satisfy step-up authentication.
 *
 * Requires `TrustedDeviceStore`.
 */
export class TrustedDeviceService extends Context.Service<
  TrustedDeviceService,
  {
    /**
     * Issue a new trusted-device token for a user. Returns the value to
     * store in a `Set-Cookie` header (`HttpOnly; Secure; SameSite=Strict`
     * recommended).
     */
    readonly issue: (userId: string) => Effect.Effect<TrustedDeviceIssueResult, Errors.AuthError>;

    /**
     * Verify a device cookie value. Returns the associated `userId` if the
     * token is valid (HMAC matches, not expired, not revoked), or `None`
     * otherwise. Never fails on an invalid token: it answers `None` instead.
     */
    readonly verify: (
      cookieValue: string,
    ) => Effect.Effect<Option.Option<string>, Errors.AuthError>;

    /**
     * Revoke a single device token by its cookie value.
     * Use when the user explicitly signs out on one device.
     */
    readonly revoke: (cookieValue: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Revoke all trusted-device tokens for a user. Password change (by
     * default), password reset and multi-factor disable already do; call it
     * on sign-out-everywhere.
     */
    readonly revokeAll: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/TrustedDeviceService") {
  static readonly layer = (config: TrustedDeviceConfig) =>
    Layer.effect(TrustedDeviceService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));

  /**
   * Construct a Layer from environment variables via {@link trustedDeviceConfig}.
   *
   * Required env vars: `TRUSTED_DEVICE_SECRET`.
   * Optional: `TRUSTED_DEVICE_MAX_AGE_MS` (default: 30 days).
   */
  static readonly layerFromEnv = Layer.effect(
    TrustedDeviceService,
    Effect.gen(function* () {
      const config = yield* trustedDeviceConfig;
      return yield* make(config);
    }),
  ).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Effect `Config` for {@link TrustedDeviceConfig}.
 *
 * Required env vars: `TRUSTED_DEVICE_SECRET`.
 * Optional: `TRUSTED_DEVICE_MAX_AGE_MS` (default: 30 days in milliseconds).
 */
export const trustedDeviceConfig: Config.Config<TrustedDeviceConfig> = Config.all({
  secret: Config.Redacted("TRUSTED_DEVICE_SECRET"),
  maxAge: Config.Int("TRUSTED_DEVICE_MAX_AGE_MS").pipe(
    Config.withDefault(30 * 24 * 60 * 60 * 1000),
  ),
});

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/** Separator between rawToken and HMAC in the cookie value. */
const COOKIE_SEPARATOR = ".";

/** Constant-time comparison of two hex strings of equal expected length. */
const timingSafeHexEqual = constantTimeHashEqual;

const parseCookie = (cookieValue: string): { rawToken: string; hmac: string } | null => {
  const idx = cookieValue.lastIndexOf(COOKIE_SEPARATOR);
  if (idx === -1) return null;
  const rawToken = cookieValue.slice(0, idx);
  const hmac = cookieValue.slice(idx + 1);
  if (!rawToken || !hmac) return null;
  return { rawToken, hmac };
};

/**
 * Build a {@link TrustedDeviceService} from its config; requires `TrustedDeviceStore` and `SecureRandom.SecureRandom`.
 */
export const make = (
  config: TrustedDeviceConfig,
): Effect.Effect<
  typeof TrustedDeviceService.Service,
  never,
  TrustedDeviceStore | SecureRandom.SecureRandom | Mac.Mac | Digest.Digest
> =>
  Effect.gen(function* () {
    const maxAge = config.maxAge ?? 30 * 24 * 60 * 60 * 1000;
    const store = yield* TrustedDeviceStore;
    const hashToken = yield* tokenHasher;
    const crypto = yield* SecureRandom.SecureRandom;
    const mac = yield* Mac.Mac;

    const computeHmac = (rawToken: string): Effect.Effect<string, Errors.AuthError> =>
      Cipher.hmac("sha256", Redacted.value(config.secret), rawToken).pipe(
        Effect.provideService(Mac.Mac, mac),
        Effect.map(Hex.encode),
      );

    const generateRawToken = (): Effect.Effect<string> => randomBase64UrlToken(crypto);

    return {
      issue: Effect.fn("TrustedDeviceService.issue")(function* (userId: string) {
        const rawToken = yield* generateRawToken();
        const hmac = yield* computeHmac(rawToken);
        const tokenHash = yield* hashToken(rawToken);
        const now = yield* Clock.currentTimeMillis;
        const record: TrustedDeviceRecord = {
          tokenHash,
          userId,
          createdAt: now,
          expiresAt: now + maxAge,
        };
        yield* store.upsert(record);
        return {
          cookieValue: `${rawToken}${COOKIE_SEPARATOR}${hmac}`,
          expiresAt: record.expiresAt,
        };
      }),

      verify: Effect.fn("TrustedDeviceService.verify")(function* (cookieValue: string) {
        const parsed = parseCookie(cookieValue);
        if (!parsed) return Option.none<string>();

        // Verify HMAC before touching the DB (forgery protection)
        const expectedHmac = yield* computeHmac(parsed.rawToken);
        if (!timingSafeHexEqual(expectedHmac, parsed.hmac)) return Option.none<string>();

        const tokenHash = yield* hashToken(parsed.rawToken);
        const found = yield* store.getByTokenHash(tokenHash);
        if (Option.isNone(found)) return Option.none<string>();
        const record = found.value;

        if ((yield* Clock.currentTimeMillis) > record.expiresAt) {
          yield* store.delete(tokenHash);
          return Option.none<string>();
        }

        return Option.some(record.userId);
      }),

      revoke: Effect.fn("TrustedDeviceService.revoke")(function* (cookieValue: string) {
        const parsed = parseCookie(cookieValue);
        if (!parsed) return;
        yield* store.delete(yield* hashToken(parsed.rawToken));
      }),

      revokeAll: Effect.fn("TrustedDeviceService.revokeAll")((userId: string) =>
        store.deleteByUserId(userId),
      ),
    };
  });

// ---------------------------------------------------------------------------
// Gate composition helper
// ---------------------------------------------------------------------------

/**
 * Wrap any `SecondFactorGate` implementation with a trusted-device short-circuit.
 *
 * `required(user)` reads `TrustedDeviceCookieRef` — if a valid, non-expired,
 * non-revoked token for this exact user is present, it returns `false` (skip
 * second factor). Otherwise it delegates to `inner`.
 *
 * `service` already resolved its own store at Layer-construction time
 * (R = never), so the returned shape has R = never too.
 */
export const gate = (
  service: typeof TrustedDeviceService.Service,
  inner: typeof SecondFactorGate.Service,
): typeof SecondFactorGate.Service => ({
  required: (user: Types.User) =>
    Effect.gen(function* () {
      const cookie = yield* TrustedDeviceCookieRef;
      if (cookie !== undefined && cookie !== "") {
        const userId = yield* service.verify(cookie);
        if (Option.contains(userId, user.id)) return false;
      }
      return yield* inner.required(user);
    }),
  begin: (user: Types.User) => inner.begin(user),
});

// ---------------------------------------------------------------------------
// Convenience gate: trusted device + TOTP
// ---------------------------------------------------------------------------

/**
 * Gate layer combining trusted-device short-circuit with TOTP second factor.
 *
 * When a valid device token is present in `TrustedDeviceCookieRef`, sign-in
 * skips the second factor entirely. Otherwise, TOTP enrollment is checked and
 * a TOTP challenge is started via `MultiFactorService`.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Redacted } from "effect"
 * import {
 *   Hooks,
 *   SessionService,
 *   TrustedDeviceService,
 *   type TrustedDeviceStore,
 *   TrustedDeviceWithMultiFactorGateLayer,
 * } from "@thomasfosterau/effect-auth"
 * import { EmailPasswordService } from "@thomasfosterau/effect-auth/email"
 * import {
 *   MultiFactorService,
 *   type MultiFactorStore,
 *   type PendingMultiFactorStore,
 * } from "@thomasfosterau/effect-auth/multifactor"
 * import { PasswordHasher } from "@thomasfosterau/effect-auth/password"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * // The app's storage adapters, passed in.
 * export const makeServices = (
 *   trustedDeviceStore: Layer.Layer<TrustedDeviceStore>,
 *   multiFactorStores: Layer.Layer<MultiFactorStore | PendingMultiFactorStore>,
 * ) =>
 *   Layer.mergeAll(
 *     EmailPasswordService.layer(),
 *     TrustedDeviceWithMultiFactorGateLayer.pipe(
 *       Layer.provide(
 *         TrustedDeviceService.layer({ secret: Redacted.make("example-trusted-device-secret") }).pipe(
 *           Layer.provide(trustedDeviceStore),
 *         ),
 *       ),
 *       Layer.provide(
 *         MultiFactorService.layer({ issuer: "MyApp" }).pipe(Layer.provide(multiFactorStores)),
 *       ),
 *     ),
 *   )
 *
 * // Built here over the in-memory reference stores; an app passes its own.
 * const services = makeServices(Testing.memoryStores, Testing.memoryStores).pipe(
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
 *   // No device cookie and no TOTP enrollment: sign-in goes straight to a session.
 *   const signedIn = yield* emailPassword.signIn(credentials)
 *   assert.equal(signedIn.secondFactor, undefined)
 *   assert.equal(signedIn.session?.userId, signedIn.user.id)
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(services)))
 * ```
 *
 * Password change (by default), password reset and multi-factor disable
 * revoke the user's devices themselves; call `TrustedDeviceService.revokeAll`
 * when the user signs out everywhere.
 */
export const TrustedDeviceWithMultiFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TrustedDeviceService | MultiFactorService
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const trustedDeviceService = yield* TrustedDeviceService;
    const multiFactor = yield* MultiFactorService;

    const totpGate: typeof SecondFactorGate.Service = {
      required: (user) => multiFactor.isEnabled(user.id),
      begin: (user) =>
        multiFactor
          .beginChallenge(user.id)
          .pipe(
            Effect.catchTag("MultiFactorError", (err) =>
              Effect.fail(new Errors.AuthError({ message: err.message })),
            ),
          ),
    };

    return gate(trustedDeviceService, totpGate);
  }),
);
