/**
 * Trusted-device tokens for skipping second-factor challenges.
 *
 * OFF by default — opt-in by including `TrustedDeviceService.layer(config)` in
 * your service graph. Tokens are HMAC-SHA256-signed so they cannot be forged;
 * only the SHA-256 hash of the raw token is stored at rest (via `hashToken`),
 * so a stolen database does not allow replay. Revocation is immediate: call
 * `revokeAll` on password change, 2FA disable, and sign-out-everywhere.
 *
 * **NEVER** use a trusted-device token to satisfy step-up authentication for
 * sensitive operations — always require a fresh second factor there.
 *
 * ### Cookie format
 *
 * `<rawToken>.<hmac>` — the raw token (32-byte base64url) followed by a dot
 * separator and its HMAC-SHA256 hex digest. Only the raw-token half is hashed
 * for DB storage; the HMAC half is verified first (constant-time) before any
 * DB lookup, eliminating oracle attacks on the hash.
 *
 * ### Per-request injection
 *
 * The gate reads the device cookie from `TrustedDeviceCookieRef`, a
 * `Context.Reference` with no requirements (R = never). Override it at the
 * HTTP request boundary before running sign-in:
 *
 * ```ts
 * Effect.provide(Context.make(TrustedDeviceCookieRef, request.cookie("device")))
 * ```
 *
 * @module trusted-device
 */
import { Config, Context, Crypto, Effect, Layer, Redacted } from "effect";
import * as Cipher from "./Cipher.ts";
import * as Errors from "./Errors.ts";
import { SecondFactorGate } from "./email/EmailPassword.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { hashToken, timingSafeEqualBytes } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { MultiFactorService } from "./multifactor/MultiFactor.ts";

// ---------------------------------------------------------------------------
// Record + Store
// ---------------------------------------------------------------------------

/**
 * Trusted-device record stored in the database. The raw token is never
 * persisted; only its SHA-256 digest is kept for constant-time revocation.
 */
export interface TrustedDeviceRecord {
  /** SHA-256 hex digest of the raw token (`hashToken(rawToken)`). */
  readonly tokenHash: string;
  readonly userId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Persistence interface for trusted-device tokens. Keyed by `tokenHash`
 * (SHA-256 of the raw token half of the cookie).
 */
export class TrustedDeviceStore extends Context.Service<
  TrustedDeviceStore,
  {
    readonly upsert: (
      record: TrustedDeviceRecord,
    ) => Effect.Effect<TrustedDeviceRecord, Errors.AuthError>;
    readonly getByTokenHash: (
      tokenHash: string,
    ) => Effect.Effect<TrustedDeviceRecord | null, Errors.AuthError>;
    readonly delete: (tokenHash: string) => Effect.Effect<void, Errors.AuthError>;
    /** Revoke every device token for a user (password change, 2FA disable, etc.). */
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/TrustedDeviceStore") {}

// ---------------------------------------------------------------------------
// Per-request Context.Reference
// ---------------------------------------------------------------------------

/**
 * Per-request `Context.Reference` carrying the trusted-device cookie value
 * supplied by the HTTP handler. Defaults to `undefined` (no cookie present).
 * Override it at the request boundary before running sign-in:
 *
 * ```ts
 * Effect.provide(Context.make(TrustedDeviceCookieRef, req.cookie("device-token")))
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
  readonly secret: Redacted.Redacted<string>;
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
     * token is valid (HMAC matches, not expired, not revoked), or `null`
     * otherwise. Never throws on invalid tokens — returns `null` instead.
     */
    readonly verify: (cookieValue: string) => Effect.Effect<string | null, Errors.AuthError>;

    /**
     * Revoke a single device token by its cookie value.
     * Use when the user explicitly signs out on one device.
     */
    readonly revoke: (cookieValue: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Revoke all trusted-device tokens for a user.
     * **Must** be called on: password change, 2FA disable, sign-out-everywhere.
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

const computeHmac = (secret: Redacted.Redacted<string>, rawToken: string): string =>
  Buffer.from(Cipher.hmac("sha256", Redacted.value(secret), rawToken)).toString("hex");

/** Constant-time comparison of two hex strings of equal expected length. */
const timingSafeHexEqual = (a: string, b: string): boolean =>
  timingSafeEqualBytes(Buffer.from(a, "hex"), Buffer.from(b, "hex"));

const parseCookie = (cookieValue: string): { rawToken: string; hmac: string } | null => {
  const idx = cookieValue.lastIndexOf(COOKIE_SEPARATOR);
  if (idx === -1) return null;
  const rawToken = cookieValue.slice(0, idx);
  const hmac = cookieValue.slice(idx + 1);
  if (!rawToken || !hmac) return null;
  return { rawToken, hmac };
};

/**
 * Build a {@link TrustedDeviceService} from its config; requires `TrustedDeviceStore` and `Crypto.Crypto`.
 */
export const make = (
  config: TrustedDeviceConfig,
): Effect.Effect<typeof TrustedDeviceService.Service, never, TrustedDeviceStore | Crypto.Crypto> =>
  Effect.gen(function* () {
    const maxAge = config.maxAge ?? 30 * 24 * 60 * 60 * 1000;
    const store = yield* TrustedDeviceStore;
    const crypto = yield* Crypto.Crypto;

    const generateRawToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate device token", cause }),
        ),
      );

    return {
      issue: Effect.fn("TrustedDeviceService.issue")(function* (userId: string) {
        const rawToken = yield* generateRawToken();
        const hmac = computeHmac(config.secret, rawToken);
        const tokenHash = hashToken(rawToken);
        const now = Date.now();
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
        if (!parsed) return null;

        // Verify HMAC before touching the DB (forgery protection)
        const expectedHmac = computeHmac(config.secret, parsed.rawToken);
        if (!timingSafeHexEqual(expectedHmac, parsed.hmac)) return null;

        const tokenHash = hashToken(parsed.rawToken);
        const record = yield* store.getByTokenHash(tokenHash);
        if (!record) return null;

        if (Date.now() > record.expiresAt) {
          yield* store.delete(tokenHash);
          return null;
        }

        return record.userId;
      }),

      revoke: Effect.fn("TrustedDeviceService.revoke")(function* (cookieValue: string) {
        const parsed = parseCookie(cookieValue);
        if (!parsed) return;
        yield* store.delete(hashToken(parsed.rawToken));
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
        if (userId === user.id) return false;
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
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   TrustedDeviceWithMultiFactorGateLayer.pipe(
 *     Layer.provide(TrustedDeviceService.layer({ secret: Redacted.make("...") }).pipe(Layer.provide(trustedDeviceStore))),
 *     Layer.provide(MultiFactorService.layer({ issuer: "MyApp" }).pipe(Layer.provide(multiFactorStores))),
 *   ),
 * )
 * ```
 *
 * Remember to call `TrustedDeviceService.revokeAll` whenever the user changes
 * their password, disables 2FA, or signs out everywhere.
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
