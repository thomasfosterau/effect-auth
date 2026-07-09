/**
 * Two-factor authentication (TOTP + backup codes) for effect-auth.
 *
 * Mirrors better-auth's two-factor plugin: users enable 2FA by verifying
 * their password, receive a TOTP secret (as an otpauth:// URI for QR codes)
 * plus single-use backup codes, and must confirm with a valid TOTP code
 * before 2FA is considered active. Sign-in flows that detect an enabled
 * second factor create a short-lived pending challenge ("password OK,
 * awaiting second factor") which is redeemed with either a TOTP code or a
 * backup code to mint the session.
 *
 * @module two-factor
 */

import { Config, Context, Data, Effect, Layer, Redacted } from "effect";
import * as crypto from "node:crypto";
import { makeAes256GcmCipher } from "./Cipher.ts";
import type { TokenCipher } from "./Cipher.ts";
import * as Errors from "./Errors.ts";
import * as Obs from "./Observability.ts";
import { EmailPasswordStore, SecondFactorGate } from "./email/EmailPassword.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { generateBase32Secret, generateOTPURI, verifyTOTP, type TOTPConfig } from "./OTP.ts";
import { PasswordHasher } from "./password/Password.ts";
import type * as Types from "./Types.ts";
import { UserStore } from "./session/UserStore.ts";
import { SessionService } from "./session/SessionService.ts";

/**
 * Two-factor error
 */
export class TwoFactorError extends Data.TaggedError("TwoFactorError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Persistent two-factor state for a user.
 *
 * `backupCodes` holds sha256 hex digests of the (normalized) plaintext
 * codes — the plaintext is only ever returned once, at generation time.
 * `verified` stays `false` until the user confirms enrollment with a valid
 * TOTP code (unless `skipVerificationOnEnable` is set).
 */
export interface TwoFactorRecord {
  readonly userId: string;
  /** Base32-encoded TOTP secret */
  readonly secret: string;
  /** sha256 hex hashes of the remaining (unused) backup codes */
  readonly backupCodes: readonly string[];
  /** False until the first successful TOTP confirmation */
  readonly verified: boolean;
  readonly createdAt: number;
}

/**
 * Storage interface for two-factor records
 */
export class TwoFactorStore extends Context.Service<
  TwoFactorStore,
  {
    readonly get: (userId: string) => Effect.Effect<TwoFactorRecord | null, Errors.AuthError>;
    readonly upsert: (
      record: TwoFactorRecord,
    ) => Effect.Effect<TwoFactorRecord, Errors.AuthError>;
    readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/TwoFactorStore") {}

/**
 * Short-lived "password OK, awaiting second factor" state created by
 * `beginChallenge` and redeemed (one-time) by `verifyTotp`/`verifyBackupCode`.
 */
export interface PendingTwoFactor {
  readonly token: string;
  readonly userId: string;
  readonly expiresAt: number;
  readonly createdAt: number;
}

/**
 * Storage interface for pending two-factor challenges
 */
export class PendingTwoFactorStore extends Context.Service<
  PendingTwoFactorStore,
  {
    readonly create: (
      pending: PendingTwoFactor,
    ) => Effect.Effect<PendingTwoFactor, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<PendingTwoFactor | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/PendingTwoFactorStore") {}

/**
 * Two-factor service configuration
 */
export interface TwoFactorConfig {
  /** Issuer name embedded in the otpauth:// URI (e.g. your app name) */
  readonly issuer: string;
  /** TOTP parameters (period/digits/algorithm/window). Default: RFC 6238 defaults */
  readonly totp?: TOTPConfig;
  /** Number of backup codes to generate (default: 10) */
  readonly backupCodeCount?: number;
  /** Lifetime of a pending challenge in milliseconds (default: 5 minutes) */
  readonly pendingExpiresIn?: number;
  /**
   * Mark the record verified immediately on enable, skipping the
   * `confirmEnable` TOTP confirmation step (default: false).
   */
  readonly skipVerificationOnEnable?: boolean;
  /**
   * Opt-in encryption-at-rest for the base32 TOTP `secret` field in
   * {@link TwoFactorStore}. The store sees only ciphertext; plaintext is only
   * ever held in memory during enrollment and verification.
   *
   * Pass `{ secret }` to use the built-in AES-256-GCM cipher. Pass
   * `{ cipher }` to supply a custom {@link TokenCipher} (envelope
   * encryption, HSM-backed keys, etc.).
   *
   * Strongly recommended in production. Backup codes are already SHA-256
   * hashed and are unaffected by this option.
   */
  readonly encryptSecret?:
    | { readonly secret: Redacted.Redacted<string> }
    | { readonly cipher: TokenCipher };
}

/**
 * Result of enabling two-factor: the secret and backup codes are returned
 * in plaintext exactly once — show them to the user, then discard.
 */
export interface TwoFactorEnableResult {
  /** Base32-encoded TOTP secret */
  readonly secret: string;
  /** otpauth:// URI for QR code generation */
  readonly totpUri: string;
  /** Plaintext single-use backup codes (shown once) */
  readonly backupCodes: readonly string[];
}

/**
 * A pending second-factor challenge handed back to the caller.
 */
export interface TwoFactorChallenge {
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * Result of redeeming a pending challenge with a valid second factor.
 */
export interface TwoFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}

export interface TwoFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Two-factor authentication service
 */
export class TwoFactorService extends Context.Service<
  TwoFactorService,
  {
    /**
     * Enable two-factor for a user. Verifies the user's password, generates a
     * TOTP secret plus backup codes, and stores the record (unverified unless
     * `skipVerificationOnEnable`). Returns the plaintext secret, otpauth:// URI
     * (labelled with the user's email) and plaintext backup codes — shown once.
     */
    readonly enable: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      TwoFactorEnableResult,
      | TwoFactorError
      | Errors.InvalidCredentialsError
      | Errors.HashingError
      | Errors.AuthError
      | Errors.UserNotFoundError,
      TwoFactorStore | EmailPasswordStore | PasswordHasher | UserStore
    >;

    /**
     * Confirm enrollment with a TOTP code generated from the stored secret.
     * Marks the record verified; two-factor is only enforced once verified.
     */
    readonly confirmEnable: (
      userId: string,
      code: string,
    ) => Effect.Effect<
      void,
      TwoFactorError | Errors.HashingError | Errors.AuthError,
      TwoFactorStore
    >;

    /**
     * Disable two-factor after re-verifying the user's password.
     */
    readonly disable: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      void,
      Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
      TwoFactorStore | EmailPasswordStore | PasswordHasher
    >;

    /**
     * Whether the user has a verified two-factor record.
     */
    readonly isEnabled: (
      userId: string,
    ) => Effect.Effect<boolean, Errors.AuthError, TwoFactorStore>;

    /**
     * Start a second-factor challenge for a user whose first factor (e.g.
     * password) already checked out. Returns a one-time pending token to be
     * redeemed with `verifyTotp` or `verifyBackupCode`.
     */
    readonly beginChallenge: (
      userId: string,
    ) => Effect.Effect<
      TwoFactorChallenge,
      TwoFactorError | Errors.AuthError,
      TwoFactorStore | PendingTwoFactorStore
    >;

    /**
     * Redeem a pending challenge with a TOTP code. On success the pending
     * token is consumed (one-time use) and a session is created.
     */
    readonly verifyTotp: (
      pendingToken: string,
      code: string,
      options?: TwoFactorVerifyOptions,
    ) => Effect.Effect<
      TwoFactorVerifyResult,
      TwoFactorError | Errors.HashingError | Errors.AuthError | HookError,
      TwoFactorStore | PendingTwoFactorStore | SessionService | Hooks
    >;

    /**
     * Redeem a pending challenge with a backup code. The matched code is
     * removed from the record (single use) and a session is created.
     */
    readonly verifyBackupCode: (
      pendingToken: string,
      code: string,
      options?: TwoFactorVerifyOptions,
    ) => Effect.Effect<
      TwoFactorVerifyResult,
      TwoFactorError | Errors.AuthError | HookError,
      TwoFactorStore | PendingTwoFactorStore | SessionService | Hooks
    >;

    /**
     * Replace all backup codes after re-verifying the user's password.
     * Returns the new plaintext codes (shown once); old codes are invalidated.
     */
    readonly regenerateBackupCodes: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      readonly string[],
      TwoFactorError | Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
      TwoFactorStore | EmailPasswordStore | PasswordHasher
    >;
  }
>()("@effect-auth/TwoFactorService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: TwoFactorConfig) =>
    Layer.effect(TwoFactorService, makeTwoFactorService(config));

  /**
   * Construct a Layer from environment variables via {@link twoFactorConfig}.
   *
   * Required env vars: `TWO_FACTOR_ISSUER`.
   * Optional: `TWO_FACTOR_ENCRYPT_SECRET`.
   */
  static readonly layerFromEnv = Layer.effect(
    TwoFactorService,
    Effect.gen(function* () {
      const cfg = yield* twoFactorConfig;
      return yield* makeTwoFactorService({
        issuer: cfg.issuer,
        ...(cfg.encryptSecret !== undefined && { encryptSecret: cfg.encryptSecret }),
      });
    }),
  );
}

/**
 * Effect `Config` for {@link TwoFactorConfig}.
 *
 * Required env vars: `TWO_FACTOR_ISSUER`.
 * Optional: `TWO_FACTOR_ENCRYPT_SECRET`.
 */
export const twoFactorConfig = Config.all({
  issuer: Config.string("TWO_FACTOR_ISSUER"),
  encryptSecret: Config.redacted("TWO_FACTOR_ENCRYPT_SECRET").pipe(
    Config.map((secret) => ({ secret }) as const),
    Config.orElse(() => Config.succeed(undefined)),
  ),
});

/**
 * Generate a cryptographically secure pending-challenge token
 */
const generatePendingToken = (): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"));

/**
 * Generate a single plaintext backup code: 10 crypto-random hex characters
 * formatted as `xxxxx-xxxxx`.
 */
const generateBackupCode = (): string => {
  const raw = crypto.randomBytes(5).toString("hex");
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
};

/**
 * Normalize a backup code for hashing/comparison (strip separators and
 * whitespace, lowercase) so `xxxxx-xxxxx` and `xxxxxxxxxx` both match.
 */
const normalizeBackupCode = (code: string): string => code.replace(/[\s-]/g, "").toLowerCase();

/**
 * sha256 hex digest of a normalized backup code
 */
export const hashBackupCode = (code: string): string =>
  crypto.createHash("sha256").update(normalizeBackupCode(code)).digest("hex");

/**
 * Find the index of a backup-code hash using timing-safe comparison.
 * Scans the full list (no early exit) to avoid leaking the match position.
 */
const findBackupCodeIndex = (hashes: readonly string[], candidateHash: string): number => {
  const candidate = Buffer.from(candidateHash, "hex");
  let match = -1;
  for (let i = 0; i < hashes.length; i++) {
    const stored = Buffer.from(hashes[i], "hex");
    if (
      stored.length === candidate.length &&
      crypto.timingSafeEqual(stored, candidate) &&
      match === -1
    ) {
      match = i;
    }
  }
  return match;
};

/**
 * Create a two-factor service
 */
export const makeTwoFactorService = (
  config: TwoFactorConfig,
): Effect.Effect<typeof TwoFactorService.Service, never> => {
  const backupCodeCount = config.backupCodeCount ?? 10;
  const pendingExpiresIn = config.pendingExpiresIn ?? 5 * 60 * 1000; // 5 minutes default
  const skipVerificationOnEnable = config.skipVerificationOnEnable ?? false;

  const cipher: TokenCipher | null = config.encryptSecret
    ? "cipher" in config.encryptSecret
      ? config.encryptSecret.cipher
      : makeAes256GcmCipher(Redacted.value(config.encryptSecret.secret))
    : null;

  /**
   * Verify the user's password against the hash held by the email/password
   * store. Fails with InvalidCredentialsError on mismatch or missing hash.
   */
  const verifyPassword = (userId: string, password: string) =>
    Effect.gen(function* () {
      const store = yield* EmailPasswordStore;
      const passwordHasher = yield* PasswordHasher;

      const passwordHash = yield* store.getPasswordHash(userId);
      if (!passwordHash) {
        return yield* Effect.fail(
          new Errors.InvalidCredentialsError({
            message: "Invalid password",
          }),
        );
      }

      const isValid = yield* passwordHasher.verify(password, passwordHash);
      if (!isValid) {
        return yield* Effect.fail(
          new Errors.InvalidCredentialsError({
            message: "Invalid password",
          }),
        );
      }
    });

  /**
   * Resolve a pending challenge token, enforcing expiry. Expired tokens are
   * deleted eagerly; the token itself is only consumed on successful
   * verification (see verifyTotp/verifyBackupCode).
   */
  const resolvePending = (pendingToken: string) =>
    Effect.gen(function* () {
      const pendingStore = yield* PendingTwoFactorStore;

      const pending = yield* pendingStore.get(pendingToken);
      if (!pending) {
        return yield* Effect.fail(
          new TwoFactorError({
            message: "Invalid or expired two-factor challenge token",
          }),
        );
      }

      if (Date.now() > pending.expiresAt) {
        yield* pendingStore.delete(pendingToken);
        return yield* Effect.fail(
          new TwoFactorError({
            message: "Two-factor challenge token has expired",
          }),
        );
      }

      return pending;
    });

  /**
   * Load the verified two-factor record for a user, failing if two-factor
   * is not (fully) enabled.
   */
  const getVerifiedRecord = (userId: string) =>
    Effect.gen(function* () {
      const store = yield* TwoFactorStore;
      const record = yield* store.get(userId);
      if (!record || !record.verified) {
        return yield* Effect.fail(
          new TwoFactorError({
            message: "Two-factor authentication is not enabled for this user",
          }),
        );
      }
      return record;
    });

  return Effect.sync(
    (): typeof TwoFactorService.Service => ({
      enable: (userId: string, password: string) =>
        Effect.gen(function* () {
          yield* verifyPassword(userId, password);

          const store = yield* TwoFactorStore;
          const userStore = yield* UserStore;

          // The otpauth:// label is the user's email
          const user = yield* userStore.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          const secret = yield* generateBase32Secret();
          const storedSecret = cipher !== null ? yield* cipher.encrypt(secret) : secret;

          const backupCodes = Array.from({ length: backupCodeCount }, () => generateBackupCode());

          const record: TwoFactorRecord = {
            userId,
            secret: storedSecret,
            backupCodes: backupCodes.map((code) => hashBackupCode(code)),
            verified: skipVerificationOnEnable,
            createdAt: Date.now(),
          };

          yield* store.upsert(record);

          const totp = config.totp;
          const totpUri = yield* Effect.try({
            try: () =>
              generateOTPURI({
                type: "totp",
                label: user.email,
                issuer: config.issuer,
                secret, // always use plaintext for URI generation
                ...(totp?.period !== undefined && { period: totp.period }),
                ...(totp?.digits !== undefined && { digits: totp.digits }),
                ...(totp?.algorithm !== undefined && { algorithm: totp.algorithm }),
              }),
            catch: (error) =>
              new TwoFactorError({
                message: "Failed to generate otpauth URI",
                cause: error,
              }),
          });

          return {
            secret, // always return plaintext secret
            totpUri,
            backupCodes,
          } satisfies TwoFactorEnableResult;
        }),

      confirmEnable: (userId: string, code: string) =>
        Effect.gen(function* () {
          const store = yield* TwoFactorStore;

          const record = yield* store.get(userId);
          if (!record) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Two-factor authentication has not been set up for this user",
              }),
            );
          }

          const plainSecret =
            cipher !== null ? yield* cipher.decrypt(record.secret) : record.secret;
          const isValid = yield* verifyTOTP(code, plainSecret, config.totp);
          if (!isValid) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Invalid two-factor code",
              }),
            );
          }

          yield* store.upsert({ ...record, verified: true });
        }),

      disable: (userId: string, password: string) =>
        Effect.gen(function* () {
          yield* verifyPassword(userId, password);

          const store = yield* TwoFactorStore;
          yield* store.delete(userId);
        }),

      isEnabled: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* TwoFactorStore;
          const record = yield* store.get(userId);
          return record !== null && record.verified;
        }),

      beginChallenge: (userId: string) =>
        Effect.gen(function* () {
          // Only users with a verified record can be challenged
          yield* getVerifiedRecord(userId);

          const pendingStore = yield* PendingTwoFactorStore;
          const token = yield* generatePendingToken();

          const pending: PendingTwoFactor = {
            token,
            userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + pendingExpiresIn,
          };

          yield* pendingStore.create(pending);

          return {
            token,
            expiresAt: pending.expiresAt,
          } satisfies TwoFactorChallenge;
        }).pipe(
          Effect.withSpan("effect-auth.2fa.challenge"),
          Effect.tap(() => Obs.recordTwoFactorChallenge()),
        ),

      verifyTotp: (pendingToken: string, code: string, options?: TwoFactorVerifyOptions) =>
        Effect.gen(function* () {
          const pending = yield* resolvePending(pendingToken);
          const record = yield* getVerifiedRecord(pending.userId);

          const plainSecret =
            cipher !== null ? yield* cipher.decrypt(record.secret) : record.secret;
          const isValid = yield* verifyTOTP(code, plainSecret, config.totp);
          if (!isValid) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Invalid two-factor code",
              }),
            );
          }

          // Consume the pending token (one-time use)
          const pendingStore = yield* PendingTwoFactorStore;
          yield* pendingStore.delete(pendingToken);

          const sessionManager = yield* SessionService;
          const session = yield* sessionManager.createSession(
            pending.userId,
            options?.sessionAttributes,
          );

          return {
            userId: pending.userId,
            session,
          } satisfies TwoFactorVerifyResult;
        }).pipe(
          Effect.withSpan("effect-auth.2fa.verify", { attributes: { type: "totp" } }),
          Effect.tap(() => Obs.recordTwoFactorVerification("totp", "success")),
          Effect.tapError(() => Obs.recordTwoFactorVerification("totp", "failure")),
        ),

      verifyBackupCode: (pendingToken: string, code: string, options?: TwoFactorVerifyOptions) =>
        Effect.gen(function* () {
          const pending = yield* resolvePending(pendingToken);
          const record = yield* getVerifiedRecord(pending.userId);

          const index = findBackupCodeIndex(record.backupCodes, hashBackupCode(code));
          if (index === -1) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Invalid backup code",
              }),
            );
          }

          // Remove the used code (single use)
          const store = yield* TwoFactorStore;
          yield* store.upsert({
            ...record,
            backupCodes: record.backupCodes.filter((_, i) => i !== index),
          });

          // Consume the pending token (one-time use)
          const pendingStore = yield* PendingTwoFactorStore;
          yield* pendingStore.delete(pendingToken);

          const sessionManager = yield* SessionService;
          const session = yield* sessionManager.createSession(
            pending.userId,
            options?.sessionAttributes,
          );

          return {
            userId: pending.userId,
            session,
          } satisfies TwoFactorVerifyResult;
        }).pipe(
          Effect.withSpan("effect-auth.2fa.verify", { attributes: { type: "backup-code" } }),
          Effect.tap(() => Obs.recordTwoFactorVerification("backup-code", "success")),
          Effect.tapError(() => Obs.recordTwoFactorVerification("backup-code", "failure")),
        ),

      regenerateBackupCodes: (userId: string, password: string) =>
        Effect.gen(function* () {
          yield* verifyPassword(userId, password);

          const store = yield* TwoFactorStore;
          const record = yield* store.get(userId);
          if (!record) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Two-factor authentication is not enabled for this user",
              }),
            );
          }

          const backupCodes = Array.from({ length: backupCodeCount }, () => generateBackupCode());

          yield* store.upsert({
            ...record,
            backupCodes: backupCodes.map(hashBackupCode),
          });

          return backupCodes;
        }),
    }),
  );
};

/**
 * Provides the {@link SecondFactorGate} seam so password sign-in returns a
 * two-factor challenge (instead of a session) for enrolled users.
 *
 * The gate's methods are self-contained (`R = never`), so the two-factor
 * stores are captured from context when the layer is built:
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   TwoFactorGateLayer.pipe(
 *     Layer.provide(TwoFactorService.layer({ issuer: "MyApp" })),
 *     Layer.provide(twoFactorStores),
 *   ),
 * )
 * ```
 */
export const TwoFactorGateLayer: Layer.Layer<
  SecondFactorGate,
  never,
  TwoFactorService | TwoFactorStore | PendingTwoFactorStore
> = Layer.effect(
  SecondFactorGate,
  Effect.gen(function* () {
    const twoFactor = yield* TwoFactorService;
    const stores = yield* Effect.context<TwoFactorStore | PendingTwoFactorStore>();

    const gate: typeof SecondFactorGate.Service = {
      required: (user) => twoFactor.isEnabled(user.id).pipe(Effect.provide(stores)),
      begin: (user) =>
        twoFactor.beginChallenge(user.id).pipe(
          Effect.provide(stores),
          Effect.catchTag("TwoFactorError", (error) =>
            Effect.fail(new Errors.AuthError({ message: error.message })),
          ),
        ),
    };
    return gate;
  }),
);
