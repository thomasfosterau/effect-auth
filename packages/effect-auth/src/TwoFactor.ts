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

import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.js";
import {
  EmailPasswordStoreTag,
  SecondFactorGateTag,
  type SecondFactorGate,
} from "./EmailPassword.js";
import { Hooks, type HookError } from "./Hooks.js";
import { generateBase32Secret, generateOTPURI, verifyTOTP, type TOTPConfig } from "./Otp.js";
import { PasswordHasherTag } from "./Password.js";
import { SessionManagerTag, UserStoreTag } from "./Session.js";
import type * as Types from "./Types.js";

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
export interface TwoFactorStore {
  readonly get: (userId: string) => Effect.Effect<TwoFactorRecord | null, Errors.AuthError>;
  readonly upsert: (record: TwoFactorRecord) => Effect.Effect<TwoFactorRecord, Errors.AuthError>;
  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

export class TwoFactorStoreTag extends Context.Service<TwoFactorStoreTag, TwoFactorStore>()(
  "@effect-auth/TwoFactorStore",
) {}

// Public ergonomic alias
export const TwoFactorStore = TwoFactorStoreTag;

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
export interface PendingTwoFactorStore {
  readonly create: (pending: PendingTwoFactor) => Effect.Effect<PendingTwoFactor, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<PendingTwoFactor | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
}

export class PendingTwoFactorStoreTag extends Context.Service<
  PendingTwoFactorStoreTag,
  PendingTwoFactorStore
>()("@effect-auth/PendingTwoFactorStore") {}

// Public ergonomic alias
export const PendingTwoFactorStore = PendingTwoFactorStoreTag;

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
export interface TwoFactorService {
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
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag | UserStoreTag
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
    TwoFactorStoreTag
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
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag
  >;

  /**
   * Whether the user has a verified two-factor record.
   */
  readonly isEnabled: (
    userId: string,
  ) => Effect.Effect<boolean, Errors.AuthError, TwoFactorStoreTag>;

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
    TwoFactorStoreTag | PendingTwoFactorStoreTag
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
    TwoFactorStoreTag | PendingTwoFactorStoreTag | SessionManagerTag | Hooks
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
    TwoFactorStoreTag | PendingTwoFactorStoreTag | SessionManagerTag | Hooks
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
    TwoFactorStoreTag | EmailPasswordStoreTag | PasswordHasherTag
  >;
}

export class TwoFactorServiceTag extends Context.Service<TwoFactorServiceTag, TwoFactorService>()(
  "@effect-auth/TwoFactorService",
) {}

// Public ergonomic alias
export const TwoFactorService = TwoFactorServiceTag;

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
): Effect.Effect<TwoFactorService, never> => {
  const backupCodeCount = config.backupCodeCount ?? 10;
  const pendingExpiresIn = config.pendingExpiresIn ?? 5 * 60 * 1000; // 5 minutes default
  const skipVerificationOnEnable = config.skipVerificationOnEnable ?? false;

  /**
   * Verify the user's password against the hash held by the email/password
   * store. Fails with InvalidCredentialsError on mismatch or missing hash.
   */
  const verifyPassword = (userId: string, password: string) =>
    Effect.gen(function* () {
      const store = yield* EmailPasswordStoreTag;
      const passwordHasher = yield* PasswordHasherTag;

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
      const pendingStore = yield* PendingTwoFactorStoreTag;

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
      const store = yield* TwoFactorStoreTag;
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
    (): TwoFactorService => ({
      enable: (userId: string, password: string) =>
        Effect.gen(function* () {
          yield* verifyPassword(userId, password);

          const store = yield* TwoFactorStoreTag;
          const userStore = yield* UserStoreTag;

          // The otpauth:// label is the user's email
          const user = yield* userStore.get(userId);

          const secret = yield* generateBase32Secret();

          const backupCodes = Array.from({ length: backupCodeCount }, () => generateBackupCode());

          const record: TwoFactorRecord = {
            userId,
            secret,
            backupCodes: backupCodes.map(hashBackupCode),
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
                secret,
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
            secret,
            totpUri,
            backupCodes,
          } satisfies TwoFactorEnableResult;
        }),

      confirmEnable: (userId: string, code: string) =>
        Effect.gen(function* () {
          const store = yield* TwoFactorStoreTag;

          const record = yield* store.get(userId);
          if (!record) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Two-factor authentication has not been set up for this user",
              }),
            );
          }

          const isValid = yield* verifyTOTP(code, record.secret, config.totp);
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

          const store = yield* TwoFactorStoreTag;
          yield* store.delete(userId);
        }),

      isEnabled: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* TwoFactorStoreTag;
          const record = yield* store.get(userId);
          return record !== null && record.verified;
        }),

      beginChallenge: (userId: string) =>
        Effect.gen(function* () {
          // Only users with a verified record can be challenged
          yield* getVerifiedRecord(userId);

          const pendingStore = yield* PendingTwoFactorStoreTag;
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
        }),

      verifyTotp: (pendingToken: string, code: string, options?: TwoFactorVerifyOptions) =>
        Effect.gen(function* () {
          const pending = yield* resolvePending(pendingToken);
          const record = yield* getVerifiedRecord(pending.userId);

          const isValid = yield* verifyTOTP(code, record.secret, config.totp);
          if (!isValid) {
            return yield* Effect.fail(
              new TwoFactorError({
                message: "Invalid two-factor code",
              }),
            );
          }

          // Consume the pending token (one-time use)
          const pendingStore = yield* PendingTwoFactorStoreTag;
          yield* pendingStore.delete(pendingToken);

          const sessionManager = yield* SessionManagerTag;
          const session = yield* sessionManager.createSession(
            pending.userId,
            options?.sessionAttributes,
          );

          return {
            userId: pending.userId,
            session,
          } satisfies TwoFactorVerifyResult;
        }),

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
          const store = yield* TwoFactorStoreTag;
          yield* store.upsert({
            ...record,
            backupCodes: record.backupCodes.filter((_, i) => i !== index),
          });

          // Consume the pending token (one-time use)
          const pendingStore = yield* PendingTwoFactorStoreTag;
          yield* pendingStore.delete(pendingToken);

          const sessionManager = yield* SessionManagerTag;
          const session = yield* sessionManager.createSession(
            pending.userId,
            options?.sessionAttributes,
          );

          return {
            userId: pending.userId,
            session,
          } satisfies TwoFactorVerifyResult;
        }),

      regenerateBackupCodes: (userId: string, password: string) =>
        Effect.gen(function* () {
          yield* verifyPassword(userId, password);

          const store = yield* TwoFactorStoreTag;
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

export const TwoFactorServiceLayer = (config: TwoFactorConfig) =>
  Layer.effect(TwoFactorServiceTag, makeTwoFactorService(config));

/**
 * Provides the {@link SecondFactorGateTag} seam so password sign-in returns a
 * two-factor challenge (instead of a session) for enrolled users.
 *
 * The gate's methods are self-contained (`R = never`), so the two-factor
 * stores are captured from context when the layer is built:
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordServiceLayer(),
 *   TwoFactorGateLayer.pipe(
 *     Layer.provide(TwoFactorServiceLayer({ issuer: "MyApp" })),
 *     Layer.provide(twoFactorStores),
 *   ),
 * )
 * ```
 */
export const TwoFactorGateLayer: Layer.Layer<
  SecondFactorGateTag,
  never,
  TwoFactorServiceTag | TwoFactorStoreTag | PendingTwoFactorStoreTag
> = Layer.effect(
  SecondFactorGateTag,
  Effect.gen(function* () {
    const twoFactor = yield* TwoFactorServiceTag;
    const stores = yield* Effect.context<TwoFactorStoreTag | PendingTwoFactorStoreTag>();

    const gate: SecondFactorGate = {
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
