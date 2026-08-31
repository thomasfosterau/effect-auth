/**
 * Two-factor authentication (TOTP + backup codes) for effect-auth.
 *
 * Mirrors better-auth's multi-factor plugin: users enable 2FA by verifying
 * their password, receive a TOTP secret (as an otpauth:// URI for QR codes)
 * plus single-use backup codes, and must confirm with a valid TOTP code
 * before 2FA is considered active. Sign-in flows that detect an enabled
 * second factor create a short-lived pending challenge ("password OK,
 * awaiting second factor") which is redeemed with either a TOTP code or a
 * backup code to mint the session.
 *
 * @module multi-factor
 */

import { Config, Context, Crypto, Data, Effect, Layer, Redacted } from "effect";
import * as Cipher from "../Cipher.ts";
import type { TokenCipher } from "../Cipher.ts";
import * as Errors from "../Errors.ts";
import * as Obs from "../Observability.ts";
import { EmailPasswordStore, SecondFactorGate } from "../email/EmailPassword.ts";
import { type HookError } from "../Hooks.ts";
import { generateBase32Secret, generateOtpUri, verifyTotp, type TotpConfig } from "./Otp.ts";
import { PasswordHasher } from "../password/Password.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { hashToken, timingSafeEqualBytes } from "../TokenHash.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";
import { anyEmailValue, IdentifierStore } from "../Identifier.ts";
import { SessionService } from "../SessionService.ts";

/**
 * Two-factor error
 */
export class MultiFactorError extends Data.TaggedError("MultiFactorError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Persistent multi-factor state for a user.
 *
 * `backupCodes` holds sha256 hex digests of the (normalized) plaintext
 * codes — the plaintext is only ever returned once, at generation time.
 * `verified` stays `false` until the user confirms enrollment with a valid
 * TOTP code (unless `skipVerificationOnEnable` is set).
 */
export interface MultiFactorRecord {
  readonly userId: string;
  /** Base32-encoded TOTP secret */
  readonly secret: string;
  /** sha256 hex hashes of the remaining (unused) backup codes */
  readonly backupCodes: readonly string[];
  /** False until the first successful TOTP confirmation */
  readonly verified: boolean;
  readonly createdAt: number;
  /**
   * The TOTP time-step counter of the last accepted code. Any code whose
   * matched counter is ≤ this value is a replay and must be rejected.
   * Stores must persist this field; absent means no code has been accepted yet.
   */
  readonly lastUsedCounter?: number;
}

/**
 * Storage interface for multi-factor records
 */
export class MultiFactorStore extends Context.Service<
  MultiFactorStore,
  {
    readonly get: (userId: string) => Effect.Effect<MultiFactorRecord | null, Errors.AuthError>;
    readonly upsert: (
      record: MultiFactorRecord,
    ) => Effect.Effect<MultiFactorRecord, Errors.AuthError>;
    readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/MultiFactorStore") {}

/**
 * Short-lived "password OK, awaiting second factor" state created by
 * `beginChallenge` and redeemed (one-time) by `verifyTotp`/`verifyBackupCode`.
 */
export interface PendingMultiFactor {
  readonly token: string;
  readonly userId: string;
  readonly expiresAt: number;
  readonly createdAt: number;
}

/**
 * Storage interface for pending multi-factor challenges
 */
export class PendingMultiFactorStore extends Context.Service<
  PendingMultiFactorStore,
  {
    readonly create: (
      pending: PendingMultiFactor,
    ) => Effect.Effect<PendingMultiFactor, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<PendingMultiFactor | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/PendingMultiFactorStore") {}

/**
 * Two-factor service configuration
 */
export interface MultiFactorConfig {
  /** Issuer name embedded in the otpauth:// URI (e.g. your app name) */
  readonly issuer: string;
  /** TOTP parameters (period/digits/algorithm/window). Default: RFC 6238 defaults */
  readonly totp?: TotpConfig;
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
   * {@link MultiFactorStore}. The store sees only ciphertext; plaintext is only
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
 * Result of enabling multi-factor: the secret and backup codes are returned
 * in plaintext exactly once — show them to the user, then discard.
 */
export interface MultiFactorEnableResult {
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
export interface MultiFactorChallenge {
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * Result of redeeming a pending challenge with a valid second factor.
 */
export interface MultiFactorVerifyResult {
  readonly userId: string;
  readonly session: Types.Session;
}

export interface MultiFactorVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Two-factor authentication service
 */
export class MultiFactorService extends Context.Service<
  MultiFactorService,
  {
    /**
     * Enable multi-factor for a user. Verifies the user's password, generates a
     * TOTP secret plus backup codes, and stores the record (unverified unless
     * `skipVerificationOnEnable`). Returns the plaintext secret, otpauth:// URI
     * (labelled with the user's email) and plaintext backup codes — shown once.
     */
    readonly enable: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      MultiFactorEnableResult,
      | MultiFactorError
      | Errors.InvalidCredentialsError
      | Errors.HashingError
      | Errors.AuthError
      | Errors.UserNotFoundError
    >;

    /**
     * Confirm enrollment with a TOTP code generated from the stored secret.
     * Marks the record verified; multi-factor is only enforced once verified.
     */
    readonly confirmEnable: (
      userId: string,
      code: string,
    ) => Effect.Effect<void, MultiFactorError | Errors.HashingError | Errors.AuthError>;

    /**
     * Disable multi-factor after re-verifying the user's password.
     */
    readonly disable: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      void,
      Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError
    >;

    /**
     * Whether the user has a verified multi-factor record.
     */
    readonly isEnabled: (userId: string) => Effect.Effect<boolean, Errors.AuthError>;

    /**
     * Start a second-factor challenge for a user whose first factor (e.g.
     * password) already checked out. Returns a one-time pending token to be
     * redeemed with `verifyTotp` or `verifyBackupCode`.
     */
    readonly beginChallenge: (
      userId: string,
    ) => Effect.Effect<MultiFactorChallenge, MultiFactorError | Errors.AuthError>;

    /**
     * Redeem a pending challenge with a TOTP code. On success the pending
     * token is consumed (one-time use) and a session is created.
     */
    readonly verifyTotp: (
      pendingToken: string,
      code: string,
      options?: MultiFactorVerifyOptions,
    ) => Effect.Effect<
      MultiFactorVerifyResult,
      MultiFactorError | Errors.HashingError | Errors.AuthError | HookError
    >;

    /**
     * Redeem a pending challenge with a backup code. The matched code is
     * removed from the record (single use) and a session is created.
     */
    readonly verifyBackupCode: (
      pendingToken: string,
      code: string,
      options?: MultiFactorVerifyOptions,
    ) => Effect.Effect<MultiFactorVerifyResult, MultiFactorError | Errors.AuthError | HookError>;

    /**
     * Replace all backup codes after re-verifying the user's password.
     * Returns the new plaintext codes (shown once); old codes are invalidated.
     */
    readonly regenerateBackupCodes: (
      userId: string,
      password: string,
    ) => Effect.Effect<
      readonly string[],
      MultiFactorError | Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError
    >;
  }
>()("@effect-auth/MultiFactorService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: MultiFactorConfig) =>
    Layer.effect(MultiFactorService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));

  /**
   * Construct a Layer from environment variables via {@link multiFactorConfig}.
   *
   * Required env vars: `TWO_FACTOR_ISSUER`.
   * Optional: `TWO_FACTOR_ENCRYPT_SECRET`.
   */
  static readonly layerFromEnv = Layer.effect(
    MultiFactorService,
    Effect.gen(function* () {
      const cfg = yield* multiFactorConfig;
      return yield* make({
        issuer: cfg.issuer,
        ...(cfg.encryptSecret !== undefined && { encryptSecret: cfg.encryptSecret }),
      });
    }),
  ).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Effect `Config` for {@link MultiFactorConfig}.
 *
 * Required env vars: `TWO_FACTOR_ISSUER`.
 * Optional: `TWO_FACTOR_ENCRYPT_SECRET`.
 */
export const multiFactorConfig = Config.all({
  issuer: Config.string("TWO_FACTOR_ISSUER"),
  encryptSecret: Config.redacted("TWO_FACTOR_ENCRYPT_SECRET").pipe(
    Config.map((secret) => ({ secret }) as const),
    Config.orElse(() => Config.succeed(undefined)),
  ),
});

/**
 * Normalize a backup code for hashing/comparison (strip separators and
 * whitespace, lowercase) so `xxxxx-xxxxx` and `xxxxxxxxxx` both match.
 */
const normalizeBackupCode = (code: string): string => code.replace(/[\s-]/g, "").toLowerCase();

/**
 * sha256 hex digest of a normalized backup code
 */
export const hashBackupCode = (code: string): string => hashToken(normalizeBackupCode(code));

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
      timingSafeEqualBytes(stored, candidate) &&
      match === -1
    ) {
      match = i;
    }
  }
  return match;
};

/**
 * Create a multi-factor service
 */
export const make = (
  config: MultiFactorConfig,
): Effect.Effect<
  typeof MultiFactorService.Service,
  never,
  | MultiFactorStore
  | PendingMultiFactorStore
  | EmailPasswordStore
  | IdentifierStore
  | PasswordHasher
  | UserStore
  | SessionService
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const backupCodeCount = config.backupCodeCount ?? 10;
    const pendingExpiresIn = config.pendingExpiresIn ?? 5 * 60 * 1000; // 5 minutes default
    const skipVerificationOnEnable = config.skipVerificationOnEnable ?? false;

    const cipher: TokenCipher | null = config.encryptSecret
      ? "cipher" in config.encryptSecret
        ? config.encryptSecret.cipher
        : Cipher.aes256GcmCipher(Redacted.value(config.encryptSecret.secret))
      : null;

    const store = yield* MultiFactorStore;
    const pendingStore = yield* PendingMultiFactorStore;
    const emailPasswordStore = yield* EmailPasswordStore;
    const passwordHasher = yield* PasswordHasher;
    const userStore = yield* UserStore;
    const identifierStore = yield* IdentifierStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    /**
     * Generate a cryptographically secure pending-challenge token
     */
    const generatePendingToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate pending token", cause }),
        ),
      );

    /**
     * Generate a single plaintext backup code: 10 crypto-random hex characters
     * formatted as `xxxxx-xxxxx`.
     */
    const generateBackupCode = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(5).pipe(
        Effect.map((bytes) => {
          const raw = Buffer.from(bytes).toString("hex");
          return `${raw.slice(0, 5)}-${raw.slice(5)}`;
        }),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate backup code", cause }),
        ),
      );

    /**
     * Verify the user's password against the hash held by the email/password
     * store. Fails with InvalidCredentialsError on mismatch or missing hash.
     */
    const verifyPassword = (userId: string, password: string) =>
      Effect.gen(function* () {
        const passwordHash = yield* emailPasswordStore.getPasswordHash(userId);
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
        const pending = yield* pendingStore.get(pendingToken);
        if (!pending) {
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Invalid or expired multi-factor challenge token",
            }),
          );
        }

        if (Date.now() > pending.expiresAt) {
          yield* pendingStore.delete(pendingToken);
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Two-factor challenge token has expired",
            }),
          );
        }

        return pending;
      });

    /**
     * Load the verified multi-factor record for a user, failing if multi-factor
     * is not (fully) enabled.
     */
    const getVerifiedRecord = (userId: string) =>
      Effect.gen(function* () {
        const record = yield* store.get(userId);
        if (!record || !record.verified) {
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Two-factor authentication is not enabled for this user",
            }),
          );
        }
        return record;
      });

    return {
      enable: Effect.fn("MultiFactorService.enable")(function* (userId: string, password: string) {
        yield* verifyPassword(userId, password);

        // The otpauth:// label is the user's email
        const user = yield* userStore.get(userId);
        if (user === null) {
          return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
        }

        const secret = yield* generateBase32Secret(crypto);
        const storedSecret = cipher !== null ? yield* cipher.encrypt(secret) : secret;

        const backupCodes = yield* Effect.all(
          Array.from({ length: backupCodeCount }, () => generateBackupCode()),
        );

        const record: MultiFactorRecord = {
          userId,
          secret: storedSecret,
          backupCodes: backupCodes.map((code) => hashBackupCode(code)),
          verified: skipVerificationOnEnable,
          createdAt: Date.now(),
        };

        yield* store.upsert(record);

        const totp = config.totp;
        // otpauth URI label: prefer the user's email identifier for a
        // recognizable authenticator entry; fall back to name, then id.
        const label =
          anyEmailValue(yield* identifierStore.listByUser(user.id)) ?? user.name ?? user.id;
        const totpUri = yield* Effect.try({
          try: () =>
            generateOtpUri({
              type: "totp",
              label,
              issuer: config.issuer,
              secret, // always use plaintext for URI generation
              ...(totp?.period !== undefined && { period: totp.period }),
              ...(totp?.digits !== undefined && { digits: totp.digits }),
              ...(totp?.algorithm !== undefined && { algorithm: totp.algorithm }),
            }),
          catch: (error) =>
            new MultiFactorError({
              message: "Failed to generate otpauth URI",
              cause: error,
            }),
        });

        return {
          secret, // always return plaintext secret
          totpUri,
          backupCodes,
        } satisfies MultiFactorEnableResult;
      }),

      confirmEnable: Effect.fn("MultiFactorService.confirmEnable")(function* (
        userId: string,
        code: string,
      ) {
        const record = yield* store.get(userId);
        if (!record) {
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Two-factor authentication has not been set up for this user",
            }),
          );
        }

        const plainSecret = cipher !== null ? yield* cipher.decrypt(record.secret) : record.secret;
        const matchedCounter = yield* verifyTotp(code, plainSecret, config.totp);
        if (matchedCounter === null) {
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Invalid multi-factor code",
            }),
          );
        }

        yield* store.upsert({ ...record, verified: true, lastUsedCounter: matchedCounter });
      }),

      disable: Effect.fn("MultiFactorService.disable")(function* (
        userId: string,
        password: string,
      ) {
        yield* verifyPassword(userId, password);
        yield* store.delete(userId);
      }),

      isEnabled: Effect.fn("MultiFactorService.isEnabled")(function* (userId: string) {
        const record = yield* store.get(userId);
        return record !== null && record.verified;
      }),

      beginChallenge: Effect.fn("MultiFactorService.beginChallenge")((userId: string) =>
        Effect.gen(function* () {
          // Only users with a verified record can be challenged
          yield* getVerifiedRecord(userId);

          const token = yield* generatePendingToken();

          const pending: PendingMultiFactor = {
            token,
            userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + pendingExpiresIn,
          };

          yield* pendingStore.create(pending);

          return {
            token,
            expiresAt: pending.expiresAt,
          } satisfies MultiFactorChallenge;
        }).pipe(
          Effect.withSpan("effect-auth.2fa.challenge"),
          Effect.tap(() => Obs.recordMultiFactorChallenge()),
        ),
      ),

      verifyTotp: Effect.fn("MultiFactorService.verifyTotp")(
        (pendingToken: string, code: string, options?: MultiFactorVerifyOptions) =>
          Effect.gen(function* () {
            const pending = yield* resolvePending(pendingToken);
            const record = yield* getVerifiedRecord(pending.userId);

            const plainSecret =
              cipher !== null ? yield* cipher.decrypt(record.secret) : record.secret;
            const matchedCounter = yield* verifyTotp(code, plainSecret, config.totp);
            if (matchedCounter === null) {
              return yield* Effect.fail(
                new MultiFactorError({
                  message: "Invalid multi-factor code",
                }),
              );
            }

            // Reject replays: a code whose matched counter has already been used.
            if (record.lastUsedCounter !== undefined && matchedCounter <= record.lastUsedCounter) {
              return yield* Effect.fail(
                new MultiFactorError({
                  message: "Multi-factor code has already been used",
                }),
              );
            }

            // Persist the counter before creating the session so concurrent
            // submissions of the same code are rejected even if the session
            // write has not completed yet.
            yield* store.upsert({ ...record, lastUsedCounter: matchedCounter });

            // Consume the pending token (one-time use)
            yield* pendingStore.delete(pendingToken);

            const session = yield* sessionManager.createSession(
              pending.userId,
              options?.sessionAttributes,
            );

            return {
              userId: pending.userId,
              session,
            } satisfies MultiFactorVerifyResult;
          }).pipe(
            Effect.withSpan("effect-auth.2fa.verify", { attributes: { type: "totp" } }),
            Effect.tap(() => Obs.recordMultiFactorVerification("totp", "success")),
            Effect.tapError(() => Obs.recordMultiFactorVerification("totp", "failure")),
          ),
      ),

      verifyBackupCode: Effect.fn("MultiFactorService.verifyBackupCode")(
        (pendingToken: string, code: string, options?: MultiFactorVerifyOptions) =>
          Effect.gen(function* () {
            const pending = yield* resolvePending(pendingToken);
            const record = yield* getVerifiedRecord(pending.userId);

            const index = findBackupCodeIndex(record.backupCodes, hashBackupCode(code));
            if (index === -1) {
              return yield* Effect.fail(
                new MultiFactorError({
                  message: "Invalid backup code",
                }),
              );
            }

            // Remove the used code (single use)
            yield* store.upsert({
              ...record,
              backupCodes: record.backupCodes.filter((_, i) => i !== index),
            });

            // Consume the pending token (one-time use)
            yield* pendingStore.delete(pendingToken);

            const session = yield* sessionManager.createSession(
              pending.userId,
              options?.sessionAttributes,
            );

            return {
              userId: pending.userId,
              session,
            } satisfies MultiFactorVerifyResult;
          }).pipe(
            Effect.withSpan("effect-auth.2fa.verify", { attributes: { type: "backup-code" } }),
            Effect.tap(() => Obs.recordMultiFactorVerification("backup-code", "success")),
            Effect.tapError(() => Obs.recordMultiFactorVerification("backup-code", "failure")),
          ),
      ),

      regenerateBackupCodes: Effect.fn("MultiFactorService.regenerateBackupCodes")(function* (
        userId: string,
        password: string,
      ) {
        yield* verifyPassword(userId, password);

        const record = yield* store.get(userId);
        if (!record) {
          return yield* Effect.fail(
            new MultiFactorError({
              message: "Two-factor authentication is not enabled for this user",
            }),
          );
        }

        const backupCodes = yield* Effect.all(
          Array.from({ length: backupCodeCount }, () => generateBackupCode()),
        );

        yield* store.upsert({
          ...record,
          backupCodes: backupCodes.map(hashBackupCode),
        });

        return backupCodes;
      }),
    };
  });

/**
 * Provides the {@link SecondFactorGate} seam so password sign-in returns a
 * multi-factor challenge (instead of a session) for enrolled users.
 *
 * The gate's methods are self-contained (`R = never`): `MultiFactorService`
 * already resolved its own stores at Layer-construction time, so this Layer
 * only requires `MultiFactorService` itself:
 *
 * ```ts
 * const services = Layer.mergeAll(
 *   EmailPasswordService.layer(),
 *   MultiFactorGateLayer.pipe(
 *     Layer.provide(MultiFactorService.layer({ issuer: "MyApp" }).pipe(Layer.provide(multiFactorStores))),
 *   ),
 * )
 * ```
 */
export const MultiFactorGateLayer: Layer.Layer<SecondFactorGate, never, MultiFactorService> =
  Layer.effect(
    SecondFactorGate,
    Effect.gen(function* () {
      const multiFactor = yield* MultiFactorService;

      const gate: typeof SecondFactorGate.Service = {
        required: (user) => multiFactor.isEnabled(user.id),
        begin: (user) =>
          multiFactor
            .beginChallenge(user.id)
            .pipe(
              Effect.catchTag("MultiFactorError", (error) =>
                Effect.fail(new Errors.AuthError({ message: error.message })),
              ),
            ),
      };
      return gate;
    }),
  );
