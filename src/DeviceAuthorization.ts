/**
 * Device Authorization Grant (RFC 8628) for input-constrained devices (CLIs,
 * TVs). The device requests a `device_code` + short human-typable `user_code`,
 * shows the user a verification URL, and polls the token endpoint while the
 * user approves the code on a second device.
 *
 * House module pattern: store tag + `Context.Service` tag + `make*` +
 * `*ServiceLayer`, module-local `Data.TaggedError`s, epoch-ms timestamps.
 */
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import { SessionService } from "./session/SessionService.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { hashToken } from "./TokenHash.ts";

/** Lifecycle status of a device authorization request. */
export type DeviceAuthorizationStatus = "pending" | "approved" | "denied";

/** A stored device authorization request. Timestamps are epoch-ms. */
export interface DeviceAuthorizationRecord {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly clientId?: string;
  readonly scopes?: readonly string[];
  readonly status: DeviceAuthorizationStatus;
  readonly userId?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly lastPolledAt: number;
  readonly interval: number;
}

/** Persistence for device authorization requests. */
export class DeviceAuthorizationStore extends Context.Service<
  DeviceAuthorizationStore,
  {
    readonly create: (
      record: DeviceAuthorizationRecord,
    ) => Effect.Effect<DeviceAuthorizationRecord, Errors.AuthError>;
    readonly getByDeviceCode: (
      deviceCode: string,
    ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
    readonly getByUserCode: (
      userCode: string,
    ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
    readonly update: (
      record: DeviceAuthorizationRecord,
    ) => Effect.Effect<DeviceAuthorizationRecord, Errors.AuthError>;
    readonly delete: (deviceCode: string) => Effect.Effect<void, Errors.AuthError>;
    /**
     * Atomically consume an approved record: if the record exists and its status
     * is `"approved"`, delete it and return it; otherwise return `null`.
     * Implementations must make the read-then-delete atomic (e.g. a conditional
     * delete or compare-and-swap) so that two concurrent polls on the same
     * approved code each see at most one win.
     */
    readonly claimApproval: (
      deviceCode: string,
    ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
  }
>()("@effect-auth/DeviceAuthorizationStore") {}

/** RFC 8628 polling errors, mapped to the standard OAuth `error` codes. */
export class DevicePollError extends Data.TaggedError("DevicePollError")<{
  readonly error: "authorization_pending" | "slow_down" | "expired_token" | "access_denied";
  readonly message: string;
}> {}

/** Raised when a user code is unknown or has expired at approve/deny time. */
export class DeviceCodeError extends Data.TaggedError("DeviceCodeError")<{
  readonly message: string;
}> {}

export interface DeviceAuthorizationConfig {
  /** URL where the user enters their code. Shown to the device. */
  readonly verificationUri: string;
  /** Request lifetime in ms. Default 30 minutes. */
  readonly expiresIn?: number;
  /** Minimum polling interval in seconds. Default 5. */
  readonly interval?: number;
  /** Number of user-code characters (grouped in two halves). Default 8. */
  readonly userCodeLength?: number;
  /** Alphabet for the user code (ambiguous characters excluded by default). */
  readonly userCodeAlphabet?: string;
}

export interface DeviceBeginResult {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresIn: number;
  readonly interval: number;
}

export interface DevicePollResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

export class DeviceAuthorizationService extends Context.Service<
  DeviceAuthorizationService,
  {
    /** Start a device authorization request. */
    readonly begin: (options?: {
      readonly clientId?: string;
      readonly scopes?: readonly string[];
    }) => Effect.Effect<DeviceBeginResult, Errors.AuthError, DeviceAuthorizationStore>;

    /**
     * Poll for completion. Returns a session once approved; otherwise fails with
     * the RFC 8628 error (`authorization_pending`, `slow_down`, `expired_token`,
     * `access_denied`).
     */
    readonly poll: (
      deviceCode: string,
    ) => Effect.Effect<
      DevicePollResult,
      | DevicePollError
      | Errors.AuthError
      | Errors.SessionNotFoundError
      | Errors.SessionExpiredError
      | Errors.UserNotFoundError
      | HookError,
      DeviceAuthorizationStore | SessionService | Hooks
    >;

    /** Approve a user code (called from an authenticated verification page). */
    readonly approve: (
      userCode: string,
      userId: string,
    ) => Effect.Effect<void, DeviceCodeError | Errors.AuthError, DeviceAuthorizationStore>;

    /** Deny a user code. */
    readonly deny: (
      userCode: string,
    ) => Effect.Effect<void, DeviceCodeError | Errors.AuthError, DeviceAuthorizationStore>;
  }
>()("@effect-auth/DeviceAuthorizationService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: DeviceAuthorizationConfig) =>
    Layer.effect(DeviceAuthorizationService, makeDeviceAuthorizationService(config));
}

const DEFAULT_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ0123456789";

const randomCode = (length: number, alphabet: string): string => {
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out;
};

/** Format a raw code as two dash-separated halves, e.g. `BDWM-HQPK`. */
const formatUserCode = (raw: string): string => {
  const half = Math.ceil(raw.length / 2);
  return `${raw.slice(0, half)}-${raw.slice(half)}`;
};

/** Normalize a user code for lookup (uppercase, strip non-alphanumerics). */
export const normalizeUserCode = (code: string): string =>
  code.toUpperCase().replace(/[^A-Z0-9]/g, "");

export const makeDeviceAuthorizationService = (
  config: DeviceAuthorizationConfig,
): Effect.Effect<typeof DeviceAuthorizationService.Service, never> =>
  Effect.sync((): typeof DeviceAuthorizationService.Service => {
    const expiresIn = config.expiresIn ?? 30 * 60 * 1000;
    const interval = config.interval ?? 5;
    const userCodeLength = config.userCodeLength ?? 8;
    const alphabet = config.userCodeAlphabet ?? DEFAULT_ALPHABET;

    return {
      begin: (options) =>
        Effect.gen(function* () {
          const store = yield* DeviceAuthorizationStore;
          const rawDeviceCode = crypto.randomBytes(32).toString("base64url");
          const rawUserCode = randomCode(userCodeLength, alphabet);
          const userCode = formatUserCode(rawUserCode);
          const normalizedUserCode = normalizeUserCode(userCode);
          const now = Date.now();

          yield* store.create({
            // Both codes are stored as SHA-256 hashes; the raw values are
            // returned to the caller and never persisted.
            deviceCode: hashToken(rawDeviceCode),
            userCode: hashToken(normalizedUserCode),
            ...(options?.clientId !== undefined && { clientId: options.clientId }),
            ...(options?.scopes !== undefined && { scopes: options.scopes }),
            status: "pending",
            createdAt: now,
            expiresAt: now + expiresIn,
            lastPolledAt: 0,
            interval,
          });

          return {
            deviceCode: rawDeviceCode,
            userCode,
            verificationUri: config.verificationUri,
            expiresIn: Math.floor(expiresIn / 1000),
            interval,
          };
        }),

      poll: (deviceCode) =>
        Effect.gen(function* () {
          const store = yield* DeviceAuthorizationStore;
          const sessionManager = yield* SessionService;

          const record = yield* store.getByDeviceCode(hashToken(deviceCode));
          const now = Date.now();

          // record.deviceCode is already the stored hash.
          if (record === null || now > record.expiresAt) {
            if (record !== null) yield* store.delete(record.deviceCode);
            return yield* new DevicePollError({
              error: "expired_token",
              message: "The device code has expired",
            });
          }

          // Enforce the minimum polling interval (RFC 8628 slow_down).
          // Don't update lastPolledAt on rejection: a slightly-too-fast client
          // would otherwise continually reset its own window and never progress.
          // Instead, escalate the stored interval by 5 s per RFC 8628 §3.5 so
          // subsequent valid polls are gated by the new minimum.
          if (record.lastPolledAt !== 0 && now - record.lastPolledAt < record.interval * 1000) {
            yield* store.update({ ...record, interval: record.interval + 5 });
            return yield* new DevicePollError({
              error: "slow_down",
              message: "Polling too frequently",
            });
          }
          yield* store.update({ ...record, lastPolledAt: now });

          if (record.status === "denied") {
            yield* store.delete(record.deviceCode);
            return yield* new DevicePollError({
              error: "access_denied",
              message: "The user denied the request",
            });
          }

          if (record.status === "pending" || record.userId === undefined) {
            return yield* new DevicePollError({
              error: "authorization_pending",
              message: "The user has not yet approved the request",
            });
          }

          // Atomically consume the approved record before minting a session.
          // claimApproval does a conditional delete so that only one concurrent
          // poll wins; a second poll racing the same approval sees null here and
          // gets expired_token instead of minting a duplicate session.
          const claimed = yield* store.claimApproval(record.deviceCode);
          if (claimed === null || claimed.userId === undefined) {
            return yield* new DevicePollError({
              error: "expired_token",
              message: "The device code has already been consumed",
            });
          }

          // User is resolved through the session manager so this flow needs no
          // direct user-store dependency (it isn't part of `AuthServices`).
          const session = yield* sessionManager.createSession(claimed.userId);
          const { user } = yield* sessionManager.validateSession(session.id);

          return { user, session };
        }),

      approve: (userCode, userId) =>
        Effect.gen(function* () {
          const store = yield* DeviceAuthorizationStore;
          const record = yield* store.getByUserCode(hashToken(normalizeUserCode(userCode)));
          if (record === null || Date.now() > record.expiresAt) {
            return yield* new DeviceCodeError({ message: "Invalid or expired code" });
          }
          yield* store.update({ ...record, status: "approved", userId });
        }),

      deny: (userCode) =>
        Effect.gen(function* () {
          const store = yield* DeviceAuthorizationStore;
          const record = yield* store.getByUserCode(hashToken(normalizeUserCode(userCode)));
          if (record === null || Date.now() > record.expiresAt) {
            return yield* new DeviceCodeError({ message: "Invalid or expired code" });
          }
          yield* store.update({ ...record, status: "denied" });
        }),
    };
  });
