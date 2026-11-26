/**
 * Device Authorization Grant (RFC 8628) for input-constrained devices (CLIs,
 * TVs). A registered client requests a `device_code` + short human-typable
 * `user_code`, shows the user a verification URL, and polls the token endpoint
 * while the user reviews the client and scopes and approves the code on a
 * second device. The session it receives records the client and scopes.
 */
import { Clock, Context, Data, Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { Digest, SecureRandom } from "effect/crypto";
import * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type * as Types from "./Types.ts";
import { CREDENTIAL_CLASS_ATTRIBUTE, DEVICE_GRANT_ATTRIBUTE } from "./Types.ts";
import { SessionService } from "./SessionService.ts";
import type { HookError } from "./Hooks.ts";
import { tokenHasher } from "./TokenHash.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";

/** Lifecycle status of a device authorization request. */
export type DeviceAuthorizationStatus = "pending" | "approved" | "denied";

/** A stored device authorization request. Timestamps are epoch-ms. */
export interface DeviceAuthorizationRecord {
  readonly deviceCode: string;
  readonly userCode: string;
  /** The registered client that began the request. */
  readonly clientId: string;
  /** The scopes it asked for, each one the client is registered for. */
  readonly scopes: readonly string[];
  readonly status: DeviceAuthorizationStatus;
  /** The user who approved or denied the request. */
  readonly userId?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly lastPolledAt: number;
  readonly interval: number;
}

/** The user's decision on a pending request, as {@link DeviceAuthorizationStore.settle} records it. */
export interface DeviceDecision {
  readonly status: "approved" | "denied";
  readonly userId: string;
}

/**
 * The one field a poll writes: the time of an accepted poll, or the
 * escalated interval after a `slow_down`.
 */
export type DevicePollTouch = { readonly lastPolledAt: number } | { readonly interval: number };

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
    /**
     * Atomically record a decision: if the record the user-code digest names
     * is `"pending"` and `expiresAt >= now`, set its `status` and `userId` and
     * return the updated record; otherwise return `null` and change nothing.
     * One conditional write (`UPDATE … WHERE status = 'pending' AND expires_at
     * >= ? RETURNING`), so a decision is never overwritten: of two concurrent
     * decisions only one lands, and a denial can never become an approval.
     */
    readonly settle: (
      userCode: string,
      decision: DeviceDecision,
      now: number,
    ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
    /**
     * Write only the given poll field of an existing record and return the
     * record as it now stands (its current `status` included), or `null` when
     * it is gone. Never writes `status` or `userId`, so a poll racing a
     * decision cannot undo it.
     */
    readonly touch: (
      deviceCode: string,
      touch: DevicePollTouch,
    ) => Effect.Effect<DeviceAuthorizationRecord | null, Errors.AuthError>;
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

/** Raised when a user code is unknown, expired or already decided at lookup, approve or deny time. */
export class DeviceCodeError extends Data.TaggedError("DeviceCodeError")<{
  readonly message: string;
}> {}

/**
 * Raised when a device authorization request names a client that is not
 * registered (`invalid_client`) or a scope the client is not registered for
 * (`invalid_scope`), the OAuth error codes RFC 8628 §3.2 answers with.
 */
export class DeviceClientError extends Data.TaggedError("DeviceClientError")<{
  readonly error: "invalid_client" | "invalid_scope";
  readonly message: string;
}> {}

/** A client allowed to start the device grant. */
export interface DeviceClient {
  /** The `clientId` the device sends. */
  readonly id: string;
  /** The name the verification page shows the user. */
  readonly name: string;
  /** The scopes it may ask for. Default none. */
  readonly scopes?: readonly string[] | undefined;
}

/** Configuration for {@link DeviceAuthorizationService}. */
export interface DeviceAuthorizationConfig {
  /** URL where the user enters their code. Shown to the device. */
  readonly verificationUri: string;
  /**
   * The clients that may start a request. A request naming any other client
   * is refused with `invalid_client`, and one asking for a scope its client is
   * not registered for with `invalid_scope`. A request begun by a client that
   * is later removed can no longer be looked up, approved or redeemed.
   */
  readonly clients: ReadonlyArray<DeviceClient>;
  /** Request lifetime in ms. Default 30 minutes. */
  readonly expiresIn?: number;
  /** Minimum polling interval in seconds. Default 5. */
  readonly interval?: number;
  /** Number of user-code characters (grouped in two halves). Default 8. */
  readonly userCodeLength?: number;
  /** Alphabet for the user code (ambiguous characters excluded by default). */
  readonly userCodeAlphabet?: string;
  /**
   * Accept that the user-code limit may be off. Default `false`.
   *
   * The HTTP layer limits lookups and decisions to 10 per signed-in caller per
   * 15 minutes (RFC 8628 §5.2) through the `RateLimiter` in `services`, beside
   * the per-address endpoint limit. The limit counts as configured whenever
   * this service is in `services`, so without a `RateLimiter`, `Http.make`
   * throws `RateLimiterConfigError`, and the lookup and decision endpoints
   * served outside `Http.make` refuse every request with `429`.
   *
   * With `true`, they run without the limit when no `RateLimiter` is in
   * `services`. A `RateLimiter` in `services` still applies the limit. Prefer
   * adding a `RateLimiter`: without the limit, a signed-in caller can try user
   * codes as fast as the address limit allows.
   */
  readonly allowMissingRateLimiter?: boolean | undefined;
}

/** What {@link DeviceAuthorizationService.begin} takes: the registered client and the scopes it asks for. */
export interface DeviceBeginInput {
  readonly clientId: string;
  readonly scopes?: readonly string[] | undefined;
}

/**
 * What a device shows and polls with after {@link DeviceAuthorizationService.begin}. `expiresIn` and `interval` are in seconds.
 */
export interface DeviceBeginResult {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresIn: number;
  readonly interval: number;
}

/**
 * A request as the verification page shows it: which client asks, for which
 * scopes, and its status. `id` is the stored device-code digest, never the
 * device code; `expiresAt` is epoch-ms.
 */
export interface DeviceAuthorizationRequest {
  readonly id: string;
  readonly clientId: string;
  readonly clientName: string;
  readonly scopes: readonly string[];
  readonly status: DeviceAuthorizationStatus;
  readonly expiresAt: number;
}

/** The user and session a device receives once its request is approved. */
export interface DevicePollResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  /** The raw session token, the credential the client presents; `session.id` is its digest. */
  readonly token: string;
  /** The client and scopes the session was granted to, as recorded on it. */
  readonly grant: DeviceGrant;
}

/** The client and scopes a device session was granted to. */
export interface DeviceGrant {
  readonly clientId: string;
  readonly scopes: readonly string[];
}

const decodeDeviceGrant = Schema.decodeUnknownOption(
  Schema.Struct({ clientId: Schema.String, scopes: Schema.Array(Schema.String) }),
);

/**
 * The device grant a session was issued under, or `None` for a session issued
 * any other way. An app restricts what a device session may do by reading it.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import * as Option from "effect/Option"
 * import { deviceGrantOf } from "@thomasfosterau/effect-auth"
 *
 * const session = {
 *   id: "digest",
 *   userId: "u-1",
 *   expiresAt: new Date(),
 *   createdAt: new Date(),
 *   lastActivityAt: new Date(),
 *   attributes: { deviceGrant: { clientId: "cli", scopes: ["read"] } },
 * }
 * assert.deepEqual(deviceGrantOf(session), Option.some({ clientId: "cli", scopes: ["read"] }))
 * assert.equal(Option.isNone(deviceGrantOf({ ...session, attributes: {} })), true)
 * ```
 */
export const deviceGrantOf = (session: Types.Session): Option.Option<DeviceGrant> =>
  decodeDeviceGrant(session.attributes[DEVICE_GRANT_ATTRIBUTE]);

/**
 * The RFC 8628 device authorization grant: a registered client begins a
 * request, the signed-in user looks up its code to see the client and scopes
 * and approves or denies it, and the device polls for a session that records
 * the client and scopes.
 *
 * Requires `DeviceAuthorizationStore` and `SessionService`.
 */
export class DeviceAuthorizationService extends Context.Service<
  DeviceAuthorizationService,
  {
    /** Start a device authorization request for a registered client. */
    readonly begin: (
      input: DeviceBeginInput,
    ) => Effect.Effect<DeviceBeginResult, DeviceClientError | Errors.AuthError>;

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
      | HookError
    >;

    /**
     * The pending request a user code names, with its client and scopes, for
     * the verification page to show before the user decides.
     */
    readonly lookup: (
      userCode: string,
    ) => Effect.Effect<DeviceAuthorizationRequest, DeviceCodeError | Errors.AuthError>;

    /** Approve a pending user code as `userId` (called from an authenticated verification page). */
    readonly approve: (
      userCode: string,
      userId: string,
    ) => Effect.Effect<DeviceAuthorizationRequest, DeviceCodeError | Errors.AuthError>;

    /** Deny a pending user code as `userId` (called from an authenticated verification page). */
    readonly deny: (
      userCode: string,
      userId: string,
    ) => Effect.Effect<DeviceAuthorizationRequest, DeviceCodeError | Errors.AuthError>;

    /**
     * `true` when the service was built with
     * {@link DeviceAuthorizationConfig.allowMissingRateLimiter}. The HTTP layer
     * reads it to decide whether lookups and decisions may run without a
     * `RateLimiter`. Absent means `false`.
     */
    readonly allowMissingRateLimiter?: boolean | undefined;
  }
>()("@effect-auth/DeviceAuthorizationService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: DeviceAuthorizationConfig) =>
    Layer.effect(DeviceAuthorizationService, make(config)).pipe(
      Layer.provide(PlatformCrypto.layer),
    );
}

const DEFAULT_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ0123456789";

/** Generate a random code by drawing each character via unbiased rejection sampling. */
const randomCode = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  length: number,
  alphabet: string,
): Effect.Effect<string> =>
  Effect.replicateEffect(
    Effect.map(crypto.intBetween(0, alphabet.length, { halfOpen: true }), (index) =>
      alphabet.charAt(index),
    ),
    length,
    { concurrency: 1 },
  ).pipe(Effect.map((chars) => chars.join("")));

/** Format a raw code as two dash-separated halves, e.g. `BDWM-HQPK`. */
const formatUserCode = (raw: string): string => {
  const half = Math.ceil(raw.length / 2);
  return `${raw.slice(0, half)}-${raw.slice(half)}`;
};

/** Normalize a user code for lookup (uppercase, strip non-alphanumerics). */
export const normalizeUserCode = (code: string): string =>
  code.toUpperCase().replace(/[^A-Z0-9]/g, "");

const invalidCode = () => new DeviceCodeError({ message: "Invalid or expired code" });

const make = (
  config: DeviceAuthorizationConfig,
): Effect.Effect<
  typeof DeviceAuthorizationService.Service,
  never,
  DeviceAuthorizationStore | SessionService | SecureRandom.SecureRandom | Digest.Digest
> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 30 * 60 * 1000;
    const interval = config.interval ?? 5;
    const userCodeLength = config.userCodeLength ?? 8;
    const alphabet = config.userCodeAlphabet ?? DEFAULT_ALPHABET;
    const findClient = (clientId: string): Option.Option<DeviceClient> =>
      Arr.findFirst(config.clients, (client) => client.id === clientId);

    const store = yield* DeviceAuthorizationStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* SecureRandom.SecureRandom;
    const hashToken = yield* tokenHasher;

    const generateDeviceCode = (): Effect.Effect<string> => randomBase64UrlToken(crypto);

    /** The request as the verification page shows it; refused once its client is gone. */
    const described = (
      record: DeviceAuthorizationRecord,
    ): Effect.Effect<DeviceAuthorizationRequest, DeviceCodeError> =>
      Option.match(findClient(record.clientId), {
        onNone: () => Effect.fail(invalidCode()),
        onSome: (client) =>
          Effect.succeed({
            id: record.deviceCode,
            clientId: client.id,
            clientName: client.name,
            scopes: record.scopes,
            status: record.status,
            expiresAt: record.expiresAt,
          }),
      });

    /** Record the user's decision on the pending request a user code names. */
    const decide = (userCode: string, decision: DeviceDecision) =>
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        const settled = yield* store.settle(
          yield* hashToken(normalizeUserCode(userCode)),
          decision,
          now,
        );
        // A request whose client was removed since is refused here, and its
        // poll answers `expired_token` whatever was recorded.
        return yield* settled === null ? Effect.fail(invalidCode()) : described(settled);
      });

    return {
      begin: Effect.fn("DeviceAuthorizationService.begin")(function* (input: DeviceBeginInput) {
        const found = findClient(input.clientId);
        if (Option.isNone(found)) {
          return yield* new DeviceClientError({
            error: "invalid_client",
            message: "Unknown client",
          });
        }
        const client = found.value;
        const scopes = Arr.dedupe(input.scopes ?? []);
        const allowed = client.scopes ?? [];
        if (!scopes.every((scope) => allowed.includes(scope))) {
          return yield* new DeviceClientError({
            error: "invalid_scope",
            message: "The client is not registered for the requested scope",
          });
        }

        const rawDeviceCode = yield* generateDeviceCode();
        const rawUserCode = yield* randomCode(crypto, userCodeLength, alphabet);
        const userCode = formatUserCode(rawUserCode);
        const normalizedUserCode = normalizeUserCode(userCode);
        const now = yield* Clock.currentTimeMillis;

        yield* store.create({
          // Both codes are stored as SHA-256 hashes; the raw values are
          // returned to the caller and never persisted.
          deviceCode: yield* hashToken(rawDeviceCode),
          userCode: yield* hashToken(normalizedUserCode),
          clientId: client.id,
          scopes,
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

      poll: Effect.fn("DeviceAuthorizationService.poll")(function* (deviceCode: string) {
        const digest = yield* hashToken(deviceCode);
        const read = yield* store.getByDeviceCode(digest);
        const now = yield* Clock.currentTimeMillis;

        if (read === null || now > read.expiresAt || Option.isNone(findClient(read.clientId))) {
          if (read !== null) yield* store.delete(read.deviceCode);
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
        if (read.lastPolledAt !== 0 && now - read.lastPolledAt < read.interval * 1000) {
          yield* store.touch(digest, { interval: read.interval + 5 });
          return yield* new DevicePollError({
            error: "slow_down",
            message: "Polling too frequently",
          });
        }
        // The touch writes only `lastPolledAt` and answers the record as it
        // now stands, so the status read below is never older than the poll.
        const record = yield* store.touch(digest, { lastPolledAt: now });
        if (record === null) {
          return yield* new DevicePollError({
            error: "expired_token",
            message: "The device code has expired",
          });
        }

        if (record.status === "denied") {
          yield* store.delete(record.deviceCode);
          return yield* new DevicePollError({
            error: "access_denied",
            message: "The user denied the request",
          });
        }

        if (record.status === "pending") {
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

        const grant: DeviceGrant = { clientId: claimed.clientId, scopes: claimed.scopes };
        // User is resolved through the session manager so this flow needs no
        // direct user-store dependency (it isn't part of `AuthServices`).
        // A device session is machine-class for its whole life: the class is
        // read from the session, never from how a request carries its token.
        const { session, token } = yield* sessionManager.createSession(claimed.userId, {
          [CREDENTIAL_CLASS_ATTRIBUTE]: "machine",
          [DEVICE_GRANT_ATTRIBUTE]: { clientId: grant.clientId, scopes: [...grant.scopes] },
        });
        const { user } = yield* sessionManager.validateSession(token);

        return { user, session, token, grant };
      }),

      lookup: Effect.fn("DeviceAuthorizationService.lookup")(function* (userCode: string) {
        const record = yield* store.getByUserCode(yield* hashToken(normalizeUserCode(userCode)));
        const now = yield* Clock.currentTimeMillis;
        if (record === null || record.status !== "pending" || now > record.expiresAt) {
          return yield* invalidCode();
        }
        return yield* described(record);
      }),

      approve: Effect.fn("DeviceAuthorizationService.approve")((userCode: string, userId: string) =>
        decide(userCode, { status: "approved", userId }),
      ),

      deny: Effect.fn("DeviceAuthorizationService.deny")((userCode: string, userId: string) =>
        decide(userCode, { status: "denied", userId }),
      ),

      allowMissingRateLimiter: config.allowMissingRateLimiter === true,
    };
  });
