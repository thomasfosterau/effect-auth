/**
 * API keys: long-lived keys shown once and verified by their SHA-256 digest,
 * with expiry, enabling, per-resource permissions, use quotas, metadata and an
 * optional per-key rate limit through the {@link RateLimiter}. Only the digest
 * is stored.
 *
 * @module api-key
 */

import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import type * as Duration from "effect/Duration";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import { Base64Url } from "effect/encoding";
import { Digest, SecureRandom } from "effect/crypto";
import * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { RateLimiter, type RateLimitConfig } from "./RateLimit.ts";
import { hashToken, tokenHasher } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { UserStore } from "./UserStore.ts";
import { isInGoodStanding } from "./UserStanding.ts";
import { definedKeys } from "./DefinedKeys.ts";

/**
 * API key error
 */
export class ApiKeyError extends Data.TaggedError("ApiKeyError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Persistent API key record.
 *
 * `keyHash` holds the sha256 hex digest of the full plaintext key (prefix
 * included) — the plaintext itself is NEVER stored. `start` keeps the first
 * six characters of the key's random portion so dashboards can display a
 * recognizable fragment without revealing the secret.
 */
export interface ApiKey {
  readonly id: string;
  /** Human-readable label (e.g. "CI deploy key") */
  readonly name?: string;
  /** Visible key prefix the plaintext key starts with (e.g. "myapp_") */
  readonly prefix?: string;
  /** First 6 characters of the key's secret portion, for display */
  readonly start: string;
  /** sha256 hex digest of the full plaintext key — never the plaintext */
  readonly keyHash: string;
  readonly userId: string;
  readonly enabled: boolean;
  /** Unix ms timestamp after which the key is rejected; undefined = never */
  readonly expiresAt?: number;
  /** Unix ms timestamp of the last successful verification */
  readonly lastUsedAt?: number;
  /** resource → allowed actions; undefined = no permission restrictions */
  readonly permissions?: Record<string, readonly string[]>;
  readonly metadata: Types.JsonObject;
  /** Remaining uses; decremented on each successful verify. undefined = unlimited */
  readonly remaining?: number;
  /**
   * Refill amount applied per elapsed `refillInterval`. When set alongside
   * `refillInterval`, each successful verify lazily tops up `remaining` by
   * `floor((now - lastRefillAt) / refillInterval) * refillAmount`, capped at
   * `refillMax`. Only meaningful when `remaining` is also set.
   */
  readonly refillAmount?: number;
  /** Interval in milliseconds between refill ticks */
  readonly refillInterval?: number;
  /** Maximum value `remaining` can be refilled to; defaults to initial `remaining` at creation */
  readonly refillMax?: number;
  /** Unix ms timestamp of the last refill tick baseline */
  readonly lastRefillAt?: number;
  /** Per-key rate limit configuration, enforced by `verifyWithRateLimit` */
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * One spend of an API key, applied by {@link ApiKeyStore}'s `recordUse`.
 *
 * `refill` is the quota top-up due at `usedAt`, computed by the service from
 * the record it read: the store applies it only while the key's `lastRefillAt`
 * still equals `from`, so two verifies that both saw a refill due add it once.
 *
 * @since 0.6.0
 */
export interface ApiKeyUse {
  /** Unix ms time of the use: the new `lastUsedAt` and `updatedAt` */
  readonly usedAt: number;
  readonly refill?: {
    /** The `lastRefillAt` the refill was computed from */
    readonly from: number;
    /** The new `lastRefillAt` */
    readonly to: number;
    /** Uses to add to `remaining` before the spend */
    readonly amount: number;
    /** Cap on `remaining` after the top-up; undefined = no cap */
    readonly max?: number;
  };
}

/**
 * The record `recordUse` stores for `use` of `key`, or `None` when the key
 * may not be spent: {@link ApiKeyStore}'s `recordUse` contract as a pure
 * function, for a store that can run it inside one atomic step of its own
 * (a lock, a compare-and-set loop, a single-threaded actor).
 *
 * @since 0.6.0
 */
export const applyApiKeyUse = (key: ApiKey, use: ApiKeyUse): Option.Option<ApiKey> => {
  if (!key.enabled) return Option.none();
  if (key.expiresAt !== undefined && use.usedAt > key.expiresAt) return Option.none();
  const refill = use.refill;
  if (refill !== undefined && key.lastRefillAt !== refill.from) return Option.none();
  const topped =
    refill === undefined || key.remaining === undefined
      ? key.remaining
      : Math.min(key.remaining + refill.amount, refill.max ?? Number.POSITIVE_INFINITY);
  if (topped !== undefined && topped <= 0) return Option.none();
  return Option.some({
    ...key,
    ...(topped !== undefined && { remaining: topped - 1 }),
    ...(refill !== undefined && { lastRefillAt: refill.to }),
    lastUsedAt: use.usedAt,
    updatedAt: use.usedAt,
  });
};

/**
 * Storage interface for API keys
 */
export class ApiKeyStore extends Context.Service<
  ApiKeyStore,
  {
    readonly create: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
    readonly get: (id: string) => Effect.Effect<Option.Option<ApiKey>, Errors.AuthError>;
    readonly getByHash: (keyHash: string) => Effect.Effect<Option.Option<ApiKey>, Errors.AuthError>;
    /**
     * Replace the stored record whole. The owner's edits go through it;
     * a verify never does, since a write from a stale read would undo a
     * concurrent edit.
     */
    readonly update: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
    /**
     * Spend one use of key `id`, atomically, and return the record
     * as stored after it, or `None` when the key may not be spent. In one
     * step: the key must exist, be enabled and not have expired at
     * `use.usedAt` (`expiresAt >= usedAt`); a `use.refill` applies only while
     * `lastRefillAt === refill.from`, setting `remaining` to
     * `min(remaining + amount, max)` and `lastRefillAt` to `refill.to`; a
     * set `remaining` must then be above zero, and drops by one; and
     * `lastUsedAt` and `updatedAt` become `usedAt`. No other field changes,
     * so an owner's concurrent disable, permission change or new expiry is
     * never overwritten, and of concurrent uses of a key with one use left
     * exactly one succeeds. On SQL this is one `UPDATE … WHERE … RETURNING`;
     * a get followed by an `update` is the race it closes.
     */
    readonly recordUse: (
      id: string,
      use: ApiKeyUse,
    ) => Effect.Effect<Option.Option<ApiKey>, Errors.AuthError>;
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
    readonly listByUserId: (userId: string) => Effect.Effect<readonly ApiKey[], Errors.AuthError>;
    /**
     * Delete every key `userId` holds; a no-op when they hold none. Deleting
     * a user calls it before the user row goes, and the first proof of
     * an address calls it too.
     */
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/ApiKeyStore") {}

/**
 * API key service configuration
 */
export interface ApiKeyConfig {
  /** Prefix prepended to generated keys when none is supplied (default: "ak_") */
  readonly defaultPrefix?: string;
  /** Number of random bytes in the secret portion, base64url-encoded (default: 32) */
  readonly keyLength?: number;
  /** Default key lifetime in milliseconds; undefined = keys never expire */
  readonly defaultExpiresIn?: number;
  /** Maximum number of keys a single user may hold (default: 10) */
  readonly maxKeysPerUser?: number;
}

/**
 * Options for creating an API key
 */
export interface ApiKeyCreateOptions {
  readonly name?: string;
  /** Overrides the configured default prefix for this key */
  readonly prefix?: string;
  /** Lifetime in milliseconds from now; overrides `defaultExpiresIn` */
  readonly expiresIn?: number;
  readonly permissions?: Record<string, readonly string[]>;
  readonly metadata?: Types.JsonObject;
  /** Number of allowed uses; undefined = unlimited */
  readonly remaining?: number;
  /** Number of uses to restore per `refillInterval` */
  readonly refillAmount?: number;
  /** Milliseconds between refill ticks */
  readonly refillInterval?: number;
  /** Cap for refill; defaults to `remaining` at creation time */
  readonly refillMax?: number;
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
}

/**
 * Result of creating an API key. `key` is the full plaintext key
 * (prefix + secret) and is shown exactly once — it is never stored.
 */
export interface ApiKeyCreateResult {
  readonly key: string;
  readonly apiKey: ApiKey;
}

/**
 * Why a key was refused, as {@link ApiKeyVerifyResult.reason} names it:
 *
 * - `invalid`: no key has that digest.
 * - `disabled`, `expired`: the key exists but is switched off or past its `expiresAt`.
 * - `exhausted`: the key has no `remaining` uses left.
 * - `missing-permissions`: the key lacks a required permission.
 * - `rate-limited`: the key is over its own `rateLimit` (`verifyWithRateLimit` only).
 */
export type ApiKeyRefusal =
  | "invalid"
  | "disabled"
  | "expired"
  | "exhausted"
  | "missing-permissions"
  | "rate-limited";

/**
 * Result of verifying an API key. Verification failures are reported as
 * `{ valid: false, error, reason }` rather than typed failures so callers can
 * treat a bad key as a normal (unauthenticated) outcome.
 */
export interface ApiKeyVerifyResult {
  readonly valid: boolean;
  readonly apiKey?: ApiKey;
  /** A refusal's message, for the server log; an HTTP answer never carries it. */
  readonly error?: string;
  /** A refusal's cause, to branch on (the HTTP tier's `429` for `rate-limited`). */
  readonly reason?: ApiKeyRefusal;
  /** For a `rate-limited` refusal: how long until the key's own limit lets it through. */
  readonly retryAfter?: Duration.Duration;
}

/** A refused verification: its message for the log, and its reason. */
const refused = (error: string, reason: ApiKeyRefusal): ApiKeyVerifyResult => ({
  valid: false,
  error,
  reason,
});

/**
 * Fields of an API key that may be changed after creation.
 */
export interface ApiKeyUpdate {
  readonly name?: string;
  readonly enabled?: boolean;
  readonly expiresAt?: number;
  readonly permissions?: Record<string, readonly string[]>;
  readonly metadata?: Types.JsonObject;
  readonly remaining?: number;
  readonly refillAmount?: number;
  readonly refillInterval?: number;
  readonly refillMax?: number;
  /** Override the refill baseline timestamp (useful for testing and admin corrections) */
  readonly lastRefillAt?: number;
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
}

/**
 * API key service. Requires `ApiKeyStore`, `RateLimiter` and `UserStore`
 * (a key verifies only while its owner exists and is neither banned nor
 * SCIM-deactivated).
 */
export class ApiKeyService extends Context.Service<
  ApiKeyService,
  {
    /**
     * Create a new API key for a user. Returns the plaintext key (shown once)
     * alongside the stored record. Fails with {@link ApiKeyError} when the
     * user already holds `maxKeysPerUser` keys.
     */
    readonly create: (
      userId: string,
      options?: ApiKeyCreateOptions,
    ) => Effect.Effect<ApiKeyCreateResult, ApiKeyError | Errors.AuthError>;

    /**
     * Verify a plaintext API key: sha256 hash lookup, then the owner check (a
     * key whose `userId` names no user, or a banned or SCIM-deactivated one,
     * answers `Invalid API key`, as an
     * unknown key does), then enabled / expiry /
     * remaining-uses / permission checks. On success `remaining` is
     * decremented (when set) and `lastUsedAt` is updated. `requiredPermissions`
     * maps resource → actions; every listed action must be granted on the key.
     */
    readonly verify: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError>;

    /**
     * Like `verify`, but spends nothing and writes nothing: the same lookup,
     * owner, enabled / expiry / remaining-uses / permission checks and the
     * same result, while `remaining`, `lastRefillAt` and `lastUsedAt` stay as
     * they are and no rate-limit token is taken. For re-validating a credential
     * already accepted with `verify` on every request of a long-lived
     * connection, so a key disabled, expired, deleted or whose owner is banned
     * or SCIM-deactivated stops working at once without each re-check using up
     * the quota. A key with no uses left is still refused (`exhausted`); the
     * `apiKey` on success shows any quota refill that is due, which the next
     * `verify` stores.
     */
    readonly check: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError>;

    /**
     * Like `verify`, but when the key carries a `rateLimit` configuration a
     * token is consumed from the {@link RateLimiter} bucket keyed
     * `api-key:${apiKey.id}` once every other check has passed, and
     * before the use is spent. When the limit is exhausted the result is
     * `{ valid: false, error: "Rate limit exceeded", reason: "rate-limited",
     * retryAfter }`. An unknown, disabled, expired, exhausted or
     * under-permitted key is refused with its own reason before any bucket is
     * touched, so only a key that would otherwise verify is ever
     * `rate-limited`, and a refused attempt spends no token. The limiter is the
     * one the layer resolved when it was built, so the call needs nothing from
     * its context.
     */
    readonly verifyWithRateLimit: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError>;

    /**
     * Fetch a key by id, failing with {@link ApiKeyError} when it does not exist.
     */
    readonly get: (keyId: string) => Effect.Effect<ApiKey, ApiKeyError | Errors.AuthError>;

    /**
     * List all keys belonging to a user.
     */
    readonly list: (userId: string) => Effect.Effect<readonly ApiKey[], Errors.AuthError>;

    /**
     * Update a key on behalf of a user. Fails with {@link ApiKeyError} when the
     * key does not exist or belongs to a different user.
     */
    readonly update: (
      userId: string,
      keyId: string,
      updates: ApiKeyUpdate,
    ) => Effect.Effect<ApiKey, ApiKeyError | Errors.AuthError>;

    /**
     * Delete a key on behalf of a user. Fails with {@link ApiKeyError} when the
     * key does not exist or belongs to a different user.
     */
    readonly delete: (
      userId: string,
      keyId: string,
    ) => Effect.Effect<void, ApiKeyError | Errors.AuthError>;

    /**
     * Delete every key of a user whose `expiresAt` is in the past. Returns the
     * number of keys removed. (The store enumerates per user, so run this per
     * user; a store-level sweep job is the right tool for global cleanup.)
     */
    readonly deleteAllExpired: (userId: string) => Effect.Effect<number, Errors.AuthError>;
  }
>()("@effect-auth/ApiKeyService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: ApiKeyConfig = {}) =>
    Layer.effect(ApiKeyService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * SHA-256 hex digest of a plaintext API key. Exposed so stores/tests can
 * compute lookup hashes without duplicating the hashing scheme.
 */
export const hashApiKey = hashToken;

/**
 * Check that every requested `resource → actions` entry is granted by the
 * key's stored permissions. A key without a `permissions` map rejects any
 * non-empty requirement.
 */
const hasRequiredPermissions = (
  granted: Record<string, readonly string[]> | undefined,
  required: Record<string, readonly string[]>,
): boolean =>
  Arr.every(R.toEntries(required), ([resource, actions]) => {
    if (Arr.isReadonlyArrayEmpty(actions)) {
      return true;
    }
    const grantedActions = granted?.[resource];
    if (!grantedActions) {
      return false;
    }
    return Arr.every(actions, (action) => grantedActions.includes(action));
  });

/** A key that passed {@link checkAt}: with its due refill, and that refill. */
interface Passed {
  readonly key: ApiKey;
  readonly refill: ApiKeyUse["refill"];
}

/**
 * The enabled / expiry / remaining-uses / permission checks of a key at
 * `now`, writing nothing: a refusal, or the key with its due quota refill
 * applied (lazily, before the remaining-uses check) and that refill, which
 * the spend hands to `recordUse`.
 */
const checkAt = (
  apiKey: ApiKey,
  requiredPermissions: Record<string, readonly string[]> | undefined,
  now: number,
): ApiKeyVerifyResult | Passed => {
  if (!apiKey.enabled) {
    return refused("API key is disabled", "disabled");
  }

  if (apiKey.expiresAt !== undefined && now > apiKey.expiresAt) {
    return refused("API key has expired", "expired");
  }

  const refill = dueRefill(apiKey, now);
  const key = withRefill(apiKey, refill);

  if (key.remaining !== undefined && key.remaining <= 0) {
    return refused("API key has no remaining uses", "exhausted");
  }

  if (requiredPermissions && !hasRequiredPermissions(key.permissions, requiredPermissions)) {
    return refused("API key is missing required permissions", "missing-permissions");
  }

  return { key, refill };
};

/**
 * {@link checkAt} at the current time: the refusal, or the record with its due
 * refills applied, that refill, and the time it was judged at.
 */
const checkRecord = (
  apiKey: ApiKey,
  requiredPermissions: Record<string, readonly string[]> | undefined,
): Effect.Effect<
  | { readonly refused: ApiKeyVerifyResult }
  | (Passed & { readonly refused?: undefined; readonly now: number })
> =>
  Effect.map(Clock.currentTimeMillis, (now) => {
    const outcome = checkAt(apiKey, requiredPermissions, now);
    return "key" in outcome ? { ...outcome, now } : { refused: outcome };
  });

/** The quota refill due on `key` by `now`, or `undefined` when none is. */
const dueRefill = (key: ApiKey, now: number): ApiKeyUse["refill"] => {
  if (
    key.remaining === undefined ||
    key.refillAmount === undefined ||
    key.refillInterval === undefined ||
    key.lastRefillAt === undefined
  ) {
    return undefined;
  }
  const dueRefills = Math.floor((now - key.lastRefillAt) / key.refillInterval);
  if (dueRefills <= 0) return undefined;
  return {
    from: key.lastRefillAt,
    to: key.lastRefillAt + dueRefills * key.refillInterval,
    amount: dueRefills * key.refillAmount,
    ...(key.refillMax !== undefined && { max: key.refillMax }),
  };
};

/** `key` with `refill` applied, capped at its `max`: what `recordUse` stores. */
const withRefill = (key: ApiKey, refill: ApiKeyUse["refill"]): ApiKey => {
  if (refill === undefined || key.remaining === undefined) return key;
  const topped = key.remaining + refill.amount;
  return {
    ...key,
    remaining: refill.max !== undefined ? Math.min(topped, refill.max) : topped,
    lastRefillAt: refill.to,
  };
};

/**
 * How many times a verify re-reads and re-checks a key whose `recordUse`
 * found it changed. A loss means a concurrent verify applied the
 * refill this one computed, or an owner edited or spent the key out: the
 * re-read sees either a key that passes (and spends without a refill) or a
 * refusal, so two attempts settle all but a key edited in a tight loop.
 */
const useAttempts = 4;

/**
 * Create an API key service
 */
export const make = (
  config: ApiKeyConfig = {},
): Effect.Effect<
  typeof ApiKeyService.Service,
  never,
  ApiKeyStore | RateLimiter | UserStore | SecureRandom.SecureRandom | Digest.Digest
> =>
  Effect.gen(function* () {
    const defaultPrefix = config?.defaultPrefix ?? "ak_";
    const keyLength = config?.keyLength ?? 32;
    const defaultExpiresIn = config?.defaultExpiresIn;
    const maxKeysPerUser = config?.maxKeysPerUser ?? 10;

    const store = yield* ApiKeyStore;
    const rateLimiter = yield* RateLimiter;
    const users = yield* UserStore;
    const crypto = yield* SecureRandom.SecureRandom;
    const hashKey = yield* tokenHasher;

    const randomToken = (): Effect.Effect<string> =>
      crypto.randomBytes(keyLength).pipe(Effect.map(Base64Url.encode));

    const randomId = (): Effect.Effect<string> => crypto.uuidV4();

    /**
     * Load a key by id and enforce ownership.
     */
    const getOwned = (userId: string, keyId: string) =>
      Effect.gen(function* () {
        const foundApiKey = yield* store.get(keyId);
        if (Option.isNone(foundApiKey) || foundApiKey.value.userId !== userId) {
          return yield* new ApiKeyError({
            message: "API key not found",
          });
        }
        const apiKey = foundApiKey.value;
        return apiKey;
      });

    /**
     * Spend one use of a key that passed {@link checkRecord}, atomically:
     * `recordUse` decrements `remaining` (when set) and moves
     * `lastUsedAt`, touching nothing an owner edits. When it finds the key
     * changed since the read, the key is read and checked again, so a key
     * disabled, expired, exhausted or narrowed meanwhile is refused as such.
     */
    const spend = (
      checked: Passed & { readonly now: number },
      requiredPermissions: Record<string, readonly string[]> | undefined,
      attempt = 1,
    ): Effect.Effect<ApiKeyVerifyResult, Errors.AuthError> =>
      Effect.gen(function* () {
        const spent = yield* store.recordUse(checked.key.id, {
          usedAt: checked.now,
          ...(checked.refill !== undefined && { refill: checked.refill }),
        });
        if (Option.isSome(spent)) {
          return { valid: true, apiKey: spent.value } satisfies ApiKeyVerifyResult;
        }
        if (attempt >= useAttempts) {
          return yield* new Errors.AuthError({ message: "apiKey.recordUse contended" });
        }
        const foundFresh = yield* store.get(checked.key.id);
        if (Option.isNone(foundFresh)) return refused("Invalid API key", "invalid");
        const fresh = foundFresh.value;
        const again = yield* checkRecord(fresh, requiredPermissions);
        if (again.refused !== undefined) return again.refused;
        return yield* spend(again, requiredPermissions, attempt + 1);
      });

    /**
     * Hash lookup for a plaintext key, `None` when no key matches or its owner
     * no longer exists or is banned or SCIM-deactivated: a key outlives its user only when something
     * deleted the user row without the purge, and it must not authenticate.
     * Lookup is by exact sha256 digest, so the comparison carries no
     * secret-dependent timing.
     */
    const lookup = (plaintextKey: string): Effect.Effect<Option.Option<ApiKey>, Errors.AuthError> =>
      Effect.flatMap(Effect.flatMap(hashKey(plaintextKey), store.getByHash), (found) =>
        Option.isNone(found)
          ? Effect.succeedNone
          : Effect.flatMap(users.get(found.value.userId), (owner) =>
              Option.isNone(owner)
                ? Effect.succeedNone
                : // A banned or SCIM-deactivated owner's key is refused as
                  // unknown, before the per-key limit and the spend.
                  Effect.map(isInGoodStanding(owner.value), (good) =>
                    good ? found : Option.none(),
                  ),
            ),
      );

    /**
     * {@link lookup}, then {@link checkRecord}: the refusal (`invalid` for a
     * key `lookup` does not find), or the key that passed, written nowhere yet.
     */
    const lookupAndCheck = (
      plaintextKey: string,
      requiredPermissions: Record<string, readonly string[]> | undefined,
    ) =>
      Effect.flatMap(lookup(plaintextKey), (apiKey) =>
        Option.isNone(apiKey)
          ? Effect.succeed({ refused: refused("Invalid API key", "invalid") })
          : checkRecord(apiKey.value, requiredPermissions),
      );

    return {
      create: Effect.fn("ApiKeyService.create")(function* (
        userId: string,
        options?: ApiKeyCreateOptions,
      ) {
        const existing = yield* store.listByUserId(userId);
        if (existing.length >= maxKeysPerUser) {
          return yield* new ApiKeyError({
            message: `User already has the maximum of ${maxKeysPerUser} API keys`,
          });
        }

        const prefix = options?.prefix ?? defaultPrefix;
        const secret = yield* randomToken();
        const key = `${prefix}${secret}`;

        const now = yield* Clock.currentTimeMillis;
        const expiresIn = options?.expiresIn ?? defaultExpiresIn;

        const hasRefill =
          options?.refillAmount !== undefined && options?.refillInterval !== undefined;

        const apiKey: ApiKey = {
          id: yield* randomId(),
          ...(options?.name !== undefined && { name: options.name }),
          prefix,
          start: secret.slice(0, 6),
          keyHash: yield* hashKey(key),
          userId,
          enabled: true,
          ...(expiresIn !== undefined && { expiresAt: now + expiresIn }),
          ...(options?.permissions !== undefined && { permissions: options.permissions }),
          metadata: options?.metadata ?? {},
          ...(options?.remaining !== undefined && { remaining: options.remaining }),
          ...(hasRefill && { refillAmount: options.refillAmount }),
          ...(hasRefill && { refillInterval: options.refillInterval }),
          ...(hasRefill && {
            lastRefillAt: now,
            ...(options?.remaining !== undefined && {
              refillMax: options.refillMax ?? options.remaining,
            }),
          }),
          ...(options?.rateLimit !== undefined && { rateLimit: options.rateLimit }),
          createdAt: now,
          updatedAt: now,
        };

        const created = yield* store.create(apiKey);

        return { key, apiKey: created } satisfies ApiKeyCreateResult;
      }),

      verify: Effect.fn("ApiKeyService.verify")(function* (
        plaintextKey: string,
        requiredPermissions?: Record<string, readonly string[]>,
      ) {
        const checked = yield* lookupAndCheck(plaintextKey, requiredPermissions);
        if (checked.refused !== undefined) return checked.refused;
        return yield* spend(checked, requiredPermissions);
      }),

      check: Effect.fn("ApiKeyService.check")(function* (
        plaintextKey: string,
        requiredPermissions?: Record<string, readonly string[]>,
      ) {
        const checked = yield* lookupAndCheck(plaintextKey, requiredPermissions);
        if (checked.refused !== undefined) return checked.refused;
        return { valid: true, apiKey: checked.key } satisfies ApiKeyVerifyResult;
      }),

      verifyWithRateLimit: Effect.fn("ApiKeyService.verifyWithRateLimit")(function* (
        plaintextKey: string,
        requiredPermissions?: Record<string, readonly string[]>,
      ) {
        // Every other refusal comes first, so a disabled, expired, exhausted
        // or under-permitted key is refused as such whatever its bucket holds
        // (and spends no token): only a key that would otherwise pass is ever
        // `rate-limited`.
        const checked = yield* lookupAndCheck(plaintextKey, requiredPermissions);
        if (checked.refused !== undefined) return checked.refused;
        const apiKey = checked.key;

        if (apiKey.rateLimit) {
          const limited = yield* rateLimiter
            .consumeToken(`api-key:${apiKey.id}`, apiKey.rateLimit satisfies RateLimitConfig)
            .pipe(
              Effect.as(Option.none<Errors.RateLimitError>()),
              Effect.catchTag("RateLimitError", (e) => Effect.succeedSome(e)),
            );
          if (Option.isSome(limited)) {
            return {
              ...refused("Rate limit exceeded", "rate-limited"),
              ...definedKeys({ retryAfter: limited.value.retryAfter }),
            } satisfies ApiKeyVerifyResult;
          }
        }

        return yield* spend(checked, requiredPermissions);
      }),

      get: Effect.fn("ApiKeyService.get")(function* (keyId: string) {
        const foundApiKey = yield* store.get(keyId);
        if (Option.isNone(foundApiKey)) {
          return yield* new ApiKeyError({
            message: "API key not found",
          });
        }
        const apiKey = foundApiKey.value;
        return apiKey;
      }),

      list: Effect.fn("ApiKeyService.list")(function* (userId: string) {
        return yield* store.listByUserId(userId);
      }),

      update: Effect.fn("ApiKeyService.update")(function* (
        userId: string,
        keyId: string,
        updates: ApiKeyUpdate,
      ) {
        const apiKey = yield* getOwned(userId, keyId);

        return yield* store.update({
          ...apiKey,
          ...(updates.name !== undefined && { name: updates.name }),
          ...(updates.enabled !== undefined && { enabled: updates.enabled }),
          ...(updates.expiresAt !== undefined && { expiresAt: updates.expiresAt }),
          ...(updates.permissions !== undefined && { permissions: updates.permissions }),
          ...(updates.metadata !== undefined && { metadata: updates.metadata }),
          ...(updates.remaining !== undefined && { remaining: updates.remaining }),
          ...(updates.refillAmount !== undefined && { refillAmount: updates.refillAmount }),
          ...(updates.refillInterval !== undefined && { refillInterval: updates.refillInterval }),
          ...(updates.refillMax !== undefined && { refillMax: updates.refillMax }),
          ...(updates.lastRefillAt !== undefined && { lastRefillAt: updates.lastRefillAt }),
          ...(updates.rateLimit !== undefined && { rateLimit: updates.rateLimit }),
          updatedAt: yield* Clock.currentTimeMillis,
        });
      }),

      delete: Effect.fn("ApiKeyService.delete")(function* (userId: string, keyId: string) {
        const apiKey = yield* getOwned(userId, keyId);
        yield* store.delete(apiKey.id);
      }),

      deleteAllExpired: Effect.fn("ApiKeyService.deleteAllExpired")(function* (userId: string) {
        const now = yield* Clock.currentTimeMillis;

        const candidates = yield* store.listByUserId(userId);

        const expired = Arr.filter(
          candidates,
          (apiKey) => apiKey.expiresAt !== undefined && now > apiKey.expiresAt,
        );
        yield* Effect.forEach(expired, (apiKey) => store.delete(apiKey.id), {
          concurrency: 1,
          discard: true,
        });
        return expired.length;
      }),
    };
  });
