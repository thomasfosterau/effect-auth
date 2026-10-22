/**
 * API key management for effect-auth.
 *
 * Mirrors better-auth's api-key plugin: users create long-lived API keys
 * (shown in plaintext exactly once), which are later presented by clients
 * and verified by sha256 hash lookup. Keys support expiry, enable/disable,
 * per-resource permissions, remaining-use quotas, arbitrary metadata, and
 * an optional per-key rate limit that is enforced through the
 * {@link RateLimiter} service.
 *
 * Only the sha256 hex digest of a key is ever persisted — the plaintext is
 * returned once from `create` and cannot be recovered. Because verification
 * looks a key up by its exact digest (rather than comparing secrets
 * byte-by-byte), the comparison is inherently timing-safe.
 *
 * @module api-key
 */

import { Array as Arr, Context, Crypto, Data, Effect, Layer, Record as Rec } from "effect";
import * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { RateLimiter, RateLimitStore, type RateLimitConfig } from "./RateLimit.ts";
import { hashToken } from "./TokenHash.ts";

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
  readonly metadata: Record<string, unknown>;
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
 * Storage interface for API keys
 */
export class ApiKeyStore extends Context.Service<
  ApiKeyStore,
  {
    readonly create: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
    readonly get: (id: string) => Effect.Effect<ApiKey | null, Errors.AuthError>;
    readonly getByHash: (keyHash: string) => Effect.Effect<ApiKey | null, Errors.AuthError>;
    readonly update: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
    readonly listByUserId: (userId: string) => Effect.Effect<readonly ApiKey[], Errors.AuthError>;
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
  readonly metadata?: Record<string, unknown>;
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
 * Result of verifying an API key. Verification failures are reported as
 * `{ valid: false, error }` rather than typed failures so callers can treat
 * a bad key as a normal (unauthenticated) outcome.
 */
export interface ApiKeyVerifyResult {
  readonly valid: boolean;
  readonly apiKey?: ApiKey;
  readonly error?: string;
}

/**
 * Fields of an API key that may be changed after creation.
 */
export interface ApiKeyUpdate {
  readonly name?: string;
  readonly enabled?: boolean;
  readonly expiresAt?: number;
  readonly permissions?: Record<string, readonly string[]>;
  readonly metadata?: Record<string, unknown>;
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
 * API key service
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
     * Verify a plaintext API key: sha256 hash lookup, then enabled / expiry /
     * remaining-uses / permission checks. On success `remaining` is
     * decremented (when set) and `lastUsedAt` is updated. `requiredPermissions`
     * maps resource → actions; every listed action must be granted on the key.
     */
    readonly verify: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError>;

    /**
     * Like `verify`, but when the key carries a `rateLimit` configuration a
     * token is consumed from the {@link RateLimiter} bucket keyed
     * `api-key:${apiKey.id}` before the remaining checks run. When the limit
     * is exhausted the result is `{ valid: false, error: "Rate limit exceeded" }`.
     */
    readonly verifyWithRateLimit: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError, RateLimitStore>;

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
  Arr.every(Rec.toEntries(required), ([resource, actions]) => {
    if (Arr.isReadonlyArrayEmpty(actions)) {
      return true;
    }
    const grantedActions = granted?.[resource];
    if (!grantedActions) {
      return false;
    }
    return Arr.every(actions, (action) => grantedActions.includes(action));
  });

/**
 * Create an API key service
 */
export const make = (
  config: ApiKeyConfig = {},
): Effect.Effect<typeof ApiKeyService.Service, never, ApiKeyStore | RateLimiter | Crypto.Crypto> =>
  Effect.gen(function* () {
    const defaultPrefix = config?.defaultPrefix ?? "ak_";
    const keyLength = config?.keyLength ?? 32;
    const defaultExpiresIn = config?.defaultExpiresIn;
    const maxKeysPerUser = config?.maxKeysPerUser ?? 10;

    const store = yield* ApiKeyStore;
    const rateLimiter = yield* RateLimiter;
    const crypto = yield* Crypto.Crypto;

    const randomToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(keyLength).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate API key secret", cause }),
        ),
      );

    const randomId = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomUUIDv4.pipe(
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate API key id", cause }),
        ),
      );

    /**
     * Load a key by id and enforce ownership.
     */
    const getOwned = (userId: string, keyId: string) =>
      Effect.gen(function* () {
        const apiKey = yield* store.get(keyId);
        if (!apiKey || apiKey.userId !== userId) {
          return yield* new ApiKeyError({
            message: "API key not found",
          });
        }
        return apiKey;
      });

    /**
     * Run the enabled/expiry/remaining/permission checks against a record
     * found by hash lookup, updating `remaining`/`lastUsedAt` on success.
     * Due quota refills are applied lazily before the remaining-uses check.
     */
    const verifyRecord = (
      apiKey: ApiKey,
      requiredPermissions: Record<string, readonly string[]> | undefined,
    ) =>
      Effect.gen(function* () {
        const now = Date.now();

        if (!apiKey.enabled) {
          return { valid: false, error: "API key is disabled" } satisfies ApiKeyVerifyResult;
        }

        if (apiKey.expiresAt !== undefined && now > apiKey.expiresAt) {
          return { valid: false, error: "API key has expired" } satisfies ApiKeyVerifyResult;
        }

        // Lazily apply quota refills before checking remaining
        let key = apiKey;
        if (
          key.remaining !== undefined &&
          key.refillAmount !== undefined &&
          key.refillInterval !== undefined &&
          key.lastRefillAt !== undefined
        ) {
          const dueRefills = Math.floor((now - key.lastRefillAt) / key.refillInterval);
          if (dueRefills > 0) {
            const refilled =
              key.refillMax !== undefined
                ? Math.min(key.remaining + dueRefills * key.refillAmount, key.refillMax)
                : key.remaining + dueRefills * key.refillAmount;
            key = {
              ...key,
              remaining: refilled,
              lastRefillAt: key.lastRefillAt + dueRefills * key.refillInterval,
            };
          }
        }

        if (key.remaining !== undefined && key.remaining <= 0) {
          return {
            valid: false,
            error: "API key has no remaining uses",
          } satisfies ApiKeyVerifyResult;
        }

        if (requiredPermissions && !hasRequiredPermissions(key.permissions, requiredPermissions)) {
          return {
            valid: false,
            error: "API key is missing required permissions",
          } satisfies ApiKeyVerifyResult;
        }

        const updated = yield* store.update({
          ...key,
          ...(key.remaining !== undefined && { remaining: key.remaining - 1 }),
          lastUsedAt: now,
          updatedAt: now,
        });

        return { valid: true, apiKey: updated } satisfies ApiKeyVerifyResult;
      });

    /**
     * Hash lookup for a plaintext key. Lookup is by exact sha256 digest, so
     * the comparison carries no secret-dependent timing.
     */
    const lookup = (plaintextKey: string) => store.getByHash(hashApiKey(plaintextKey));

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

        const now = Date.now();
        const expiresIn = options?.expiresIn ?? defaultExpiresIn;

        const hasRefill =
          options?.refillAmount !== undefined && options?.refillInterval !== undefined;

        const apiKey: ApiKey = {
          id: yield* randomId(),
          ...(options?.name !== undefined && { name: options.name }),
          prefix,
          start: secret.slice(0, 6),
          keyHash: hashApiKey(key),
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
        const apiKey = yield* lookup(plaintextKey);
        if (!apiKey) {
          return { valid: false, error: "Invalid API key" } satisfies ApiKeyVerifyResult;
        }
        return yield* verifyRecord(apiKey, requiredPermissions);
      }),

      verifyWithRateLimit: Effect.fn("ApiKeyService.verifyWithRateLimit")(function* (
        plaintextKey: string,
        requiredPermissions?: Record<string, readonly string[]>,
      ) {
        const apiKey = yield* lookup(plaintextKey);
        if (!apiKey) {
          return { valid: false, error: "Invalid API key" } satisfies ApiKeyVerifyResult;
        }

        if (apiKey.rateLimit) {
          const limited = yield* rateLimiter
            .consumeToken(`api-key:${apiKey.id}`, apiKey.rateLimit satisfies RateLimitConfig)
            .pipe(
              Effect.as(false),
              Effect.catchTag("RateLimitError", () => Effect.succeed(true)),
            );
          if (limited) {
            return { valid: false, error: "Rate limit exceeded" } satisfies ApiKeyVerifyResult;
          }
        }

        return yield* verifyRecord(apiKey, requiredPermissions);
      }),

      get: Effect.fn("ApiKeyService.get")(function* (keyId: string) {
        const apiKey = yield* store.get(keyId);
        if (!apiKey) {
          return yield* new ApiKeyError({
            message: "API key not found",
          });
        }
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
          updatedAt: Date.now(),
        });
      }),

      delete: Effect.fn("ApiKeyService.delete")(function* (userId: string, keyId: string) {
        const apiKey = yield* getOwned(userId, keyId);
        yield* store.delete(apiKey.id);
      }),

      deleteAllExpired: Effect.fn("ApiKeyService.deleteAllExpired")(function* (userId: string) {
        const now = Date.now();

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
