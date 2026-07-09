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

import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type * as Errors from "./Errors.ts";
import { RateLimiter, RateLimitStore, type RateLimitConfig } from "./RateLimit.ts";
import { hashToken } from "./TokenHash.ts";

/**
 * API key error
 */
export class APIKeyError extends Data.TaggedError("APIKeyError")<{
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
export interface APIKey {
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
export class APIKeyStore extends Context.Service<
  APIKeyStore,
  {
    readonly create: (apiKey: APIKey) => Effect.Effect<APIKey, Errors.AuthError>;
    readonly get: (id: string) => Effect.Effect<APIKey | null, Errors.AuthError>;
    readonly getByHash: (keyHash: string) => Effect.Effect<APIKey | null, Errors.AuthError>;
    readonly update: (apiKey: APIKey) => Effect.Effect<APIKey, Errors.AuthError>;
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
    readonly listByUserId: (userId: string) => Effect.Effect<readonly APIKey[], Errors.AuthError>;
  }
>()("@effect-auth/APIKeyStore") {}

/**
 * API key service configuration
 */
export interface APIKeyConfig {
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
export interface APIKeyCreateOptions {
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
export interface APIKeyCreateResult {
  readonly key: string;
  readonly apiKey: APIKey;
}

/**
 * Result of verifying an API key. Verification failures are reported as
 * `{ valid: false, error }` rather than typed failures so callers can treat
 * a bad key as a normal (unauthenticated) outcome.
 */
export interface APIKeyVerifyResult {
  readonly valid: boolean;
  readonly apiKey?: APIKey;
  readonly error?: string;
}

/**
 * Fields of an API key that may be changed after creation.
 */
export interface APIKeyUpdate {
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
export class APIKeyService extends Context.Service<
  APIKeyService,
  {
    /**
     * Create a new API key for a user. Returns the plaintext key (shown once)
     * alongside the stored record. Fails with {@link APIKeyError} when the
     * user already holds `maxKeysPerUser` keys.
     */
    readonly create: (
      userId: string,
      options?: APIKeyCreateOptions,
    ) => Effect.Effect<APIKeyCreateResult, APIKeyError | Errors.AuthError, APIKeyStore>;

    /**
     * Verify a plaintext API key: sha256 hash lookup, then enabled / expiry /
     * remaining-uses / permission checks. On success `remaining` is
     * decremented (when set) and `lastUsedAt` is updated. `requiredPermissions`
     * maps resource → actions; every listed action must be granted on the key.
     */
    readonly verify: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<APIKeyVerifyResult, Errors.AuthError, APIKeyStore>;

    /**
     * Like `verify`, but when the key carries a `rateLimit` configuration a
     * token is consumed from the {@link RateLimiter} bucket keyed
     * `api-key:${apiKey.id}` before the remaining checks run. When the limit
     * is exhausted the result is `{ valid: false, error: "Rate limit exceeded" }`.
     */
    readonly verifyWithRateLimit: (
      plaintextKey: string,
      requiredPermissions?: Record<string, readonly string[]>,
    ) => Effect.Effect<
      APIKeyVerifyResult,
      Errors.AuthError,
      APIKeyStore | RateLimiter | RateLimitStore
    >;

    /**
     * Fetch a key by id, failing with {@link APIKeyError} when it does not exist.
     */
    readonly get: (
      keyId: string,
    ) => Effect.Effect<APIKey, APIKeyError | Errors.AuthError, APIKeyStore>;

    /**
     * List all keys belonging to a user.
     */
    readonly list: (
      userId: string,
    ) => Effect.Effect<readonly APIKey[], Errors.AuthError, APIKeyStore>;

    /**
     * Update a key on behalf of a user. Fails with {@link APIKeyError} when the
     * key does not exist or belongs to a different user.
     */
    readonly update: (
      userId: string,
      keyId: string,
      updates: APIKeyUpdate,
    ) => Effect.Effect<APIKey, APIKeyError | Errors.AuthError, APIKeyStore>;

    /**
     * Delete a key on behalf of a user. Fails with {@link APIKeyError} when the
     * key does not exist or belongs to a different user.
     */
    readonly delete: (
      userId: string,
      keyId: string,
    ) => Effect.Effect<void, APIKeyError | Errors.AuthError, APIKeyStore>;

    /**
     * Delete every key of a user whose `expiresAt` is in the past. Returns the
     * number of keys removed. (The store enumerates per user, so run this per
     * user; a store-level sweep job is the right tool for global cleanup.)
     */
    readonly deleteAllExpired: (
      userId: string,
    ) => Effect.Effect<number, Errors.AuthError, APIKeyStore>;
  }
>()("@effect-auth/APIKeyService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: APIKeyConfig = {}) =>
    Layer.effect(APIKeyService, makeAPIKeyService(config));
}

/**
 * SHA-256 hex digest of a plaintext API key. Exposed so stores/tests can
 * compute lookup hashes without duplicating the hashing scheme.
 */
export const hashAPIKey = hashToken;

/**
 * Check that every requested `resource → actions` entry is granted by the
 * key's stored permissions. A key without a `permissions` map rejects any
 * non-empty requirement.
 */
const hasRequiredPermissions = (
  granted: Record<string, readonly string[]> | undefined,
  required: Record<string, readonly string[]>,
): boolean => {
  for (const [resource, actions] of Object.entries(required)) {
    if (actions.length === 0) {
      continue;
    }
    const grantedActions = granted?.[resource];
    if (!grantedActions) {
      return false;
    }
    for (const action of actions) {
      if (!grantedActions.includes(action)) {
        return false;
      }
    }
  }
  return true;
};

/**
 * Create an API key service
 */
export const makeAPIKeyService = (
  config: APIKeyConfig = {},
): Effect.Effect<typeof APIKeyService.Service, never> => {
  const defaultPrefix = config?.defaultPrefix ?? "ak_";
  const keyLength = config?.keyLength ?? 32;
  const defaultExpiresIn = config?.defaultExpiresIn;
  const maxKeysPerUser = config?.maxKeysPerUser ?? 10;

  /**
   * Load a key by id and enforce ownership.
   */
  const getOwned = (userId: string, keyId: string) =>
    Effect.gen(function* () {
      const store = yield* APIKeyStore;
      const apiKey = yield* store.get(keyId);
      if (!apiKey || apiKey.userId !== userId) {
        return yield* Effect.fail(
          new APIKeyError({
            message: "API key not found",
          }),
        );
      }
      return apiKey;
    });

  /**
   * Run the enabled/expiry/remaining/permission checks against a record
   * found by hash lookup, updating `remaining`/`lastUsedAt` on success.
   * Due quota refills are applied lazily before the remaining-uses check.
   */
  const verifyRecord = (
    apiKey: APIKey,
    requiredPermissions: Record<string, readonly string[]> | undefined,
  ) =>
    Effect.gen(function* () {
      const now = Date.now();

      if (!apiKey.enabled) {
        return { valid: false, error: "API key is disabled" } satisfies APIKeyVerifyResult;
      }

      if (apiKey.expiresAt !== undefined && now > apiKey.expiresAt) {
        return { valid: false, error: "API key has expired" } satisfies APIKeyVerifyResult;
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
        } satisfies APIKeyVerifyResult;
      }

      if (requiredPermissions && !hasRequiredPermissions(key.permissions, requiredPermissions)) {
        return {
          valid: false,
          error: "API key is missing required permissions",
        } satisfies APIKeyVerifyResult;
      }

      const store = yield* APIKeyStore;
      const updated = yield* store.update({
        ...key,
        ...(key.remaining !== undefined && { remaining: key.remaining - 1 }),
        lastUsedAt: now,
        updatedAt: now,
      });

      return { valid: true, apiKey: updated } satisfies APIKeyVerifyResult;
    });

  /**
   * Hash lookup for a plaintext key. Lookup is by exact sha256 digest, so
   * the comparison carries no secret-dependent timing.
   */
  const lookup = (plaintextKey: string) =>
    Effect.gen(function* () {
      const store = yield* APIKeyStore;
      return yield* store.getByHash(hashAPIKey(plaintextKey));
    });

  return Effect.sync((): typeof APIKeyService.Service => ({
    create: (userId, options) =>
      Effect.gen(function* () {
        const store = yield* APIKeyStore;

        const existing = yield* store.listByUserId(userId);
        if (existing.length >= maxKeysPerUser) {
          return yield* Effect.fail(
            new APIKeyError({
              message: `User already has the maximum of ${maxKeysPerUser} API keys`,
            }),
          );
        }

        const prefix = options?.prefix ?? defaultPrefix;
        const secret = crypto.randomBytes(keyLength).toString("base64url");
        const key = `${prefix}${secret}`;

        const now = Date.now();
        const expiresIn = options?.expiresIn ?? defaultExpiresIn;

        const hasRefill =
          options?.refillAmount !== undefined && options?.refillInterval !== undefined;

        const apiKey: APIKey = {
          id: crypto.randomUUID(),
          ...(options?.name !== undefined && { name: options.name }),
          prefix,
          start: secret.slice(0, 6),
          keyHash: hashAPIKey(key),
          userId,
          enabled: true,
          ...(expiresIn !== undefined && { expiresAt: now + expiresIn }),
          ...(options?.permissions !== undefined && { permissions: options.permissions }),
          metadata: options?.metadata ?? {},
          ...(options?.remaining !== undefined && { remaining: options.remaining }),
          ...(hasRefill && { refillAmount: options!.refillAmount }),
          ...(hasRefill && { refillInterval: options!.refillInterval }),
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

        return { key, apiKey: created } satisfies APIKeyCreateResult;
      }),

    verify: (plaintextKey, requiredPermissions) =>
      Effect.gen(function* () {
        const apiKey = yield* lookup(plaintextKey);
        if (!apiKey) {
          return { valid: false, error: "Invalid API key" } satisfies APIKeyVerifyResult;
        }
        return yield* verifyRecord(apiKey, requiredPermissions);
      }),

    verifyWithRateLimit: (plaintextKey, requiredPermissions) =>
      Effect.gen(function* () {
        const apiKey = yield* lookup(plaintextKey);
        if (!apiKey) {
          return { valid: false, error: "Invalid API key" } satisfies APIKeyVerifyResult;
        }

        if (apiKey.rateLimit) {
          const rateLimiter = yield* RateLimiter;
          const limited = yield* rateLimiter
            .consumeToken(`api-key:${apiKey.id}`, apiKey.rateLimit satisfies RateLimitConfig)
            .pipe(
              Effect.as(false),
              Effect.catchTag("RateLimitError", () => Effect.succeed(true)),
            );
          if (limited) {
            return { valid: false, error: "Rate limit exceeded" } satisfies APIKeyVerifyResult;
          }
        }

        return yield* verifyRecord(apiKey, requiredPermissions);
      }),

    get: (keyId) =>
      Effect.gen(function* () {
        const store = yield* APIKeyStore;
        const apiKey = yield* store.get(keyId);
        if (!apiKey) {
          return yield* Effect.fail(
            new APIKeyError({
              message: "API key not found",
            }),
          );
        }
        return apiKey;
      }),

    list: (userId) =>
      Effect.gen(function* () {
        const store = yield* APIKeyStore;
        return yield* store.listByUserId(userId);
      }),

    update: (userId, keyId, updates) =>
      Effect.gen(function* () {
        const apiKey = yield* getOwned(userId, keyId);
        const store = yield* APIKeyStore;

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

    delete: (userId, keyId) =>
      Effect.gen(function* () {
        const apiKey = yield* getOwned(userId, keyId);
        const store = yield* APIKeyStore;
        yield* store.delete(apiKey.id);
      }),

    deleteAllExpired: (userId) =>
      Effect.gen(function* () {
        const store = yield* APIKeyStore;
        const now = Date.now();

        const candidates = yield* store.listByUserId(userId);

        let deleted = 0;
        for (const apiKey of candidates) {
          if (apiKey.expiresAt !== undefined && now > apiKey.expiresAt) {
            yield* store.delete(apiKey.id);
            deleted += 1;
          }
        }
        return deleted;
      }),
  }));
};
