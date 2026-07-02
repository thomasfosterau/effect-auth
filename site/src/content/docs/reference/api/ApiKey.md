---
title: "ApiKey"
description: "API reference for the ApiKey module."
---

## ApiKey overview

API key management for effect-auth.

Mirrors better-auth's api-key plugin: users create long-lived API keys
(shown in plaintext exactly once), which are later presented by clients
and verified by sha256 hash lookup. Keys support expiry, enable/disable,
per-resource permissions, remaining-use quotas, arbitrary metadata, and
an optional per-key rate limit that is enforced through the
{@link RateLimiterTag} service.

Only the sha256 hex digest of a key is ever persisted — the plaintext is
returned once from `create` and cannot be recovered. Because verification
looks a key up by its exact digest (rather than comparing secrets
byte-by-byte), the comparison is inherently timing-safe.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [ApiKey (interface)](#apikey-interface)
  - [ApiKeyConfig (interface)](#apikeyconfig-interface)
  - [ApiKeyCreateOptions (interface)](#apikeycreateoptions-interface)
  - [ApiKeyCreateResult (interface)](#apikeycreateresult-interface)
  - [ApiKeyError (class)](#apikeyerror-class)
  - [ApiKeyService](#apikeyservice)
  - [ApiKeyService (interface)](#apikeyservice-interface)
  - [ApiKeyServiceLayer](#apikeyservicelayer)
  - [ApiKeyServiceTag (class)](#apikeyservicetag-class)
  - [ApiKeyStore](#apikeystore)
  - [ApiKeyStore (interface)](#apikeystore-interface)
  - [ApiKeyStoreTag (class)](#apikeystoretag-class)
  - [ApiKeyUpdate (interface)](#apikeyupdate-interface)
  - [ApiKeyVerifyResult (interface)](#apikeyverifyresult-interface)
  - [hashApiKey](#hashapikey)
  - [makeApiKeyService](#makeapikeyservice)

---

# utils

## ApiKey (interface)

Persistent API key record.

`keyHash` holds the sha256 hex digest of the full plaintext key (prefix
included) — the plaintext itself is NEVER stored. `start` keeps the first
six characters of the key's random portion so dashboards can display a
recognizable fragment without revealing the secret.

**Signature**

```ts
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
  /** Per-key rate limit configuration, enforced by `verifyWithRateLimit` */
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
  readonly createdAt: number;
  readonly updatedAt: number;
}
```

## ApiKeyConfig (interface)

API key service configuration

**Signature**

```ts
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
```

## ApiKeyCreateOptions (interface)

Options for creating an API key

**Signature**

```ts
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
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
}
```

## ApiKeyCreateResult (interface)

Result of creating an API key. `key` is the full plaintext key
(prefix + secret) and is shown exactly once — it is never stored.

**Signature**

```ts
export interface ApiKeyCreateResult {
  readonly key: string;
  readonly apiKey: ApiKey;
}
```

## ApiKeyError (class)

API key error

**Signature**

```ts
export declare class ApiKeyError
```

## ApiKeyService

**Signature**

```ts
export declare const ApiKeyService: typeof ApiKeyServiceTag;
```

## ApiKeyService (interface)

API key service

**Signature**

```ts
export interface ApiKeyService {
  /**
   * Create a new API key for a user. Returns the plaintext key (shown once)
   * alongside the stored record. Fails with {@link ApiKeyError} when the
   * user already holds `maxKeysPerUser` keys.
   */
  readonly create: (
    userId: string,
    options?: ApiKeyCreateOptions,
  ) => Effect.Effect<ApiKeyCreateResult, ApiKeyError | Errors.AuthError, ApiKeyStoreTag>;

  /**
   * Verify a plaintext API key: sha256 hash lookup, then enabled / expiry /
   * remaining-uses / permission checks. On success `remaining` is
   * decremented (when set) and `lastUsedAt` is updated. `requiredPermissions`
   * maps resource → actions; every listed action must be granted on the key.
   */
  readonly verify: (
    plaintextKey: string,
    requiredPermissions?: Record<string, readonly string[]>,
  ) => Effect.Effect<ApiKeyVerifyResult, Errors.AuthError, ApiKeyStoreTag>;

  /**
   * Like `verify`, but when the key carries a `rateLimit` configuration a
   * token is consumed from the {@link RateLimiterTag} bucket keyed
   * `api-key:${apiKey.id}` before the remaining checks run. When the limit
   * is exhausted the result is `{ valid: false, error: "Rate limit exceeded" }`.
   */
  readonly verifyWithRateLimit: (
    plaintextKey: string,
    requiredPermissions?: Record<string, readonly string[]>,
  ) => Effect.Effect<
    ApiKeyVerifyResult,
    Errors.AuthError,
    ApiKeyStoreTag | RateLimiterTag | RateLimitStoreTag
  >;

  /**
   * Fetch a key by id, failing with {@link ApiKeyError} when it does not exist.
   */
  readonly get: (
    keyId: string,
  ) => Effect.Effect<ApiKey, ApiKeyError | Errors.AuthError, ApiKeyStoreTag>;

  /**
   * List all keys belonging to a user.
   */
  readonly list: (
    userId: string,
  ) => Effect.Effect<readonly ApiKey[], Errors.AuthError, ApiKeyStoreTag>;

  /**
   * Update a key on behalf of a user. Fails with {@link ApiKeyError} when the
   * key does not exist or belongs to a different user.
   */
  readonly update: (
    userId: string,
    keyId: string,
    updates: ApiKeyUpdate,
  ) => Effect.Effect<ApiKey, ApiKeyError | Errors.AuthError, ApiKeyStoreTag>;

  /**
   * Delete a key on behalf of a user. Fails with {@link ApiKeyError} when the
   * key does not exist or belongs to a different user.
   */
  readonly delete: (
    userId: string,
    keyId: string,
  ) => Effect.Effect<void, ApiKeyError | Errors.AuthError, ApiKeyStoreTag>;

  /**
   * Delete every key of a user whose `expiresAt` is in the past. Returns the
   * number of keys removed. (The store enumerates per user, so run this per
   * user; a store-level sweep job is the right tool for global cleanup.)
   */
  readonly deleteAllExpired: (
    userId: string,
  ) => Effect.Effect<number, Errors.AuthError, ApiKeyStoreTag>;
}
```

## ApiKeyServiceLayer

**Signature**

```ts
export declare const ApiKeyServiceLayer: (
  config?: ApiKeyConfig,
) => Layer.Layer<ApiKeyServiceTag, never, never>;
```

## ApiKeyServiceTag (class)

**Signature**

```ts
export declare class ApiKeyServiceTag
```

## ApiKeyStore

**Signature**

```ts
export declare const ApiKeyStore: typeof ApiKeyStoreTag;
```

## ApiKeyStore (interface)

Storage interface for API keys

**Signature**

```ts
export interface ApiKeyStore {
  readonly create: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
  readonly getById: (id: string) => Effect.Effect<ApiKey | null, Errors.AuthError>;
  readonly getByHash: (keyHash: string) => Effect.Effect<ApiKey | null, Errors.AuthError>;
  readonly update: (apiKey: ApiKey) => Effect.Effect<ApiKey, Errors.AuthError>;
  readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;
  readonly listByUserId: (userId: string) => Effect.Effect<readonly ApiKey[], Errors.AuthError>;
}
```

## ApiKeyStoreTag (class)

**Signature**

```ts
export declare class ApiKeyStoreTag
```

## ApiKeyUpdate (interface)

Fields of an API key that may be changed after creation.

**Signature**

```ts
export interface ApiKeyUpdate {
  readonly name?: string;
  readonly enabled?: boolean;
  readonly expiresAt?: number;
  readonly permissions?: Record<string, readonly string[]>;
  readonly metadata?: Record<string, unknown>;
  readonly remaining?: number;
  readonly rateLimit?: {
    readonly maxRequests: number;
    readonly windowMs: number;
  };
}
```

## ApiKeyVerifyResult (interface)

Result of verifying an API key. Verification failures are reported as
`{ valid: false, error }` rather than typed failures so callers can treat
a bad key as a normal (unauthenticated) outcome.

**Signature**

```ts
export interface ApiKeyVerifyResult {
  readonly valid: boolean;
  readonly apiKey?: ApiKey;
  readonly error?: string;
}
```

## hashApiKey

sha256 hex digest of a plaintext API key. Exposed so stores/tests can
compute lookup hashes without duplicating the hashing scheme.

**Signature**

```ts
export declare const hashApiKey: (plaintextKey: string) => string;
```

## makeApiKeyService

Create an API key service

**Signature**

```ts
export declare const makeApiKeyService: (
  config?: ApiKeyConfig,
) => Effect.Effect<ApiKeyService, never>;
```
