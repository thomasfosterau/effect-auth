---
title: "KeyValueStores"
description: "API reference for the KeyValueStores module."
---

## KeyValueStores overview

`KeyValueStore`-backed implementations of effect-auth's ephemeral stores.

These stores hold short-lived token/state data (OAuth states, WebAuthn
challenges, rate-limit counters, verification / reset / magic-link tokens,
email OTPs and pending two-factor challenges) — a natural fit for a
key-value backend such as Redis, Cloudflare KV, or an in-memory map.

Each layer requires the `KeyValueStore` service from
`effect/unstable/persistence`; provide any of its backends (e.g.
`KeyValueStore.layerMemory`, `KeyValueStore.layerFileSystem`,
`KeyValueStore.layerSql`) underneath.

Records are serialized as JSON strings. All of these record shapes use
epoch-millisecond numbers for timestamps (no `Date` fields), so plain
`JSON.stringify`/`JSON.parse` roundtrips them; WebAuthn challenge bytes are
base64-encoded.

## Key layout

Every store namespaces its keys, e.g. `oauth-state:${state}` or
`magic-link:token:${token}`.

## Secondary indexes

A key-value store cannot scan by user id or email, so stores with
`deleteByUserId`/`deleteByEmail` maintain a secondary index key (e.g.
`email-verification:user:${userId}` holding a JSON array of live tokens).
The index is updated on create/delete. Tokens that simply expire (without
being read or deleted) leave garbage entries behind until the next
create/delete for the same user/email — this is safe because every
consuming service already checks `expiresAt` before honouring a record.

## Atomicity caveat

`RateLimitStore.increment` (and `EmailOtpStore.incrementAttempts` / the
secondary index updates) are implemented as read-modify-write, which is not
atomic. Unlike a Redis `INCR`, two concurrent increments may both observe
the same count and only bump it once. This is acceptable for the KV
backend's intended use (best-effort rate limiting / attempt counting);
use a backend with atomic counters when strict enforcement is required.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [ChallengeStoreKV](#challengestorekv)
  - [EmailOtpStoreKV](#emailotpstorekv)
  - [EmailVerificationStoreKV](#emailverificationstorekv)
  - [MagicLinkStoreKV](#magiclinkstorekv)
  - [OAuthStateStoreKV](#oauthstatestorekv)
  - [PasswordResetStoreKV](#passwordresetstorekv)
  - [PendingTwoFactorStoreKV](#pendingtwofactorstorekv)
  - [RateLimitStoreKV](#ratelimitstorekv)
  - [layerKV](#layerkv)
  - [makeChallengeStoreKV](#makechallengestorekv)
  - [makeEmailOtpStoreKV](#makeemailotpstorekv)
  - [makeEmailVerificationStoreKV](#makeemailverificationstorekv)
  - [makeMagicLinkStoreKV](#makemagiclinkstorekv)
  - [makeOAuthStateStoreKV](#makeoauthstatestorekv)
  - [makePasswordResetStoreKV](#makepasswordresetstorekv)
  - [makePendingTwoFactorStoreKV](#makependingtwofactorstorekv)
  - [makeRateLimitStoreKV](#makeratelimitstorekv)

---

# utils

## ChallengeStoreKV

WebAuthn `ChallengeStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const ChallengeStoreKV: Layer.Layer<
  ChallengeStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## EmailOtpStoreKV

`EmailOtpStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const EmailOtpStoreKV: Layer.Layer<
  EmailOtpStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## EmailVerificationStoreKV

`EmailVerificationStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const EmailVerificationStoreKV: Layer.Layer<
  EmailVerificationStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## MagicLinkStoreKV

`MagicLinkStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const MagicLinkStoreKV: Layer.Layer<
  MagicLinkStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## OAuthStateStoreKV

`OAuthStateStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const OAuthStateStoreKV: Layer.Layer<
  OAuthStateStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## PasswordResetStoreKV

`PasswordResetStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const PasswordResetStoreKV: Layer.Layer<
  PasswordResetStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## PendingTwoFactorStoreKV

`PendingTwoFactorStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const PendingTwoFactorStoreKV: Layer.Layer<
  PendingTwoFactorStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## RateLimitStoreKV

`RateLimitStore` layer backed by `KeyValueStore`.

**Signature**

```ts
export declare const RateLimitStoreKV: Layer.Layer<
  RateLimitStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## layerKV

Every ephemeral store in one layer, backed by the ambient `KeyValueStore`.

Combine with a persistent backend (e.g. `@effect-auth/sql`'s user/session
stores) for a complete auth stack.

**Signature**

```ts
export declare const layerKV: Layer.Layer<
  | ChallengeStoreTag
  | PendingTwoFactorStoreTag
  | EmailVerificationStoreTag
  | PasswordResetStoreTag
  | RateLimitStoreTag
  | OAuthStateStoreTag
  | MagicLinkStoreTag
  | EmailOtpStoreTag,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeChallengeStoreKV

Build a WebAuthn {@link ChallengeStore} over the ambient `KeyValueStore`.

**Signature**

```ts
export declare const makeChallengeStoreKV: Effect.Effect<
  ChallengeStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeEmailOtpStoreKV

Build an {@link EmailOtpStore} over the ambient `KeyValueStore`.

There is at most one active OTP per email + purpose pair, so the pair is
the key itself and no secondary index is needed. `incrementAttempts` is
read-modify-write (see the module docs on atomicity).

**Signature**

```ts
export declare const makeEmailOtpStoreKV: Effect.Effect<
  EmailOtpStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeEmailVerificationStoreKV

Build an {@link EmailVerificationStore} over the ambient `KeyValueStore`.

`deleteByUserId` is served by a secondary index key per user holding the
user's live tokens (see the module docs for staleness guarantees).

**Signature**

```ts
export declare const makeEmailVerificationStoreKV: Effect.Effect<
  EmailVerificationStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeMagicLinkStoreKV

Build a {@link MagicLinkStore} over the ambient `KeyValueStore`.

`deleteByEmail` is served by a secondary index key per email address.

**Signature**

```ts
export declare const makeMagicLinkStoreKV: Effect.Effect<
  MagicLinkStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeOAuthStateStoreKV

Build an {@link OAuthStateStore} over the ambient `KeyValueStore`.

**Signature**

```ts
export declare const makeOAuthStateStoreKV: Effect.Effect<
  OAuthStateStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makePasswordResetStoreKV

Build a {@link PasswordResetStore} over the ambient `KeyValueStore`.

`deleteByUserId` is served by a secondary index key per user.

**Signature**

```ts
export declare const makePasswordResetStoreKV: Effect.Effect<
  PasswordResetStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makePendingTwoFactorStoreKV

Build a {@link PendingTwoFactorStore} over the ambient `KeyValueStore`.

**Signature**

```ts
export declare const makePendingTwoFactorStoreKV: Effect.Effect<
  PendingTwoFactorStore,
  never,
  KeyValueStore.KeyValueStore
>;
```

## makeRateLimitStoreKV

Build a {@link RateLimitStore} over the ambient `KeyValueStore`.

`increment` is read-modify-write and therefore not atomic (see the module
docs) — fine for best-effort limiting, not for strict quota enforcement.
The `ttl` arguments are honoured logically via each entry's `resetAt`
rather than by backend-level expiry, since `KeyValueStore` has no TTL API.

**Signature**

```ts
export declare const makeRateLimitStoreKV: Effect.Effect<
  RateLimitStore,
  never,
  KeyValueStore.KeyValueStore
>;
```
