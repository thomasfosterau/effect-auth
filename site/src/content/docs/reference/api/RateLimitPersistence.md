---
title: "RateLimitPersistence"
description: "API reference for the RateLimitPersistence module."
---

## RateLimitPersistence overview

A {@link RateLimiterTag} implementation backed by
`effect/unstable/persistence`'s `RateLimiter`, so consumers keep the existing
`consumeToken`/`checkLimit` facade but gain the library's tested fixed-window
algorithm and pluggable storage backends (in-memory or Redis for
multi-instance deployments).

Usage (in-memory):

```ts
import { Layer } from "effect";
import { RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";
import { RateLimiterPersistenceLayer } from "effect-auth";

const RateLimiterLive = RateLimiterPersistenceLayer.pipe(
  Layer.provide(PersistenceRateLimiter.layer),
  Layer.provide(PersistenceRateLimiter.layerStoreMemory),
);
```

Redis (multi-instance; atomic increments avoid the read-modify-write race of
the KV-backed stores):

```ts
import { Layer } from "effect";
import { Redis, RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";

const RateLimiterRedis = RateLimiterPersistenceLayer.pipe(
  Layer.provide(PersistenceRateLimiter.layer),
  Layer.provide(
    Layer.effect(PersistenceRateLimiter.RateLimiterStore, PersistenceRateLimiter.makeStoreRedis()),
  ),
  Layer.provide(Redis.layer({ url: process.env.REDIS_URL! })),
);
```

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [RateLimiterPersistenceLayer](#ratelimiterpersistencelayer)
  - [makeRateLimiterPersistence](#makeratelimiterpersistence)

---

# utils

## RateLimiterPersistenceLayer

A `Layer<RateLimiterTag, never, PersistenceRateLimiter.RateLimiter>`. Provide
`PersistenceRateLimiter.layer` plus a store (`layerStoreMemory` or a Redis
store) to obtain a runnable limiter (see the module docs for examples).

**Signature**

```ts
export declare const RateLimiterPersistenceLayer: Layer.Layer<
  RateLimiterTag,
  never,
  PersistenceRateLimiter.RateLimiter
>;
```

## makeRateLimiterPersistence

Build the facade over the persistence limiter. The persistence `RateLimiter`
service is captured here so the returned methods keep the interface's
(`RateLimitStoreTag`) requirement satisfiable without touching the legacy
store.

**Signature**

```ts
export declare const makeRateLimiterPersistence: Effect.Effect<
  RateLimiter,
  never,
  PersistenceRateLimiter.RateLimiter
>;
```
