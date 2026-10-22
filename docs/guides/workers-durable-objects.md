# Rate limits and sessions on Cloudflare Durable Objects

On Cloudflare Workers no process memory outlives a request, so the in-memory stores (`KeyValueStore.layerMemory`, `RateLimiter`'s `layerStoreMemory`) hold nothing between requests. Workers KV holds data, but it is eventually consistent: a write can take up to a minute to reach other locations, and there is no compare-and-swap. A rate-limit counter on KV therefore loses increments under concurrency. Two requests read the same count, both write count + 1, and a burst gets through that the limit was meant to stop.

A Durable Object fixes that. Every request for one object name goes to the same single instance, wherever in the world it came from. The instance runs one request's storage reads and writes before it delivers the next request (its input gate), so read, decide and write inside one call is atomic. Storage is strongly consistent and persisted.

This guide gives copyable code for three objects:

1. **A strict rate limiter** (§1): effect-auth's `RateLimiter`, built with `rateLimiterPersistenceLayer` over an `effect/persistence` `RateLimiterStore` whose counters live in Durable Objects. Use this one.
2. **The core `RateLimitStore` contract** (§2), for code that reads and writes `RateLimitStore` directly.
3. **A `SessionStore`** (§3), optional.

§4 wires them into a Worker. The code was type-checked against `@cloudflare/workers-types` and the current store contracts. It was then run against a single-process stand-in for the Durable Objects runtime, which serialises calls per object as input gates do; §5 has the details.

## 1. A strict rate limiter

effect-auth has two `RateLimiter` implementations. `RateLimiter.layer()` is built over the `RateLimitStore` contract (§2). It reads the count, decides, and then increments. So concurrent requests at the limit all read the same count and all pass, even when the store's increment is atomic (#455). `rateLimiterPersistenceLayer` is built over `effect/persistence`'s `RateLimiter`, which asks its store for one atomic `fixedWindow` operation and decides from the count that operation returns. Over a Durable Object, that is strict: in the check below, 50 concurrent sign-in attempts against a limit of 5 let exactly 5 through.

One object per key holds the counter. The semantics are those of `effect/persistence`'s in-memory store: each token holds the counter open for one refill interval (window ÷ limit), and a request over the limit is refused without changing the counter.

```ts
// auth-rate-limits.ts
import { DurableObject } from "cloudflare:workers";
import { Duration, Effect, Layer } from "effect";
import { RateLimiter as PersistenceRateLimiter } from "effect/persistence";
import { rateLimiterPersistenceLayer } from "@thomasfosterau/effect-auth";

interface Counter {
  readonly count: number;
  /** When the counter has fully drained: each token holds it open for one refill interval. */
  readonly expiresAt: number;
}

/**
 * One fixed-window counter, addressed by key (`idFromName(key)`). The whole
 * read, decision and write happen inside one call on one object, which runs
 * its storage operations for one request before it delivers the next. So two
 * concurrent requests for the same key can never both see room under the limit.
 * The semantics are those of `effect/persistence`'s in-memory store.
 */
export class FixedWindowCounter extends DurableObject {
  async fixedWindow(
    tokens: number,
    refillRateMillis: number,
    limit: number | undefined,
  ): Promise<{ readonly count: number; readonly ttl: number }> {
    const now = Date.now();
    const stored = await this.ctx.storage.get<Counter>("counter");
    const counter =
      stored === undefined || stored.expiresAt <= now ? { count: 0, expiresAt: now } : stored;
    if (limit !== undefined && limit > 0 && counter.count + tokens > limit) {
      // Over the limit: refused, and the counter is left as it was.
      return { count: counter.count + tokens, ttl: counter.expiresAt - now };
    }
    const next: Counter = {
      count: counter.count + tokens,
      expiresAt: counter.expiresAt + refillRateMillis * tokens,
    };
    await this.ctx.storage.put("counter", next);
    if (next.expiresAt > now) await this.ctx.storage.setAlarm(next.expiresAt);
    return { count: next.count, ttl: next.expiresAt - now };
  }

  // Drained counters delete themselves, so idle keys cost no storage.
  override async alarm(): Promise<void> {
    const counter = await this.ctx.storage.get<Counter>("counter");
    if (counter !== undefined && counter.expiresAt > Date.now()) {
      await this.ctx.storage.setAlarm(counter.expiresAt);
      return;
    }
    await this.ctx.storage.deleteAll();
  }
}

const storeError = (message: string, cause?: unknown) =>
  new PersistenceRateLimiter.RateLimiterError({
    reason: new PersistenceRateLimiter.RateLimitStoreError({ message, cause }),
  });

/**
 * `effect/persistence`'s `RateLimiterStore` over the `FixedWindowCounter`
 * namespace. effect-auth's `rateLimiterPersistenceLayer` uses only the
 * fixed-window algorithm, so the token-bucket and adaptive operations fail
 * with a store error rather than pretend.
 */
export const makeRateLimiterStore = (
  namespace: DurableObjectNamespace<FixedWindowCounter>,
): typeof PersistenceRateLimiter.RateLimiterStore.Service => {
  const unsupported = (operation: string) =>
    Effect.fail(storeError(`${operation} is not supported by the Durable Object store`));
  return {
    fixedWindow: (options) =>
      Effect.tryPromise({
        try: () =>
          namespace
            .get(namespace.idFromName(options.key))
            .fixedWindow(options.tokens, Duration.toMillis(options.refillRate), options.limit),
        catch: (cause) => storeError("fixedWindow failed", cause),
      }).pipe(Effect.map(({ count, ttl }) => [count, ttl] as const)),
    tokenBucket: () => unsupported("tokenBucket"),
    adaptiveConsume: () => unsupported("adaptiveConsume"),
    adaptiveFeedback: () => unsupported("adaptiveFeedback"),
  };
};

/** effect-auth's `RateLimiter`, deciding on Durable Object counters. */
export const rateLimiterLayer = (namespace: DurableObjectNamespace<FixedWindowCounter>) =>
  rateLimiterPersistenceLayer.pipe(
    Layer.provide(PersistenceRateLimiter.layer),
    Layer.provide(
      Layer.succeed(PersistenceRateLimiter.RateLimiterStore, makeRateLimiterStore(namespace)),
    ),
  );
```

effect-auth's facade uses only the fixed-window algorithm, so the store leaves the token-bucket and adaptive operations unimplemented. They fail with a store error, so nothing passes silently. As with the in-memory and Redis stores, the facade's `resetLimit` is a no-op: a counter drains at the end of its window.

## 2. The core `RateLimitStore` contract

Implement this one when your own code, or a plugin, reads and writes `RateLimitStore` directly. One object per key holds the entry. `increment` resets an expired window and counts, atomically, in one call: 100 concurrent increments of one key return 1 through 100. The object deletes itself by alarm once the window and any block are over.

```ts
// auth-rate-limit-store.ts
import { DurableObject } from "cloudflare:workers";
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

/** When an entry can be dropped: its window is over and any block has lapsed. */
const cleanupAt = (entry: Auth.RateLimitEntry): number =>
  Math.max(entry.resetAt, entry.blockedUntil ?? 0);

/**
 * One rate-limit counter. The Worker addresses one object per key
 * (`idFromName(key)`), so every request for a key lands on the same object,
 * and the object runs one request's storage reads and writes before it
 * delivers the next request. That is what makes `increment` atomic.
 */
export class RateLimitCounter extends DurableObject {
  async read(): Promise<Auth.RateLimitEntry | null> {
    return (await this.ctx.storage.get<Auth.RateLimitEntry>("entry")) ?? null;
  }

  async write(entry: Auth.RateLimitEntry, ttlSeconds: number): Promise<void> {
    await this.ctx.storage.put("entry", entry);
    await this.ctx.storage.setAlarm(Math.max(cleanupAt(entry), Date.now() + ttlSeconds * 1000));
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    const now = Date.now();
    const existing = await this.ctx.storage.get<Auth.RateLimitEntry>("entry");
    const entry: Auth.RateLimitEntry =
      existing === undefined || now >= existing.resetAt
        ? { key, count: 1, resetAt: now + ttlSeconds * 1000 }
        : { ...existing, count: existing.count + 1 };
    await this.ctx.storage.put("entry", entry);
    await this.ctx.storage.setAlarm(cleanupAt(entry));
    return entry.count;
  }

  async remove(): Promise<void> {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  // The stored expiry: once the window and any block are over, the object
  // empties itself, so idle keys cost no storage.
  override async alarm(): Promise<void> {
    const entry = await this.ctx.storage.get<Auth.RateLimitEntry>("entry");
    if (entry !== undefined && Date.now() < cleanupAt(entry)) {
      await this.ctx.storage.setAlarm(cleanupAt(entry));
      return;
    }
    await this.ctx.storage.deleteAll();
  }
}

const call = <A>(label: string, run: () => Promise<A>): Effect.Effect<A, Auth.AuthError> =>
  Effect.tryPromise({
    try: run,
    catch: (cause) => new Auth.AuthError({ message: `${label} failed`, cause }),
  });

/** `RateLimitStore` over the `RateLimitCounter` namespace: one object per key. */
export const makeRateLimitStore = (
  namespace: DurableObjectNamespace<RateLimitCounter>,
): typeof Auth.RateLimitStore.Service => {
  const counter = (key: string) => namespace.get(namespace.idFromName(key));
  return {
    get: (key) => call("rateLimit.get", () => counter(key).read()),
    set: (key, entry, ttl) => call("rateLimit.set", () => counter(key).write(entry, ttl)),
    increment: (key, ttl) => call("rateLimit.increment", () => counter(key).increment(key, ttl)),
    delete: (key) => call("rateLimit.delete", () => counter(key).remove()),
  };
};

export const rateLimitStoreLayer = (namespace: DurableObjectNamespace<RateLimitCounter>) =>
  Layer.succeed(Auth.RateLimitStore, makeRateLimitStore(namespace));
```

An exact store does not make `RateLimiter.layer()` strict. That limiter decides before it increments (#455), so use §1 for limits that must hold under concurrency.

## 3. Sessions

Sessions are not counters. Their risk is reading a stale session, for example a revoked one, not losing an update. Any strongly consistent store works, and if you already use D1, `@thomasfosterau/effect-auth-sql` (or effect-auth-alchemy) is the simpler choice. KV is the store to avoid: a deleted session can still be read for up to a minute after sign-out.

To keep sessions in Durable Objects, use two kinds of object:

- **`UserSessions`**, one per user, holds that user's sessions. It is the source of truth, so `listByUserId` and `deleteByUserId` are one object's local reads and writes.
- **`SessionPointer`**, one per session id, records the session's user. `get` and `delete` only know the session id (the token's SHA-256 hash), and the pointer routes them to the right `UserSessions` object.

A session is written before its pointer and deleted before it. A pointer left behind by a failure in between therefore reads as a miss, never as a session that should be gone. Alarms drop expired sessions and pointers. `SessionService` already refuses an expired session, so the alarms are housekeeping, not enforcement.

```ts
// auth-sessions.ts
import { DurableObject } from "cloudflare:workers";
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const sessionKey = (sessionId: string) => `session:${sessionId}`;

/**
 * One user's sessions: the source of truth. Named `user:<userId>`, so
 * `listByUserId` and `deleteByUserId` are one object's local reads and writes.
 */
export class UserSessions extends DurableObject {
  async put(session: Auth.Session): Promise<void> {
    await this.ctx.storage.put(sessionKey(session.id), session);
    await this.scheduleCleanup();
  }

  async read(sessionId: string): Promise<Auth.Session | null> {
    return (await this.ctx.storage.get<Auth.Session>(sessionKey(sessionId))) ?? null;
  }

  async remove(sessionId: string): Promise<void> {
    await this.ctx.storage.delete(sessionKey(sessionId));
  }

  async list(): Promise<ReadonlyArray<Auth.Session>> {
    const sessions = await this.ctx.storage.list<Auth.Session>({ prefix: "session:" });
    return [...sessions.values()];
  }

  /** Delete every session, returning their ids so the caller can clear the pointers. */
  async removeAll(): Promise<ReadonlyArray<string>> {
    const ids = (await this.list()).map((session) => session.id);
    await this.ctx.storage.deleteAll();
    return ids;
  }

  // Expired sessions are dropped by an alarm at the earliest expiry.
  // `SessionService` already refuses an expired session, so this is
  // housekeeping, not enforcement.
  override async alarm(): Promise<void> {
    const now = Date.now();
    const expired = (await this.list()).filter((session) => session.expiresAt.getTime() <= now);
    await this.ctx.storage.delete(expired.map((session) => sessionKey(session.id)));
    await this.scheduleCleanup();
  }

  private async scheduleCleanup(): Promise<void> {
    const expiries = (await this.list()).map((session) => session.expiresAt.getTime());
    if (expiries.length === 0) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.min(...expiries));
  }
}

/**
 * Which user a session id belongs to. Named `session:<sessionId>`. A pointer
 * routes `get` and `delete`, which only know the session id, to the user's
 * object; it is never the source of truth, so a stale pointer reads as a miss.
 */
export class SessionPointer extends DurableObject {
  async read(): Promise<string | null> {
    return (await this.ctx.storage.get<string>("userId")) ?? null;
  }

  async write(userId: string, expiresAt: Date): Promise<void> {
    await this.ctx.storage.put("userId", userId);
    await this.ctx.storage.setAlarm(expiresAt);
  }

  async clear(): Promise<void> {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

const call = <A>(label: string, run: () => Promise<A>): Effect.Effect<A, Auth.AuthError> =>
  Effect.tryPromise({
    try: run,
    catch: (cause) => new Auth.AuthError({ message: `${label} failed`, cause }),
  });

/** `SessionStore` over the `UserSessions` and `SessionPointer` namespaces. */
export const makeSessionStore = (
  users: DurableObjectNamespace<UserSessions>,
  pointers: DurableObjectNamespace<SessionPointer>,
): typeof Auth.SessionStore.Service => {
  const user = (userId: string) => users.get(users.idFromName(`user:${userId}`));
  const pointer = (sessionId: string) => pointers.get(pointers.idFromName(`session:${sessionId}`));

  return {
    // The session first, then its pointer: a `get` that finds the pointer
    // always finds the session.
    create: (session) =>
      call("session.create", async () => {
        await user(session.userId).put(session);
        await pointer(session.id).write(session.userId, session.expiresAt);
        return session;
      }),
    get: (sessionId) =>
      call("session.get", async () => {
        const userId = await pointer(sessionId).read();
        return userId === null ? null : user(userId).read(sessionId);
      }),
    update: (session) =>
      call("session.update", async () => {
        await user(session.userId).put(session);
        await pointer(session.id).write(session.userId, session.expiresAt);
        return session;
      }),
    // The session first, then its pointer: a pointer left behind by a failure
    // in between reads as a miss.
    delete: (sessionId) =>
      call("session.delete", async () => {
        const userId = await pointer(sessionId).read();
        if (userId !== null) await user(userId).remove(sessionId);
        await pointer(sessionId).clear();
      }),
    deleteByUserId: (userId) =>
      call("session.deleteByUserId", async () => {
        const ids = await user(userId).removeAll();
        await Promise.all(ids.map((id) => pointer(id).clear()));
      }),
    listByUserId: (userId) => call("session.listByUserId", () => user(userId).list()),
  };
};

export const sessionStoreLayer = (
  users: DurableObjectNamespace<UserSessions>,
  pointers: DurableObjectNamespace<SessionPointer>,
) => Layer.succeed(Auth.SessionStore, makeSessionStore(users, pointers));
```

This store passes the `SessionStore` conformance suite from `@thomasfosterau/effect-auth/testing` (#341).

## 4. Wiring it into a Worker

Declare the classes and their migrations in the Wrangler config. New Durable Object classes use the SQLite storage backend:

```jsonc
// wrangler.jsonc
{
  "durable_objects": {
    "bindings": [
      { "name": "RATE_LIMITS", "class_name": "FixedWindowCounter" },
      { "name": "USER_SESSIONS", "class_name": "UserSessions" },
      { "name": "SESSION_POINTERS", "class_name": "SessionPointer" },
    ],
  },
  "migrations": [
    { "tag": "v1", "new_sqlite_classes": ["FixedWindowCounter", "UserSessions", "SessionPointer"] },
  ],
}
```

Bindings exist only inside a request, so build the store layers from `env` and provide them wherever the app provides its other stores. The entry module must export the classes:

```ts
// worker.ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { type FixedWindowCounter, rateLimiterLayer } from "./FixedWindowCounter";
import { type SessionPointer, sessionStoreLayer, type UserSessions } from "./SessionObjects";

// The Durable Object classes must be exported from the Worker's entry module.
export { FixedWindowCounter } from "./FixedWindowCounter";
export { SessionPointer, UserSessions } from "./SessionObjects";

interface Env {
  readonly RATE_LIMITS: DurableObjectNamespace<FixedWindowCounter>;
  readonly USER_SESSIONS: DurableObjectNamespace<UserSessions>;
  readonly SESSION_POINTERS: DurableObjectNamespace<SessionPointer>;
}

// Bindings exist only per request, so the store layers are built from `env`.
const authStores = (env: Env) =>
  Layer.mergeAll(
    rateLimiterLayer(env.RATE_LIMITS),
    sessionStoreLayer(env.USER_SESSIONS, env.SESSION_POINTERS),
  );

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    const program = Effect.gen(function* () {
      const limiter = yield* Auth.RateLimiter;
      yield* limiter.consumeToken(`sign-in:${ip}`, { maxRequests: 5, windowMs: 60_000 });
      const sessions = yield* Auth.SessionStore;
      return (yield* sessions.listByUserId("u-1")).length;
    });
    return Effect.runPromise(
      program.pipe(
        Effect.map((count) => Response.json({ sessions: count })),
        Effect.catchTag("RateLimitError", () =>
          Effect.succeed(new Response("Too many requests", { status: 429 })),
        ),
        Effect.provide(authStores(env)),
      ),
    );
  },
} satisfies ExportedHandler<Env>;
```

## 5. How this code was checked

- It type-checks under `strict` and `exactOptionalPropertyTypes`, against `@cloudflare/workers-types` and the published effect-auth types. That covers the RPC stub types, which is why `fixedWindow` returns an object rather than a tuple: RPC does not keep tuple types.
- It was run against a stand-in for the runtime: one instance per name, storage and RPC values copied with `structuredClone`, and one call at a time per object. That last part stands in for the input gate, conservatively. The checks:
  - `rateLimiterPersistenceLayer` allowed exactly 5 of 50 concurrent `consumeToken` calls with `maxRequests: 5`.
  - `getRemainingTokens` reported 0 for the exhausted key and 5 for a fresh one.
  - The `RateLimitStore` returned 1..100 for 100 concurrent increments, reset an expired window, and scheduled its alarm at the window or block end.
  - The `SessionStore` passed all six `sessionStoreConformance` cases.
- It was not run on Cloudflare's runtime. Before relying on the limits, run the same checks in your own Worker test setup (for example `@cloudflare/vitest-pool-workers`).
