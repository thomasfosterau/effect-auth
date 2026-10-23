import { describe, it, expect } from "vite-plus/test";
import { Clock, Duration, Effect, Layer, Result } from "effect";
import { TestClock } from "effect/testing";
import { make, type RateLimitConfig, type RateLimitEntry, RateLimitStore } from "./RateLimit.ts";
import { RateLimitError } from "./Errors.ts";

/**
 * A `RateLimitStore` over a plain map, seeded with `entries`. Every operation
 * yields to the scheduler before it touches the map, so concurrent callers
 * interleave between operations; each operation itself is atomic, as a
 * single-statement SQL upsert or a Durable Object's input gate makes it.
 */
const makeStore = (...entries: ReadonlyArray<RateLimitEntry>) => {
  const stored = new Map<string, RateLimitEntry>(entries.map((entry) => [entry.key, entry]));
  const layer = Layer.succeed(RateLimitStore)({
    get: (key) =>
      Effect.andThen(
        Effect.yieldNow,
        Effect.sync(() => stored.get(key) ?? null),
      ),
    set: (key, entry) =>
      Effect.andThen(
        Effect.yieldNow,
        Effect.sync(() => {
          stored.set(key, entry);
        }),
      ),
    increment: (key, ttlSeconds) =>
      Effect.andThen(
        Effect.yieldNow,
        Effect.flatMap(Clock.currentTimeMillis, (now) =>
          Effect.sync(() => {
            const entry = stored.get(key);
            const next: RateLimitEntry =
              entry === undefined || now >= entry.resetAt
                ? { key, count: 1, resetAt: now + ttlSeconds * 1000 }
                : { ...entry, count: entry.count + 1 };
            stored.set(key, next);
            return next.count;
          }),
        ),
      ),
    delete: (key) =>
      Effect.sync(() => {
        stored.delete(key);
      }),
  });
  return { stored, layer };
};

const checkLimit = (layer: Layer.Layer<RateLimitStore>, key: string, config: RateLimitConfig) =>
  Effect.runPromise(
    Effect.flatMap(make(), (limiter) => limiter.checkLimit(key, config)).pipe(
      Effect.provide(layer),
    ),
  );

const refusal = (layer: Layer.Layer<RateLimitStore>, key: string, config: RateLimitConfig) =>
  Effect.runPromise(
    Effect.flatMap(make(), (limiter) => Effect.flip(limiter.checkLimit(key, config))).pipe(
      Effect.provide(layer),
    ),
  );

const config = { maxRequests: 2, windowMs: 60_000 };
// Far in the future (2100-01-01), so the window is still open.
const OPEN_UNTIL = 4_102_444_800_000;

describe("RateLimiter.checkLimit", () => {
  it("allows a key with no entry", async () => {
    const { layer } = makeStore();
    const result = await checkLimit(layer, "fresh", config);
    expect(result).toBe(true);
  });

  it("allows a key whose window has closed, however many requests it counted", async () => {
    const { layer } = makeStore({ key: "old", count: 99, resetAt: 1 });
    const result = await checkLimit(layer, "old", config);
    expect(result).toBe(true);
  });

  it("allows a key under its limit in an open window", async () => {
    const { layer } = makeStore({ key: "under", count: 1, resetAt: OPEN_UNTIL });
    const result = await checkLimit(layer, "under", config);
    expect(result).toBe(true);
  });

  it("refuses a blocked key until the block lifts", async () => {
    const { layer } = makeStore({
      key: "blocked",
      count: 0,
      resetAt: 1,
      blockedUntil: OPEN_UNTIL,
    });
    const error = await refusal(layer, "blocked", config);
    expect(error).toBeInstanceOf(RateLimitError);
    expect(error).toMatchObject({ key: "blocked" });
  });

  it("refuses a key at its limit without blocking it when no block is configured", async () => {
    const entry: RateLimitEntry = { key: "full", count: 2, resetAt: OPEN_UNTIL };
    const { layer, stored } = makeStore(entry);
    const error = await refusal(layer, "full", config);
    expect(error).toBeInstanceOf(RateLimitError);
    expect(stored.get("full")).toEqual(entry);
  });

  it("blocks a key at its limit when a block duration is configured", async () => {
    const { layer, stored } = makeStore({ key: "full", count: 2, resetAt: OPEN_UNTIL });
    const error = await refusal(layer, "full", { ...config, blockDurationMs: 60_000 });
    expect(error).toBeInstanceOf(RateLimitError);
    expect(stored.get("full")?.blockedUntil).toBeGreaterThan(0);
  });
});

const consume = (layer: Layer.Layer<RateLimitStore>, key: string, config: RateLimitConfig) =>
  Effect.flatMap(make(), (limiter) => limiter.consumeToken(key, config)).pipe(
    Effect.provide(layer),
  );

describe("RateLimiter.consumeToken", () => {
  it("allows up to the limit in a window, then refuses", async () => {
    const { layer } = makeStore();
    const results = await Effect.runPromise(
      Effect.forEach([1, 2, 3], () => Effect.result(consume(layer, "seq", config)), {
        concurrency: 1,
      }),
    );
    expect(results.map(Result.isSuccess)).toEqual([true, true, false]);
  });

  it("allows only the limit when requests arrive concurrently (#455)", async () => {
    const { layer, stored } = makeStore();
    const limit = { maxRequests: 5, windowMs: 60_000 };
    const results = await Effect.runPromise(
      Effect.forEach(
        Array.from({ length: 50 }),
        () => Effect.result(consume(layer, "burst", limit)),
        {
          concurrency: "unbounded",
        },
      ),
    );
    expect(results.filter(Result.isSuccess)).toHaveLength(5);
    expect(stored.get("burst")?.count).toBe(50);
  });

  it("starts a new window once the old one has expired", async () => {
    const { layer } = makeStore({ key: "old", count: 99, resetAt: 1 });
    await Effect.runPromise(consume(layer, "old", config));
  });

  it("refuses a blocked key even after its window has expired", async () => {
    const { layer } = makeStore({ key: "blocked", count: 2, resetAt: 1, blockedUntil: OPEN_UNTIL });
    const error = await Effect.runPromise(Effect.flip(consume(layer, "blocked", config)));
    expect(error).toBeInstanceOf(RateLimitError);
  });

  it("blocks a key that goes over its limit when a block duration is configured", async () => {
    const { layer, stored } = makeStore({ key: "full", count: 2, resetAt: OPEN_UNTIL });
    const error = await Effect.runPromise(
      Effect.flip(consume(layer, "full", { ...config, blockDurationMs: 60_000 })),
    );
    expect(error).toBeInstanceOf(RateLimitError);
    expect(stored.get("full")?.blockedUntil).toBeGreaterThan(0);
  });

  it("reports retryAfter as the Duration until the window resets", async () => {
    const { layer } = makeStore();
    const error = await Effect.runPromise(
      Effect.gen(function* () {
        yield* TestClock.setTime(1_000_000);
        yield* consume(layer, "timed", { maxRequests: 1, windowMs: 60_000 });
        yield* TestClock.adjust("15 seconds");
        return yield* Effect.flip(consume(layer, "timed", { maxRequests: 1, windowMs: 60_000 }));
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(error.retryAfter && Duration.toMillis(error.retryAfter)).toBe(45_000);
  });
});
