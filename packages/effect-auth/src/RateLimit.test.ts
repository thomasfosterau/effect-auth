import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { make, type RateLimitConfig, type RateLimitEntry, RateLimitStore } from "./RateLimit.ts";
import { RateLimitError } from "./Errors.ts";

/** A `RateLimitStore` over a plain map, seeded with `entries`. */
const makeStore = (...entries: ReadonlyArray<RateLimitEntry>) => {
  const stored = new Map<string, RateLimitEntry>(entries.map((entry) => [entry.key, entry]));
  const layer = Layer.succeed(RateLimitStore)({
    get: (key) => Effect.succeed(stored.get(key) ?? null),
    set: (key, entry) =>
      Effect.sync(() => {
        stored.set(key, entry);
      }),
    increment: (key) =>
      Effect.sync(() => {
        const entry = stored.get(key);
        const count = (entry?.count ?? 0) + 1;
        if (entry !== undefined) stored.set(key, { ...entry, count });
        return count;
      }),
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
