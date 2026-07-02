import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { RateLimiter as PersistenceRateLimiter } from "effect/unstable/persistence";
import { RateLimiterPersistenceLayer } from "./RateLimitPersistence.js";
import { RateLimiterTag, RateLimitStoreTag, RateLimitPresets } from "./RateLimit.js";
import { RateLimitError } from "./Errors.js";

/**
 * The persistence facade + an in-memory persistence store. The legacy
 * `RateLimitStoreTag` requirement declared on the interface methods is unused by
 * this backend, so a no-op satisfies the type.
 */
const Live = Layer.mergeAll(
  RateLimiterPersistenceLayer.pipe(
    Layer.provide(PersistenceRateLimiter.layer),
    Layer.provide(PersistenceRateLimiter.layerStoreMemory),
  ),
  Layer.succeed(RateLimitStoreTag)(undefined as never),
);

const run = <A, E>(eff: Effect.Effect<A, E, RateLimiterTag | RateLimitStoreTag>) =>
  Effect.runPromise(eff.pipe(Effect.provide(Live)));

describe("RateLimiterPersistenceLayer", () => {
  it("consumeToken allows up to the limit then fails with RateLimitError", async () => {
    const config = { maxRequests: 3, windowMs: 60_000 };
    const result = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiterTag;
        yield* rl.consumeToken("k1", config);
        yield* rl.consumeToken("k1", config);
        yield* rl.consumeToken("k1", config);
        return yield* Effect.catch(rl.consumeToken("k1", config), (e) => Effect.succeed(e));
      }),
    );
    expect(result).toBeInstanceOf(RateLimitError);
    expect((result as RateLimitError).key).toBe("k1");
  });

  it("checkLimit reflects remaining capacity without failing", async () => {
    const config = { maxRequests: 1, windowMs: 60_000 };
    const [before, after] = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiterTag;
        const before = yield* rl.checkLimit("k2", config);
        yield* rl.consumeToken("k2", config);
        const after = yield* rl.checkLimit("k2", config);
        return [before, after] as const;
      }),
    );
    expect(before).toBe(true);
    expect(after).toBe(false);
  });

  it("getRemainingTokens decreases as tokens are consumed", async () => {
    const config = { maxRequests: 2, windowMs: 60_000 };
    const [start, mid, end] = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiterTag;
        const start = yield* rl.getRemainingTokens("k3", config);
        yield* rl.consumeToken("k3", config);
        const mid = yield* rl.getRemainingTokens("k3", config);
        yield* rl.consumeToken("k3", config);
        const end = yield* rl.getRemainingTokens("k3", config);
        return [start, mid, end] as const;
      }),
    );
    expect(start).toBe(2);
    expect(mid).toBe(1);
    expect(end).toBe(0);
  });

  it("keeps working with the existing RateLimitPresets", async () => {
    // RateLimitPresets.login = 5 attempts; the 6th must be rejected.
    const result = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiterTag;
        for (let i = 0; i < 5; i++) {
          yield* rl.consumeToken("login:user", RateLimitPresets.login);
        }
        return yield* Effect.catch(rl.consumeToken("login:user", RateLimitPresets.login), (e) =>
          Effect.succeed(e),
        );
      }),
    );
    expect(result).toBeInstanceOf(RateLimitError);
  });
});
