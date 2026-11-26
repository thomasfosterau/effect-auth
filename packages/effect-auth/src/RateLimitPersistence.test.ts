import { assert, describe, it, expect } from "vite-plus/test";
import { Duration, Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import { RateLimiter as PersistenceRateLimiter } from "effect/persistence";
import { TestClock } from "effect/testing";
import * as RateLimitPersistence from "./RateLimitPersistence.ts";
import {
  RATE_LIMIT_EXCEEDED_MESSAGE,
  RateLimiter,
  RateLimitStore,
  RateLimitPresets,
} from "./RateLimit.ts";
import { RateLimitError } from "./Errors.ts";

/**
 * The persistence facade + an in-memory persistence store. The legacy
 * `RateLimitStoreTag` requirement declared on the interface methods is unused by
 * this backend, so a no-op satisfies the type.
 */
const Live = Layer.mergeAll(
  RateLimitPersistence.rateLimiterPersistenceLayer.pipe(
    Layer.provide(PersistenceRateLimiter.layer),
    Layer.provide(PersistenceRateLimiter.layerStoreMemory),
  ),
  // SAFETY: this backend never reads `RateLimitStore`; only the interface's
  // legacy requirement asks for it.
  Layer.mock(RateLimitStore, {}),
);

const run = <A, E>(eff: Effect.Effect<A, E, RateLimiter | RateLimitStore>) =>
  Effect.runPromise(eff.pipe(Effect.provide(Live)));

describe("RateLimitPersistence.rateLimiterPersistenceLayer", () => {
  it("consumeToken allows up to the limit then fails with RateLimitError", async () => {
    const config = { maxRequests: 3, windowMs: 60_000 };
    const result = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiter;
        yield* rl.consumeToken("k1", config);
        yield* rl.consumeToken("k1", config);
        yield* rl.consumeToken("k1", config);
        return yield* Effect.catch(rl.consumeToken("k1", config), (e) => Effect.succeed(e));
      }),
    );
    assert.instanceOf(result, RateLimitError);
    expect(result.key).toBe("k1");
    // The same Duration RateLimit.make reports: at most the window, not a bare number.
    assert.isTrue(result.retryAfter !== undefined && Duration.isDuration(result.retryAfter));
    expect(Duration.toMillis(result.retryAfter ?? Duration.zero)).toBeLessThanOrEqual(60_000);
    expect(Duration.toMillis(result.retryAfter ?? Duration.zero)).toBeGreaterThan(0);
  });

  it("checkLimit reflects remaining capacity without failing", async () => {
    const config = { maxRequests: 1, windowMs: 60_000 };
    const [before, after] = await run(
      Effect.gen(function* () {
        const rl = yield* RateLimiter;
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
        const rl = yield* RateLimiter;
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
        const rl = yield* RateLimiter;
        yield* Effect.forEach(
          Arr.range(1, 5),
          () => rl.consumeToken("login:user", RateLimitPresets.login),
          { concurrency: 1, discard: true },
        );
        return yield* Effect.catch(rl.consumeToken("login:user", RateLimitPresets.login), (e) =>
          Effect.succeed(e),
        );
      }),
    );
    expect(result).toBeInstanceOf(RateLimitError);
  });

  it("applies blockDurationMs: the key stays refused after its window resets, until the block ends", async () => {
    const config = { maxRequests: 2, windowMs: 60_000, blockDurationMs: 600_000 };
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        const rl = yield* RateLimiter;
        const attempt = Effect.match(rl.consumeToken("blocked", config), {
          onFailure: (e) => (e instanceof RateLimitError ? e : "fault"),
          onSuccess: () => "ok" as const,
        });
        yield* TestClock.setTime(1_000_000);
        const first = [yield* attempt, yield* attempt, yield* attempt];
        // Past the window, inside the block.
        yield* TestClock.adjust(Duration.minutes(2));
        const inBlock = yield* attempt;
        const remaining = yield* rl.getRemainingTokens("blocked", config);
        const checked = yield* Effect.flip(rl.checkLimit("blocked", config));
        // Past the block.
        yield* TestClock.adjust(Duration.minutes(9));
        const after = yield* attempt;
        return { first, inBlock, remaining, checked, after };
      }).pipe(Effect.provide(Layer.mergeAll(Live, TestClock.layer()))),
    );
    expect(outcomes.first.slice(0, 2)).toEqual(["ok", "ok"]);
    const refused = outcomes.first[2];
    assert.instanceOf(refused, RateLimitError);
    expect(Duration.toMillis(refused.retryAfter ?? Duration.zero)).toBe(600_000);
    assert.instanceOf(outcomes.inBlock, RateLimitError);
    expect(Duration.toMillis(outcomes.inBlock.retryAfter ?? Duration.zero)).toBe(480_000);
    expect(outcomes.remaining).toBe(0);
    expect(outcomes.checked._tag).toBe("RateLimitError");
    expect(outcomes.after).toBe("ok");
  });

  it("without blockDurationMs, admits the key again once its window resets", async () => {
    const config = { maxRequests: 1, windowMs: 60_000 };
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        const rl = yield* RateLimiter;
        const attempt = Effect.match(rl.consumeToken("unblocked", config), {
          onFailure: () => "refused" as const,
          onSuccess: () => "ok" as const,
        });
        yield* TestClock.setTime(1_000_000);
        const first = [yield* attempt, yield* attempt];
        yield* TestClock.adjust(Duration.minutes(2));
        return [...first, yield* attempt];
      }).pipe(Effect.provide(Layer.mergeAll(Live, TestClock.layer()))),
    );
    expect(outcomes).toEqual(["ok", "refused", "ok"]);
  });

  it("refuses with a fixed message that names no key", async () => {
    const config = { maxRequests: 0, windowMs: 60_000 };
    const error = await run(
      Effect.flip(
        Effect.gen(function* () {
          const rl = yield* RateLimiter;
          yield* rl.consumeToken("ip:signin:203.0.113.7", config);
        }),
      ),
    );
    expect(error.message).toBe(RATE_LIMIT_EXCEEDED_MESSAGE);
    expect(error.message).not.toContain("203.0.113.7");
  });
});
