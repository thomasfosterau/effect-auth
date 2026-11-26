import { describe, expect, it } from "vite-plus/test";
import { Deferred, Effect, Fiber, Ref } from "effect";
import { TestClock } from "effect/testing";
import * as RemoteJwks from "./RemoteJwks.ts";
import type * as Types from "./Types.ts";

const byKid =
  (kid: string): RemoteJwks.Pick =>
  (keys) =>
    keys.find((key) => key["kid"] === kid);

/** A fetch that answers each call from `answers` in turn, counting calls. */
const scriptedFetch = Effect.fn("scriptedFetch")(function* (
  answers: ReadonlyArray<ReadonlyArray<Types.JsonObject> | "fail">,
) {
  const calls = yield* Ref.make(0);
  const answer = (n: number) => answers[Math.min(n, answers.length - 1)];
  const fetch = Ref.getAndUpdate(calls, (c) => c + 1).pipe(
    Effect.flatMap((n) => {
      const next = answer(n);
      return next === "fail" || next === undefined
        ? Effect.fail("unavailable" as const)
        : Effect.succeed(next);
    }),
  );
  return { fetch, calls: Ref.get(calls) };
});

const run = <A, E>(effect: Effect.Effect<A, E>) =>
  Effect.runPromise(effect.pipe(Effect.provide(TestClock.layer())));

describe("RemoteJwks", () => {
  it("serves cached keys until they go stale, then refetches", () =>
    run(
      Effect.gen(function* () {
        const { fetch, calls } = yield* scriptedFetch([[{ kid: "a" }], [{ kid: "b" }]]);
        const set = yield* RemoteJwks.make(fetch);
        expect(yield* set.key(byKid("a"))).toEqual({ kid: "a" });
        expect(yield* set.key(byKid("a"))).toEqual({ kid: "a" });
        expect(yield* calls).toBe(1);
        yield* TestClock.adjust("6 minutes");
        expect(yield* set.key(byKid("b"))).toEqual({ kid: "b" });
        expect(yield* calls).toBe(2);
      }),
    ));

  it("refetches for unknown kids at most once per interval", () =>
    run(
      Effect.gen(function* () {
        const { fetch, calls } = yield* scriptedFetch([[{ kid: "a" }]]);
        const set = yield* RemoteJwks.make(fetch);
        yield* set.key(byKid("a"));
        const forged = yield* Effect.forEach(
          ["forged-1", "forged-2", "forged-3"],
          (kid) => set.key(byKid(kid)),
          { concurrency: 1 },
        );
        expect(forged).toEqual([undefined, undefined, undefined]);
        // The first refetch is inside the interval of the initial fetch.
        expect(yield* calls).toBe(1);
        yield* TestClock.adjust("31 seconds");
        yield* set.key(byKid("forged-4"));
        yield* set.key(byKid("forged-5"));
        expect(yield* calls).toBe(2);
      }),
    ));

  it("keeps serving known keys when a refetch fails", () =>
    run(
      Effect.gen(function* () {
        const { fetch, calls } = yield* scriptedFetch([[{ kid: "a" }], "fail"]);
        const set = yield* RemoteJwks.make(fetch);
        yield* set.key(byKid("a"));
        yield* TestClock.adjust("6 minutes");
        expect(yield* set.key(byKid("a"))).toEqual({ kid: "a" });
        expect(yield* calls).toBe(2);
        // The failed attempt starts the interval too: no fetch per request.
        expect(yield* set.key(byKid("a"))).toEqual({ kid: "a" });
        expect(yield* calls).toBe(2);
      }),
    ));

  it("fails when no key is known and the fetch fails", () =>
    run(
      Effect.gen(function* () {
        const { fetch } = yield* scriptedFetch(["fail"]);
        const set = yield* RemoteJwks.make(fetch);
        expect(yield* Effect.flip(set.key(byKid("a")))).toBe("unavailable");
      }),
    ));

  it("shares one fetch between concurrent lookups", () =>
    run(
      Effect.gen(function* () {
        const gate = yield* Deferred.make<void>();
        const calls = yield* Ref.make(0);
        const fetch = Ref.update(calls, (c) => c + 1).pipe(
          Effect.andThen(Deferred.await(gate)),
          Effect.as<ReadonlyArray<Types.JsonObject>>([{ kid: "a" }]),
        );
        const set = yield* RemoteJwks.make(fetch);
        const fibers = yield* Effect.forEach(
          Array.from({ length: 5 }),
          () => Effect.forkChild(set.key(byKid("a"))),
          { concurrency: 1 },
        );
        yield* Effect.yieldNow;
        yield* Deferred.succeed(gate, undefined);
        const keys = yield* Fiber.joinAll(fibers);
        expect(keys).toEqual(Array.from({ length: 5 }, () => ({ kid: "a" })));
        expect(yield* Ref.get(calls)).toBe(1);
      }),
    ));

  it("keeps one key set per URL", () =>
    run(
      Effect.gen(function* () {
        const sets = yield* RemoteJwks.makeKeySets();
        const { fetch } = yield* scriptedFetch([[{ kid: "a" }]]);
        const first = yield* sets.forUrl("https://a.test/jwks", fetch);
        const again = yield* sets.forUrl("https://a.test/jwks", fetch);
        const other = yield* sets.forUrl("https://b.test/jwks", fetch);
        expect(again).toBe(first);
        expect(other).not.toBe(first);
      }),
    ));
});
