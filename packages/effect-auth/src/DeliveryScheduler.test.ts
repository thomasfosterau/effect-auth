import { describe, it, expect } from "vite-plus/test";
import { Deferred, Effect, Layer, Metric } from "effect";
import { DeliveryScheduler, makeDetachedSend } from "./DeliveryScheduler.ts";
import { AuthError } from "./Errors.ts";
import { type DeliveryFailure, Hooks, makePlugin } from "./Hooks.ts";
import * as Obs from "./Observability.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";

/** Hooks that record every `afterDeliveryFailure` they see. */
const recordingHooks = () => {
  const failures: DeliveryFailure[] = [];
  const layer = makePlugin({
    afterDeliveryFailure: Hooks.tap((failure: DeliveryFailure) =>
      Effect.sync(() => void failures.push(failure)),
    ),
  }).pipe(Layer.provide(Hooks.Default));
  return { failures, layer };
};

const failureCount = (purpose: string) =>
  Effect.map(
    Metric.value(Metric.withAttributes(Obs.deliverySends, { purpose, outcome: "failure" })),
    (state) => state.count,
  );

describe("makeDetachedSend", () => {
  it("hands the send to the provided scheduler and returns without running it", async () => {
    const scheduled: Array<Effect.Effect<void>> = [];
    let sent = 0;
    const scheduler = Layer.succeed(DeliveryScheduler, {
      schedule: (task) => Effect.sync(() => void scheduled.push(task)),
    });

    await Effect.runPromise(
      Effect.gen(function* () {
        const detached = yield* makeDetachedSend;
        yield* detached(
          "magic-link",
          Effect.sync(() => void sent++),
        );
        expect(scheduled).toHaveLength(1);
        expect(sent).toBe(0);
        yield* Effect.all(scheduled, { concurrency: 1, discard: true });
        expect(sent).toBe(1);
      }).pipe(Effect.provide(scheduler)),
    );
  });

  it("reads the scheduler from the calling fiber, not from where it was built", async () => {
    let scheduled = 0;
    const perRequest = Layer.succeed(DeliveryScheduler, {
      schedule: () => Effect.sync(() => void scheduled++),
    });

    const detached = await Effect.runPromise(makeDetachedSend);
    await Effect.runPromise(
      detached("password-reset", Effect.void).pipe(Effect.provide(perRequest)),
    );

    expect(scheduled).toBe(1);
  });

  it("returns even when the send never finishes, with no scheduler provided", async () => {
    const detached = await Effect.runPromise(makeDetachedSend);

    const outcome = await Promise.race([
      Effect.runPromise(detached("magic-link", Effect.never)).then(() => "returned" as const),
      new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 250)),
    ]);

    expect(outcome).toBe("returned");
  });

  it("never fails the caller; a failed send is counted and reaches afterDeliveryFailure", async () => {
    const hooks = recordingHooks();
    const purpose = "email-otp:forget-password";
    const before = await Effect.runPromise(failureCount(purpose));
    const cause = new AuthError({ message: "provider down" });

    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const detached = yield* makeDetachedSend;
        return yield* detached(purpose, Effect.fail(cause));
      }).pipe(Effect.provide(Layer.merge(hooks.layer, inlineDeliveryScheduler))),
    );

    expect(outcome).toBeUndefined();
    expect(await Effect.runPromise(failureCount(purpose))).toBe(before + 1);
    expect(hooks.failures).toEqual([{ purpose, cause }]);
  });
});

describe("DeliveryScheduler.waitUntil", () => {
  it("passes waitUntil a promise that settles once the send has run", async () => {
    const promises: Array<Promise<unknown>> = [];
    let sent = false;

    await Effect.runPromise(
      Effect.gen(function* () {
        const gate = yield* Deferred.make<void>();
        const detached = yield* makeDetachedSend;
        yield* detached(
          "existing-account",
          Deferred.await(gate).pipe(Effect.andThen(Effect.sync(() => void (sent = true)))),
        );
        expect(promises).toHaveLength(1);
        expect(sent).toBe(false);
        yield* Deferred.succeed(gate, undefined);
      }).pipe(
        Effect.provide(DeliveryScheduler.waitUntil((promise) => void promises.push(promise))),
      ),
    );

    await promises[0];
    expect(sent).toBe(true);
  });
});

describe("DeliveryScheduler.forkDetach", () => {
  it("returns before the send finishes, and the send still runs", async () => {
    let sent = false;

    await Effect.runPromise(
      Effect.gen(function* () {
        const gate = yield* Deferred.make<void>();
        const done = yield* Deferred.make<void>();
        const detached = yield* makeDetachedSend;
        yield* detached(
          "password-reset",
          Deferred.await(gate).pipe(
            Effect.andThen(Effect.sync(() => void (sent = true))),
            Effect.andThen(Deferred.succeed(done, undefined)),
          ),
        );
        expect(sent).toBe(false);
        yield* Deferred.succeed(gate, undefined);
        yield* Deferred.await(done);
      }).pipe(Effect.provide(DeliveryScheduler.forkDetach)),
    );

    expect(sent).toBe(true);
  });
});
