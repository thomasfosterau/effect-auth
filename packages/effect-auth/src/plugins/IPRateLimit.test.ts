import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, DateTime, Effect, Layer } from "effect";
import { ClientIP } from "../ClientIP.ts";
import { Hooks } from "../Hooks.ts";
import type { SignInInput } from "../email/EmailPassword.ts";
import { RateLimitError } from "../Errors.ts";
import { RateLimiter, RateLimitStore, type RateLimitEntry } from "../RateLimit.ts";
import { IPRateLimitPlugin } from "./IPRateLimit.ts";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/** In-memory rate-limit store backed by a simple Map (pass one to inspect it). */
const makeMemStore = (
  store: Map<string, RateLimitEntry> = new Map(),
): typeof RateLimitStore.Service => {
  return {
    get: (key) => Effect.succeed(store.get(key) ?? null),
    set: (key, entry) =>
      Effect.sync(() => {
        store.set(key, entry);
      }),
    increment: (key, ttlSec) =>
      Effect.sync(() => {
        const now = DateTime.toEpochMillis(DateTime.nowUnsafe());
        const existing = store.get(key);
        if (!existing || now >= existing.resetAt) {
          const entry: RateLimitEntry = { key, count: 1, resetAt: now + ttlSec * 1000 };
          store.set(key, entry);
          return 1;
        }
        const updated = { ...existing, count: existing.count + 1 };
        store.set(key, updated);
        return updated.count;
      }),
    delete: (key) =>
      Effect.sync(() => {
        store.delete(key);
      }),
  };
};

/**
 * Build the Hooks layer (without ClientIP — that is provided per-call at
 * runtime, mirroring what the HTTP middleware does).
 */
const makeHooksLayer = (
  cfg?: Parameters<typeof IPRateLimitPlugin>[0],
  entries?: Map<string, RateLimitEntry>,
) => {
  const storeImpl = makeMemStore(entries);
  const storeLayer = Layer.succeed(RateLimitStore, storeImpl);
  const limiterLayer = RateLimiter.layer().pipe(Layer.provide(storeLayer));
  return IPRateLimitPlugin(cfg).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(limiterLayer),
    Layer.provide(storeLayer),
  );
};

const signIn: SignInInput = { email: "u@example.com", password: "pw" };

/**
 * Invoke `hooks.beforeSignIn` with a specific IP in scope.
 * `Effect.provideService(ClientIP, { ip })` simulates what the HTTP middleware
 * does per-request so `Effect.serviceOption(ClientIP)` finds the value.
 */
const callSignIn = (ip: string | undefined) =>
  Effect.gen(function* () {
    const hooks = yield* Hooks;
    return yield* hooks.beforeSignIn(signIn).pipe(
      Effect.provideService(ClientIP, { ip }),
      Effect.map(() => "ok" as const),
      Effect.catchTag("RateLimitError", () => Effect.succeed("limited" as const)),
      Effect.catchTag("AuthError", () => Effect.succeed("ok" as const)),
    );
  });

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("IPRateLimitPlugin", () => {
  it("allows requests within the limit", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // Default sign-in limit: 5 per 15 min
        yield* Effect.forEach(
          Arr.makeBy(5, () => "1.2.3.4"),
          (ip) => callSignIn(ip).pipe(Effect.map((result) => expect(result).toBe("ok"))),
          { concurrency: 1, discard: true },
        );
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("blocks after exceeding the limit", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        yield* Effect.forEach(
          Arr.makeBy(5, () => "5.6.7.8"),
          (ip) => callSignIn(ip).pipe(Effect.map((result) => expect(result).toBe("ok"))),
          { concurrency: 1, discard: true },
        );
        // 6th and 7th attempts should be blocked
        expect(yield* callSignIn("5.6.7.8")).toBe("limited");
        expect(yield* callSignIn("5.6.7.8")).toBe("limited");
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("refuses every request whose ClientIP carries no address, and counts none of them", () => {
    const entries = new Map<string, RateLimitEntry>();
    return Effect.runPromise(
      Effect.gen(function* () {
        // Ten address-less sign-ins: each is refused, none is let through unlimited
        // or counted under a bucket that other callers share (#389).
        yield* Effect.forEach(
          Arr.makeBy(10, () => undefined),
          (ip) => callSignIn(ip).pipe(Effect.map((result) => expect(result).toBe("limited"))),
          { concurrency: 1, discard: true },
        );
        const hooks = yield* Hooks;
        const err = yield* Effect.flip(
          hooks.beforeSignIn(signIn).pipe(Effect.provideService(ClientIP, { ip: undefined })),
        );
        expect(err).toBeInstanceOf(RateLimitError);
        expect(err).toMatchObject({ key: "ip:signin" });
        // None of the refusals touched the store.
        expect([...entries.keys()]).toEqual([]);
        // A visitor with an address is still keyed on their own budget.
        expect(yield* callSignIn("198.51.100.4")).toBe("ok");
        expect([...entries.keys()]).toEqual(["ip:signin:198.51.100.4"]);
      }).pipe(Effect.provide(makeHooksLayer(undefined, entries))),
    );
  });

  it("refuses every request when the ClientIP service is absent (a hook run outside HTTP)", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // No ClientIP service: there is no address to key on, so each hook is
        // refused, never let through unlimited (#389).
        const hooks = yield* Hooks;
        yield* Effect.forEach(
          [
            hooks.beforeSignIn(signIn),
            hooks.beforeSignUp(signIn),
            hooks.beforeRequestPasswordReset({ email: signIn.email }),
          ],
          (run) =>
            Effect.flip(run).pipe(
              Effect.map((err) => {
                expect(err).toBeInstanceOf(RateLimitError);
                expect(err.message).toBe(
                  "No ClientIP service in scope; this request cannot be rate limited",
                );
              }),
            ),
          { concurrency: 1, discard: true },
        );
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("limits different IPs independently", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // Exhaust ip1's limit (5 requests)
        yield* Effect.forEach(
          Arr.makeBy(5, () => "10.0.0.1"),
          callSignIn,
          {
            concurrency: 1,
            discard: true,
          },
        );
        // ip1 is now limited, ip2 is not
        expect(yield* callSignIn("10.0.0.1")).toBe("limited");
        expect(yield* callSignIn("10.0.0.2")).toBe("ok");
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("fails with RateLimitError when limit exceeded", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;

        // Exhaust the limit
        yield* Effect.forEach(
          Arr.makeBy(5, () => signIn),
          (input) =>
            hooks
              .beforeSignIn(input)
              .pipe(Effect.provideService(ClientIP, { ip: "9.9.9.9" }), Effect.ignore),
          { concurrency: 1, discard: true },
        );

        // 6th attempt should fail with RateLimitError
        const err = yield* Effect.flip(
          hooks.beforeSignIn(signIn).pipe(Effect.provideService(ClientIP, { ip: "9.9.9.9" })),
        );

        expect(err).toBeInstanceOf(RateLimitError);
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("applies custom rate limit config", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // Custom: only 2 sign-in attempts allowed
        const call = callSignIn("3.3.3.3");
        expect(yield* call).toBe("ok");
        expect(yield* call).toBe("ok");
        expect(yield* call).toBe("limited"); // 3rd attempt exceeds limit of 2
      }).pipe(
        Effect.provide(makeHooksLayer({ signIn: { maxRequests: 2, windowMs: 60 * 60 * 1000 } })),
      ),
    ));
});
