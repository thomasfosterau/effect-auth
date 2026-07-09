import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { ClientIP } from "../ClientIP.js";
import { Hooks } from "../Hooks.js";
import type { SignInInput } from "../email/EmailPassword.js";
import { RateLimitError } from "../Errors.js";
import {
  RateLimiter,
  RateLimitStore,
  type RateLimitEntry,
  type RateLimitStoreShape,
} from "../RateLimit.js";
import { IPRateLimitPlugin } from "./IPRateLimit.js";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/** In-memory rate-limit store backed by a simple Map. */
const makeMemStore = (): RateLimitStoreShape => {
  const store = new Map<string, RateLimitEntry>();
  return {
    get: (key) => Effect.succeed(store.get(key) ?? null),
    set: (key, entry) =>
      Effect.sync(() => {
        store.set(key, entry);
      }),
    increment: (key, ttlSec) =>
      Effect.sync(() => {
        const now = Date.now();
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
const makeHooksLayer = (cfg?: Parameters<typeof IPRateLimitPlugin>[0]) => {
  const storeImpl = makeMemStore();
  const storeLayer = Layer.succeed(RateLimitStore, storeImpl);
  const limiterLayer = RateLimiter.layer().pipe(Layer.provide(storeLayer));
  return IPRateLimitPlugin(cfg)
    .pipe(Layer.provide(Hooks.Default))
    .pipe(Layer.provide(limiterLayer))
    .pipe(Layer.provide(storeLayer));
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
        for (let i = 0; i < 5; i++) {
          expect(yield* callSignIn("1.2.3.4")).toBe("ok");
        }
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("blocks after exceeding the limit", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        for (let i = 0; i < 5; i++) {
          expect(yield* callSignIn("5.6.7.8")).toBe("ok");
        }
        // 6th and 7th attempts should be blocked
        expect(yield* callSignIn("5.6.7.8")).toBe("limited");
        expect(yield* callSignIn("5.6.7.8")).toBe("limited");
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("is a no-op when ip is undefined (no IP available)", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // All 10 should succeed — nothing to key on
        for (let i = 0; i < 10; i++) {
          expect(yield* callSignIn(undefined)).toBe("ok");
        }
      }).pipe(Effect.provide(makeHooksLayer())),
    ));

  it("limits different IPs independently", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        // Exhaust ip1's limit (5 requests)
        for (let i = 0; i < 5; i++) {
          yield* callSignIn("10.0.0.1");
        }
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
        for (let i = 0; i < 5; i++) {
          yield* hooks
            .beforeSignIn(signIn)
            .pipe(Effect.provideService(ClientIP, { ip: "9.9.9.9" }), Effect.ignore);
        }

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
