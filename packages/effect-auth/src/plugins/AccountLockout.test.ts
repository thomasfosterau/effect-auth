import { assert, describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { Hooks, type HookError } from "../Hooks.ts";
import {
  AccountLockoutPlugin,
  AccountLockoutStore,
  memoryAccountLockoutStore,
  type AccountLockoutConfig,
  type AccountLockoutRecord,
} from "./AccountLockout.ts";
import { AccountLockedError, AuthError } from "../Errors.ts";
import type { SignInInput, AuthResult } from "../email/EmailPassword.ts";
import type * as Types from "../Types.ts";

const signIn = (email: string): SignInInput => ({ email, password: "pw" });

const authResult = (email: string): AuthResult => ({
  user: {
    id: "u1",
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  } satisfies Types.User,
  identifier: { type: "email", value: email },
});

interface Harness {
  readonly records: Map<string, AccountLockoutRecord>;
  readonly beforeSignIn: (email: string) => Promise<SignInInput>;
  readonly beforeSignInResult: (email: string) => Promise<SignInInput | HookError>;
  readonly afterSignIn: (email: string) => Promise<AuthResult>;
}

const makeHarness = (
  config?: AccountLockoutConfig,
  storeOverride?: typeof AccountLockoutStore.Service,
): Harness => {
  const records = new Map<string, AccountLockoutRecord>();
  const store = storeOverride ?? memoryAccountLockoutStore(records);

  const layer = AccountLockoutPlugin(config).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(Layer.succeed(AccountLockoutStore)(store)),
  );

  const drive = <A, E>(f: (hooks: typeof Hooks.Service) => Effect.Effect<A, E, never>) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* f(hooks);
      }).pipe(Effect.provide(layer)),
    );

  return {
    records,
    beforeSignIn: (email) => drive((hooks) => hooks.beforeSignIn(signIn(email))),
    beforeSignInResult: (email) =>
      drive((hooks) => Effect.catch(hooks.beforeSignIn(signIn(email)), (e) => Effect.succeed(e))),
    afterSignIn: (email) => drive((hooks) => hooks.afterSignIn(authResult(email))),
  };
};

describe("AccountLockoutPlugin", () => {
  it("locks the identifier after maxAttempts failed attempts", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });

    // The first three sign-in attempts pass through the hook (the credential
    // check happens downstream); the counter climbs to the limit.
    await h.beforeSignIn("user@example.com");
    await h.beforeSignIn("user@example.com");
    await h.beforeSignIn("user@example.com");

    // The next attempt is short-circuited while locked.
    const blocked = await h.beforeSignInResult("user@example.com");
    expect(blocked).toBeInstanceOf(AccountLockedError);
  });

  it("unlocks once the lockout window elapses", async () => {
    const h = makeHarness({ maxAttempts: 2, lockoutDurationMs: 60_000 });
    await h.beforeSignIn("user@example.com");
    await h.beforeSignIn("user@example.com");
    expect(await h.beforeSignInResult("user@example.com")).toBeInstanceOf(AccountLockedError);

    // Simulate the window elapsing by moving the lock into the past.
    const key = "lockout:user@example.com";
    const rec = h.records.get(key);
    assert(rec !== undefined, "the lock is recorded");

    h.records.set(key, { ...rec, lockedUntil: Date.now() - 1 });

    // Now allowed again (counter reset to a fresh streak).
    const allowed = await h.beforeSignInResult("user@example.com");
    expect(allowed).not.toBeInstanceOf(AccountLockedError);
    expect(h.records.get(key)?.failures).toBe(1);
  });

  it("resets the counter on a successful sign-in", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });
    await h.beforeSignIn("user@example.com");
    await h.beforeSignIn("user@example.com");
    expect(h.records.get("lockout:user@example.com")?.failures).toBe(2);

    await h.afterSignIn("user@example.com");
    expect(h.records.has("lockout:user@example.com")).toBe(false);

    // A fresh streak starts from zero, so the identifier is nowhere near locked.
    await h.beforeSignIn("user@example.com");
    expect(h.records.get("lockout:user@example.com")?.failures).toBe(1);
  });

  it("keys by normalized email (case/whitespace-insensitive)", async () => {
    const h = makeHarness({ maxAttempts: 5, lockoutDurationMs: 60_000 });
    await h.beforeSignIn("User@Example.com");
    await h.beforeSignIn("  user@example.com ");
    expect(h.records.get("lockout:user@example.com")?.failures).toBe(2);
  });

  it("concurrent attempts do not lose increments (atomic registerAttempt)", async () => {
    const records = new Map<string, AccountLockoutRecord>();
    const store = memoryAccountLockoutStore(records);
    const options = { maxAttempts: 100, lockoutDurationMs: 60_000, now: Date.now() };

    await Effect.runPromise(
      Effect.all(
        Array.from({ length: 25 }, () => store.registerAttempt("lockout:burst", options)),
        { concurrency: "unbounded" },
      ),
    );

    expect(records.get("lockout:burst")?.failures).toBe(25);
  });

  it("registerAttempt does not increment or extend an active lock", async () => {
    const records = new Map<string, AccountLockoutRecord>();
    const store = memoryAccountLockoutStore(records);
    const now = Date.now();
    records.set("lockout:k", { failures: 5, lockedUntil: now + 60_000 });

    const result = await Effect.runPromise(
      store.registerAttempt("lockout:k", { maxAttempts: 5, lockoutDurationMs: 60_000, now }),
    );

    expect(result).toEqual({ failures: 5, lockedUntil: now + 60_000 });
  });

  it("a delete failure after a successful sign-in is isolated (does not abort)", async () => {
    const records = new Map<string, AccountLockoutRecord>();
    const flaky: typeof AccountLockoutStore.Service = {
      ...memoryAccountLockoutStore(records),
      delete: () => Effect.fail(new AuthError({ message: "store down" })),
    };
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 }, flaky);

    // The tap swallows the store error; the successful sign-in result flows on.
    const result = await h.afterSignIn("user@example.com");
    expect(result.identifier).toEqual({ type: "email", value: "user@example.com" });
  });

  it("fails closed by default when the store errors during beforeSignIn", async () => {
    const broken: typeof AccountLockoutStore.Service = {
      get: () => Effect.fail(new AuthError({ message: "store down" })),
      registerAttempt: () => Effect.fail(new AuthError({ message: "store down" })),
      delete: () => Effect.void,
    };
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 }, broken);

    const result = await h.beforeSignInResult("user@example.com");
    expect(result).toBeInstanceOf(AuthError);
  });

  it("onStoreError: 'fail-open' lets the sign-in proceed when the store errors", async () => {
    const broken: typeof AccountLockoutStore.Service = {
      get: () => Effect.fail(new AuthError({ message: "store down" })),
      registerAttempt: () => Effect.fail(new AuthError({ message: "store down" })),
      delete: () => Effect.void,
    };
    const h = makeHarness(
      { maxAttempts: 3, lockoutDurationMs: 60_000, onStoreError: "fail-open" },
      broken,
    );

    const result = await h.beforeSignInResult("user@example.com");
    expect(result).not.toBeInstanceOf(AuthError);
    expect(result).toEqual(signIn("user@example.com"));
  });
});
