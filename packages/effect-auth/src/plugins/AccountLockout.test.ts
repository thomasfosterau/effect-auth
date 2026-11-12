import { assert, describe, it, expect } from "vite-plus/test";
import { DateTime, Duration, Effect, Layer, MutableHashMap } from "effect";
import * as Option from "effect/Option";
import { Hooks, type AuthenticateAttempt, type HookError } from "../Hooks.ts";
import {
  AccountLockoutPlugin,
  AccountLockoutStore,
  memoryAccountLockoutStore,
  type AccountLockoutConfig,
  type AccountLockoutRecord,
} from "./AccountLockout.ts";
import { AccountLockedError, AuthError } from "../Errors.ts";
import type * as Types from "../Types.ts";

/** A password attempt by email, resolved to `userId` when one is given. */
const byEmail = (email: string, userId?: string): AuthenticateAttempt => ({
  method: "email-password",
  identifier: { type: "email", value: email },
  userId,
});

const session = (userId: string, attributes: Types.Attributes = {}): Types.Session => {
  const now = DateTime.toDateUtc(DateTime.nowUnsafe());
  return {
    id: "raw-token",
    userId,
    expiresAt: now,
    createdAt: now,
    lastActivityAt: now,
    attributes,
  };
};

interface Harness {
  readonly records: MutableHashMap.MutableHashMap<string, AccountLockoutRecord>;
  readonly attempt: (attempt: AuthenticateAttempt) => Promise<AuthenticateAttempt>;
  readonly attemptResult: (
    attempt: AuthenticateAttempt,
  ) => Promise<AuthenticateAttempt | HookError>;
  readonly sessionIssued: (userId: string, attributes?: Types.Attributes) => Promise<Types.Session>;
  readonly failures: (key: string) => number | undefined;
}

const makeHarness = (
  config?: AccountLockoutConfig,
  storeOverride?: typeof AccountLockoutStore.Service,
): Harness => {
  const records = MutableHashMap.empty<string, AccountLockoutRecord>();
  const store = storeOverride ?? memoryAccountLockoutStore(records);

  const layer = AccountLockoutPlugin(config).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(Layer.succeed(AccountLockoutStore)(store)),
  );

  const drive = <A, E>(f: (hooks: typeof Hooks.Service) => Effect.Effect<A, E>) =>
    Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* f(hooks);
      }).pipe(Effect.provide(layer)),
    );

  return {
    records,
    attempt: (attempt) => drive((hooks) => hooks.beforeAuthenticate(attempt)),
    attemptResult: (attempt) =>
      drive((hooks) => Effect.catch(hooks.beforeAuthenticate(attempt), (e) => Effect.succeed(e))),
    sessionIssued: (userId, attributes) =>
      drive((hooks) => hooks.afterCreateSession(session(userId, attributes))),
    failures: (key) => Option.getOrUndefined(MutableHashMap.get(records, key))?.failures,
  };
};

describe("AccountLockoutPlugin", () => {
  it("locks the handle after maxAttempts attempts", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });

    // The first three attempts pass through the hook (the credential check
    // happens downstream); the counter climbs to the limit.
    await h.attempt(byEmail("user@example.com"));
    await h.attempt(byEmail("user@example.com"));
    await h.attempt(byEmail("user@example.com"));

    // The next attempt is short-circuited while locked.
    const blocked = await h.attemptResult(byEmail("user@example.com"));
    expect(blocked).toBeInstanceOf(AccountLockedError);
  });

  it("reports the time left on the lock as a Duration", async () => {
    const h = makeHarness({ maxAttempts: 1, lockoutDurationMs: 60_000 });
    await h.attempt(byEmail("user@example.com"));

    const blocked = await h.attemptResult(byEmail("user@example.com"));
    assert(blocked instanceof AccountLockedError, "the handle is locked");
    assert(blocked.retryAfter !== undefined, "the lock reports its remaining time");
    expect(Duration.toMillis(blocked.retryAfter)).toBeGreaterThan(0);
    expect(Duration.toMillis(blocked.retryAfter)).toBeLessThanOrEqual(60_000);
  });

  it("unlocks once the lockout window elapses", async () => {
    const h = makeHarness({ maxAttempts: 2, lockoutDurationMs: 60_000 });
    await h.attempt(byEmail("user@example.com"));
    await h.attempt(byEmail("user@example.com"));
    expect(await h.attemptResult(byEmail("user@example.com"))).toBeInstanceOf(AccountLockedError);

    // Simulate the window elapsing by moving the lock into the past.
    const key = "lockout:email:user@example.com";
    const rec = Option.getOrUndefined(MutableHashMap.get(h.records, key));
    assert(rec !== undefined, "the lock is recorded");

    MutableHashMap.set(h.records, key, {
      ...rec,
      lockedUntil: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1,
    });

    // Now allowed again (counter reset to a fresh streak).
    const allowed = await h.attemptResult(byEmail("user@example.com"));
    expect(allowed).not.toBeInstanceOf(AccountLockedError);
    expect(h.failures(key)).toBe(1);
  });

  it("keys a resolved handle on the user, so every handle of one account shares one count", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt({
      method: "username",
      identifier: { type: "username", value: "ada" },
      userId: "u1",
    });
    await h.attempt({
      method: "username",
      identifier: { type: "username", value: "ada" },
      userId: "u1",
    });
    expect(h.failures("lockout:user:u1")).toBe(3);

    // Switching handles buys no fresh attempts.
    const blocked = await h.attemptResult({
      method: "username",
      identifier: { type: "username", value: "ada" },
      userId: "u1",
    });
    expect(blocked).toBeInstanceOf(AccountLockedError);
  });

  it("neither counts nor refuses a passkey attempt, even on a locked account (#698)", async () => {
    const h = makeHarness({ maxAttempts: 2, lockoutDurationMs: 60_000 });
    const passkey: AuthenticateAttempt = {
      method: "passkey",
      identifier: { type: "user", value: "u1" },
      userId: "u1",
    };
    const attempts = Array.from({ length: 5 }, () => passkey);
    expect(await Promise.all(attempts.map((attempt) => h.attemptResult(attempt)))).toEqual(
      attempts,
    );
    expect(h.failures("lockout:user:u1")).toBeUndefined();

    // Lock the account with passwords; a passkey still gets through.
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt(byEmail("user@example.com", "u1"));
    expect(await h.attemptResult(byEmail("user@example.com", "u1"))).toBeInstanceOf(
      AccountLockedError,
    );
    expect(await h.attemptResult(passkey)).toEqual(passkey);
  });

  it("neither counts nor refuses a possession proof (one-time code, magic link) (#678)", async () => {
    const h = makeHarness({ maxAttempts: 2, lockoutDurationMs: 60_000 });
    const proofs: ReadonlyArray<AuthenticateAttempt> = [
      {
        method: "email-otp",
        identifier: { type: "email", value: "user@example.com" },
        userId: "u1",
      },
      { method: "phone-otp", identifier: { type: "phone", value: "+15550100" }, userId: "u1" },
      {
        method: "magic-link",
        identifier: { type: "email", value: "user@example.com" },
        userId: "u1",
      },
    ];
    // Not counted: a run of them never locks the account.
    await Promise.all([...proofs, ...proofs].map((proof) => h.attempt(proof)));
    expect(h.failures("lockout:user:u1")).toBeUndefined();

    // Not refused: with the account locked by password attempts, each still passes.
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt(byEmail("user@example.com", "u1"));
    expect(await h.attemptResult(byEmail("user@example.com", "u1"))).toBeInstanceOf(
      AccountLockedError,
    );
    expect(await Promise.all(proofs.map((proof) => h.attemptResult(proof)))).toEqual(proofs);
    // ...and the lock on the password methods stands.
    expect(h.failures("lockout:user:u1")).toBe(2);
  });

  it("lets an unkeyed attempt through without counting it (#678)", async () => {
    const h = makeHarness({ maxAttempts: 1, lockoutDurationMs: 60_000 });
    const unkeyed: AuthenticateAttempt = { method: "second-factor" };
    expect(await h.attemptResult(unkeyed)).toEqual(unkeyed);
    expect(await h.attemptResult({ method: "passkey" })).toEqual({ method: "passkey" });
    expect(MutableHashMap.size(h.records)).toBe(0);
  });

  it("an impersonation session leaves the target's counts standing (#678)", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.sessionIssued("u1", { impersonatedBy: "admin-1" });
    expect(h.failures("lockout:user:u1")).toBe(2);

    // A session the user earned clears them.
    await h.sessionIssued("u1");
    expect(h.failures("lockout:user:u1")).toBeUndefined();
  });

  it("resets the counts only when a session is issued for the user", async () => {
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 });
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt(byEmail("user@example.com", "u1"));
    await h.attempt({
      method: "second-factor",
      identifier: { type: "user", value: "u1" },
      userId: "u1",
    });
    expect(h.failures("lockout:user:u1")).toBe(2);
    expect(h.failures("lockout:second-factor:user:u1")).toBe(1);

    await h.sessionIssued("u1");
    expect(MutableHashMap.has(h.records, "lockout:user:u1")).toBe(false);
    expect(MutableHashMap.has(h.records, "lockout:second-factor:user:u1")).toBe(false);

    // A fresh streak starts from zero, so the account is nowhere near locked.
    await h.attempt(byEmail("user@example.com", "u1"));
    expect(h.failures("lockout:user:u1")).toBe(1);
  });

  it("counts second-factor redemptions per user across challenges, apart from first-factor attempts", async () => {
    const h = makeHarness({
      maxAttempts: 5,
      maxSecondFactorAttempts: 2,
      lockoutDurationMs: 60_000,
    });
    const secondFactor: AuthenticateAttempt = {
      method: "second-factor",
      identifier: { type: "user", value: "u1" },
      userId: "u1",
    };
    await h.attempt(secondFactor);
    await h.attempt(secondFactor);

    const blocked = await h.attemptResult(secondFactor);
    assert(blocked instanceof AccountLockedError, "second-factor redemption is locked");
    expect(blocked.message).toMatch(/Second-factor/);

    // The first factor has a count of its own and stays open.
    expect(await h.attemptResult(byEmail("user@example.com", "u1"))).not.toBeInstanceOf(
      AccountLockedError,
    );
  });

  it("concurrent attempts do not lose increments (atomic registerAttempt)", async () => {
    const records = MutableHashMap.empty<string, AccountLockoutRecord>();
    const store = memoryAccountLockoutStore(records);
    const options = {
      maxAttempts: 100,
      lockoutDurationMs: 60_000,
      now: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    };

    await Effect.runPromise(
      Effect.all(
        Array.from({ length: 25 }, () => store.registerAttempt("lockout:burst", options)),
        { concurrency: "unbounded" },
      ),
    );

    expect(Option.getOrUndefined(MutableHashMap.get(records, "lockout:burst"))?.failures).toBe(25);
  });

  it("registerAttempt does not increment or extend an active lock", async () => {
    const records = MutableHashMap.empty<string, AccountLockoutRecord>();
    const store = memoryAccountLockoutStore(records);
    const now = DateTime.toEpochMillis(DateTime.nowUnsafe());
    MutableHashMap.set(records, "lockout:k", { failures: 5, lockedUntil: now + 60_000 });

    const result = await Effect.runPromise(
      store.registerAttempt("lockout:k", { maxAttempts: 5, lockoutDurationMs: 60_000, now }),
    );

    expect(result).toEqual({ failures: 5, lockedUntil: now + 60_000 });
  });

  it("a delete failure after a session is issued is isolated (does not abort)", async () => {
    const records = MutableHashMap.empty<string, AccountLockoutRecord>();
    const flaky: typeof AccountLockoutStore.Service = {
      ...memoryAccountLockoutStore(records),
      delete: () => Effect.fail(new AuthError({ message: "store down" })),
    };
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 }, flaky);

    // The tap swallows the store error; the new session flows on.
    const result = await h.sessionIssued("u1");
    expect(result.userId).toBe("u1");
  });

  it("fails closed by default when the store errors during beforeAuthenticate", async () => {
    const broken: typeof AccountLockoutStore.Service = {
      get: () => Effect.fail(new AuthError({ message: "store down" })),
      registerAttempt: () => Effect.fail(new AuthError({ message: "store down" })),
      delete: () => Effect.void,
    };
    const h = makeHarness({ maxAttempts: 3, lockoutDurationMs: 60_000 }, broken);

    const result = await h.attemptResult(byEmail("user@example.com"));
    expect(result).toBeInstanceOf(AuthError);
  });

  it("onStoreError: 'fail-open' lets the attempt proceed when the store errors", async () => {
    const broken: typeof AccountLockoutStore.Service = {
      get: () => Effect.fail(new AuthError({ message: "store down" })),
      registerAttempt: () => Effect.fail(new AuthError({ message: "store down" })),
      delete: () => Effect.void,
    };
    const h = makeHarness(
      { maxAttempts: 3, lockoutDurationMs: 60_000, onStoreError: "fail-open" },
      broken,
    );

    const result = await h.attemptResult(byEmail("user@example.com"));
    expect(result).not.toBeInstanceOf(AuthError);
    expect(result).toEqual(byEmail("user@example.com"));
  });
});
