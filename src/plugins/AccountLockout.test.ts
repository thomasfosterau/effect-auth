import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { Hooks, type HookError } from "../Hooks.js";
import {
  AccountLockoutPlugin,
  AccountLockoutStore,
  type AccountLockoutRecord,
} from "./AccountLockout.js";
import { AccountLockedError } from "../Errors.js";
import type { SignInInput, AuthResult } from "../email/EmailPassword.js";
import type * as Types from "../Types.js";

const signIn = (email: string): SignInInput => ({ email, password: "pw" });

const authResult = (email: string): AuthResult => ({
  user: {
    id: "u1",
    email,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  } satisfies Types.User,
});

interface Harness {
  readonly records: Map<string, AccountLockoutRecord>;
  readonly beforeSignIn: (email: string) => Promise<SignInInput>;
  readonly beforeSignInResult: (email: string) => Promise<SignInInput | HookError>;
  readonly afterSignIn: (email: string) => Promise<AuthResult>;
}

const makeHarness = (config?: { maxAttempts?: number; lockoutDurationMs?: number }): Harness => {
  const records = new Map<string, AccountLockoutRecord>();
  const store: typeof AccountLockoutStore.Service = {
    get: (key) => Effect.sync(() => records.get(key) ?? null),
    set: (key, record) => Effect.sync(() => void records.set(key, record)),
    delete: (key) => Effect.sync(() => void records.delete(key)),
  };

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
    const rec = h.records.get(key)!;
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
});
