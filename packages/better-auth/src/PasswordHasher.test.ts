import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Exit } from "effect";
import * as P from "effect/Predicate";
import * as Auth from "@thomasfosterau/effect-auth";
import { makeAuth, rowOf, signUp } from "./testing/Fixtures.ts";
import { ALGORITHM, betterAuthHasher } from "./PasswordHasher.ts";

const hasher = betterAuthHasher();

describe("betterAuthHasher", () => {
  it("verifies the hash BetterAuth stored in its account table, bare or prefixed", async () => {
    const { auth, db } = makeAuth();
    const { password } = await signUp(auth);
    const stored = rowOf(db, "account")["password"];
    assert(P.isString(stored), "BetterAuth stored a hash");
    expect(await Effect.runPromise(hasher.verify(password, stored))).toBe(true);
    expect(await Effect.runPromise(hasher.verify("wrong password", stored))).toBe(false);
    expect(await Effect.runPromise(hasher.verify(password, `${ALGORITHM}$${stored}`))).toBe(true);
  });

  it("writes a hash BetterAuth's own verifier accepts", async () => {
    const { auth } = makeAuth();
    const { hash } = await Effect.runPromise(hasher.hash("correct horse battery"));
    const context = await auth.$context;
    expect(await context.password.verify({ hash, password: "correct horse battery" })).toBe(true);
  });

  it("routes prefixed hashes through MultiAlgorithmVerifier beside the core's own", async () => {
    const verifier = Auth.Password.multiAlgorithmVerifier([
      Auth.Password.pbkdf2Hasher({ iterations: 1000 }),
      hasher,
    ]);
    const { hash } = await Effect.runPromise(hasher.hash("correct horse battery"));
    expect(
      await Effect.runPromise(verifier.verify("correct horse battery", `${ALGORITHM}$${hash}`)),
    ).toBe(true);
  });

  it("fails on a hash that is not BetterAuth's, and refuses empty or oversized passwords", async () => {
    const malformed = await Effect.runPromiseExit(hasher.verify("pw", "$argon2id$v=19$m=1"));
    expect(Exit.isFailure(malformed)).toBe(true);
    const { hash } = await Effect.runPromise(hasher.hash("pw-long-enough"));
    expect(await Effect.runPromise(hasher.verify("", hash))).toBe(false);
    expect(await Effect.runPromise(hasher.verify("x".repeat(1025), hash))).toBe(false);
    expect(Exit.isFailure(await Effect.runPromiseExit(hasher.hash("")))).toBe(true);
    expect(Exit.isFailure(await Effect.runPromiseExit(hasher.hash("x".repeat(1025))))).toBe(true);
  });
});
