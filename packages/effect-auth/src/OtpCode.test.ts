import { sha256Hex } from "./testing/Sha256.ts";
import { describe, expect, it } from "vite-plus/test";
import * as Clock from "effect/Clock";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Arr from "effect/Array";
import { verifyCode, type VerifyFailure } from "./OtpCode.ts";
import type { PhoneOtpPurpose, PhoneOtpStore } from "./PhoneOtp.ts";
import { memoryPhoneOtpStore } from "./testing/MemoryStores.ts";

const phoneNumber = "+15550100";
const purpose: PhoneOtpPurpose = "sign-in";
const code = "123456";

/** A store whose reads yield, as a database round trip does. */
const slowReads = (): typeof PhoneOtpStore.Service => {
  const inner = memoryPhoneOtpStore();
  return {
    ...inner,
    get: (number, kind) => Effect.tap(inner.get(number, kind), () => Effect.yieldNow),
  };
};

const verify = (store: typeof PhoneOtpStore.Service, guess: string) =>
  verifyCode(store, {
    address: phoneNumber,
    code: guess,
    purpose,
    maxAttempts: 3,
    hash: (plain) => Effect.succeed(sha256Hex(plain)),
    reject: (_purpose, reason): Effect.Effect<never, VerifyFailure> => Effect.fail(reason),
  }).pipe(Effect.result);

describe("verifyCode under concurrency", () => {
  it("compares at most maxAttempts of a concurrent burst, so a guess past the cap fails even when right", async () => {
    const store = slowReads();
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        yield* store.upsert({
          phoneNumber,
          purpose,
          otpHash: sha256Hex(code),
          attempts: 0,
          createdAt: now,
          expiresAt: now + 60_000,
        });
        // Nine wrong guesses, then the right one: every guess reads the code
        // before any is counted, as a burst of parallel requests does.
        const guesses = [...Arr.makeBy(9, (i) => String(100_000 + i)), code];
        return yield* Effect.forEach(guesses, (guess) => verify(store, guess), {
          concurrency: "unbounded",
        });
      }),
    );

    // Three guesses were compared (two mismatches, and the third wrong one
    // exhausted the code); every later one was refused uncompared, the right
    // one among them.
    expect(outcomes.filter(Result.isSuccess)).toHaveLength(0);
    const reasons = outcomes.flatMap((outcome) =>
      Result.isFailure(outcome) ? [outcome.failure] : [],
    );
    expect(reasons.filter((reason) => reason === "mismatch")).toHaveLength(2);
    expect(reasons.filter((reason) => reason !== "mismatch")).toHaveLength(8);
  });

  it("still accepts the right code within the cap", async () => {
    const store = slowReads();
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        yield* store.upsert({
          phoneNumber,
          purpose,
          otpHash: sha256Hex(code),
          attempts: 2,
          createdAt: now,
          expiresAt: now + 60_000,
        });
        return yield* verify(store, code);
      }),
    );
    expect(Result.isSuccess(outcome)).toBe(true);
  });
});
