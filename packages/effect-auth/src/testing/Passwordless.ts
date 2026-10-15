/**
 * Test helpers shared by the passwordless suites (`MagicLink.test.ts`,
 * `PhoneOtp.test.ts`, `email/EmailOtp.test.ts`).
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */
import { Crypto, Effect } from "effect";
import { vi } from "vite-plus/test";
import * as PlatformCrypto from "../PlatformCrypto.ts";

/** A `send` outcome as a caller sees it, apart from the time-dependent `retryAfter`. */
export const observable = (
  result:
    | { readonly _tag: "Success" }
    | {
        readonly _tag: "Failure";
        readonly failure: { readonly _tag: string; readonly message: string };
      },
) =>
  result._tag === "Success"
    ? { _tag: "Success" }
    : { _tag: "Failure", error: result.failure._tag, message: result.failure.message };

/**
 * A deterministic `Crypto` whose every random byte is 0. Every random integer
 * it derives is the range's lower bound, so the only OTP it can produce is all
 * zeros. Digests are the platform's.
 */
export const zeroCrypto: Crypto.Crypto = Crypto.make({
  randomBytes: (size) => new Uint8Array(size),
  digest: (algorithm, data) => PlatformCrypto.instance.digest(algorithm, data),
});

/** A code no OTP matches: OTPs are digits only. */
export const wrongCode = "not-a-code";

/**
 * The verify sequences the #417 tests compare across addresses: wrong codes
 * up to and past the attempt limit, and a code tried after expiry.
 */
export const verifySequences = ["wrong codes", "expired code"] as const;
export type VerifySequence = (typeof verifySequences)[number];

/** A stored OTP record as the #417 comparison sees it. */
export interface RecordState {
  readonly attempts: number;
  /** `expiresAt - createdAt`. */
  readonly lifetime: number;
}

/**
 * Run one verify sequence for one address and return, for each step, what the
 * caller observes and the address's stored record. The suite must fake `Date`
 * (`vi.useFakeTimers({ toFake: ["Date"] })`): the expiry step moves it past
 * `expiresIn`.
 */
export const runVerifySequence = <E extends { readonly _tag: string; readonly message: string }>(
  sequence: VerifySequence,
  options: {
    readonly maxAttempts: number;
    readonly expiresIn: number;
    /** Request a code for the address, or `undefined` to request none. */
    readonly send: Effect.Effect<void, unknown> | undefined;
    /** Try {@link wrongCode} for the address. */
    readonly verify: Effect.Effect<unknown, E>;
    /** The address's stored record, or `null`. */
    readonly record: () => RecordState | null;
  },
) =>
  Effect.gen(function* () {
    if (options.send !== undefined) {
      yield* Effect.orDie(options.send);
    }
    const record = Effect.sync(options.record);
    const steps: Array<{ readonly answer: unknown; readonly record: RecordState | null }> = [
      { answer: "sent", record: yield* record },
    ];
    if (sequence === "expired code") {
      yield* Effect.sync(() => vi.setSystemTime(Date.now() + options.expiresIn + 1));
    }
    const tries = sequence === "wrong codes" ? options.maxAttempts + 1 : 2;
    for (let i = 0; i < tries; i++) {
      const result = yield* Effect.result(options.verify);
      steps.push({ answer: observable(result), record: yield* record });
    }
    return steps;
  });
