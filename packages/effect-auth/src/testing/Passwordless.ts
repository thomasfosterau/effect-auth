/**
 * Test helpers shared by the passwordless suites (`MagicLink.test.ts`,
 * `PhoneOtp.test.ts`, `email/EmailOtp.test.ts`).
 *
 * Never published (`tsconfig.json` excludes this file; the rest of `src/testing/`
 * is the public `./testing` subpath).
 */
import { DateTime, Duration, Effect, type MutableHashMap, Result } from "effect";
import * as Arr from "effect/Array";
import * as P from "effect/Predicate";
import { SecureRandom } from "effect/crypto";
import { vi } from "vite-plus/test";
import * as Errors from "../Errors.ts";
import type * as Types from "../Types.ts";
import { memoryOtpFailures } from "./MemoryStores.ts";

/** A `send` outcome as a caller sees it, apart from the time-dependent `retryAfter`. */
export const observable = (
  result:
    | { readonly _tag: "Success" }
    | {
        readonly _tag: "Failure";
        readonly failure: { readonly _tag: string; readonly message: string };
      },
) =>
  P.isTagged(result, "Failure")
    ? { _tag: "Failure", error: result.failure._tag, message: result.failure.message }
    : { _tag: "Success" };

/**
 * A deterministic `SecureRandom` whose every random byte is 0. Every random
 * integer it derives is the range's lower bound, so the only OTP it can
 * produce is all zeros.
 */
export const zeroCrypto: typeof SecureRandom.SecureRandom.Service = SecureRandom.make(
  (size) => new Uint8Array(size),
);

/**
 * {@link memoryOtpFailures} over `failures`, logging each call's name to
 * `ops` as the suites' recording code stores log theirs.
 */
export const recordingOtpFailures = <P extends string>(
  failures: MutableHashMap.MutableHashMap<string, Types.OtpFailures>,
  ops: Array<string>,
): ReturnType<typeof memoryOtpFailures<P>> => {
  const inner = memoryOtpFailures<P>(failures);
  const log = (op: string) => Effect.sync(() => void ops.push(op));
  return {
    getFailures: (address, purpose) =>
      Effect.andThen(log("getFailures"), inner.getFailures(address, purpose)),
    recordFailure: (address, purpose, at) =>
      Effect.andThen(log("recordFailure"), inner.recordFailure(address, purpose, at)),
    clearFailures: (address, purpose) =>
      Effect.andThen(log("clearFailures"), inner.clearFailures(address, purpose)),
  };
};

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
    const sent: { readonly answer: unknown; readonly record: RecordState | null } = {
      answer: "sent",
      record: yield* record,
    };
    if (sequence === "expired code") {
      yield* Effect.sync(() =>
        vi.setSystemTime(DateTime.toEpochMillis(DateTime.nowUnsafe()) + options.expiresIn + 1),
      );
    }
    const tries = sequence === "wrong codes" ? options.maxAttempts + 1 : 2;
    const attempts = yield* Effect.forEach(
      Arr.makeBy(tries, () => options.verify),
      (verify) =>
        Effect.gen(function* () {
          const result = yield* Effect.result(verify);
          return { answer: observable(result), record: yield* record };
        }),
      { concurrency: 1 },
    );
    return [sent, ...attempts];
  });

/** Run `send` twice in a row, keeping both outcomes. */
export const sendTwice = <E>(send: Effect.Effect<void, E>) =>
  Effect.all([Effect.result(send), Effect.result(send)], { concurrency: 1 });

/** The (faked) current time, in epoch ms. */
const nowMillis = (): number => DateTime.toEpochMillis(DateTime.nowUnsafe());

/** Move the faked `Date` forward by `ms`. */
export const advanceTime = (ms: number): Effect.Effect<void> =>
  Effect.sync(() => vi.setSystemTime(nowMillis() + ms));

/** A day, in ms: the {@link bruteForce} horizon the #590 tests use. */
export const day = 24 * 60 * 60 * 1000;

/**
 * What {@link bruteForce} manages against one address in a day under the
 * default policy (3 attempts per code, a 60 s cooldown, backoff after 5 wrong
 * codes from one minute, doubling, capped at a day): six codes, 18 guesses.
 * A code spent on its last attempt is deleted, so the cooldown never holds
 * the next send; the backoff does, after 6, 9, 12 and 15 wrong codes: 2, 16,
 * 128 and 1 024 minutes. The next wait would be the one-day cap. Before #590
 * every send issued a fresh code at once, so the run reached `maxSends`.
 */
export const defaultBackoffDay: BruteForceResult = {
  guesses: 18,
  sends: 6,
  waits: [2 * 60_000, 16 * 60_000, 128 * 60_000, 1024 * 60_000],
};

/** What one {@link bruteForce} run managed. */
export interface BruteForceResult {
  /** Wrong codes tried. */
  readonly guesses: number;
  /** Sends that issued a code. */
  readonly sends: number;
  /** Each `retryAfter` (ms) the attacker waited out, in order. */
  readonly waits: ReadonlyArray<number>;
}

/**
 * The #590 attack against one address: request a code, spend its
 * `maxAttempts` wrong guesses, request again, for as long as `horizon` ms of
 * (faked) time allows or until `maxSends` codes were issued. A send refused
 * with `ResendTooSoonError` is waited out by moving the faked `Date` forward
 * by its `retryAfter`, unless that would pass the horizon. Any other send
 * failure is a defect. The suite must fake `Date`
 * (`vi.useFakeTimers({ toFake: ["Date"] })`).
 */
export const bruteForce = <E1, E2>(options: {
  readonly send: Effect.Effect<void, E1>;
  readonly guess: Effect.Effect<unknown, E2>;
  readonly maxAttempts: number;
  readonly horizon: number;
  readonly maxSends: number;
}): Effect.Effect<BruteForceResult> => {
  const end = nowMillis() + options.horizon;
  const guesses = Effect.replicateEffect(Effect.ignore(options.guess), options.maxAttempts, {
    concurrency: 1,
  });
  const step = (state: BruteForceResult): Effect.Effect<BruteForceResult> =>
    state.sends >= options.maxSends
      ? Effect.succeed(state)
      : Effect.flatMap(Effect.result(options.send), (sent) => {
          if (Result.isSuccess(sent)) {
            return Effect.andThen(
              guesses,
              Effect.suspend(() =>
                step({
                  ...state,
                  sends: state.sends + 1,
                  guesses: state.guesses + options.maxAttempts,
                }),
              ),
            );
          }
          const refused = sent.failure;
          if (!(refused instanceof Errors.ResendTooSoonError)) {
            return Effect.die(refused);
          }
          const wait = Duration.toMillis(refused.retryAfter);
          return nowMillis() + wait > end
            ? Effect.succeed(state)
            : Effect.andThen(
                advanceTime(wait),
                Effect.suspend(() => step({ ...state, waits: [...state.waits, wait] })),
              );
        });
  return Effect.suspend(() => step({ guesses: 0, sends: 0, waits: [] }));
};
