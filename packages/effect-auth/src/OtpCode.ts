/**
 * The steps `EmailOtp` and `PhoneOtp` share: defaults, the send gate (resend
 * cooldown and failure backoff) and verification. Each wrong code counts
 * against the (address, purpose) pair, apart from the code, until a success
 * clears it; past `freeFailures`, sends back off exponentially, never refused
 * for good. Internal.
 */
import { Clock, Duration, Effect } from "effect";
import * as Option from "effect/Option";
import type { SecureRandom } from "effect/crypto";
import * as Errors from "./Errors.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";
import { constantTimeHashEqual } from "./TokenHash.ts";
import type { OtpBackoffConfig, OtpFailureBudget, OtpFailures } from "./Types.ts";

/** The fields of a stored code the shared steps read. */
export interface CodeRecord {
  readonly otpHash: string;
  readonly attempts: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * The part of a code store the shared steps use; `EmailOtpStore` and
 * `PhoneOtpStore` both fit, with `A` their record.
 */
export interface CodeStore<P, A extends CodeRecord = CodeRecord> extends OtpFailureBudget<P> {
  readonly get: (address: string, purpose: P) => Effect.Effect<Option.Option<A>, Errors.AuthError>;
  readonly delete: (address: string, purpose: P) => Effect.Effect<void, Errors.AuthError>;
  readonly incrementAttempts: (
    address: string,
    purpose: P,
  ) => Effect.Effect<Option.Option<number>, Errors.AuthError>;
}

/** The configuration both flows take for their codes. */
export interface CodeConfig {
  readonly otpLength?: number;
  readonly expiresIn?: number;
  readonly maxAttempts?: number;
  readonly disableSignUp?: boolean;
  readonly resendCooldown?: number;
  readonly backoff?: OtpBackoffConfig;
}

/** {@link CodeConfig} with its defaults applied. */
export interface ResolvedCodeConfig {
  readonly otpLength: number;
  readonly expiresIn: number;
  readonly maxAttempts: number;
  readonly disableSignUp: boolean;
  readonly resendCooldown: number;
  readonly backoff: { readonly [K in keyof OtpBackoffConfig]-?: number };
}

/** Apply the defaults: 6 digits, 5 minutes, 3 attempts, a 60 s cooldown, backoff after 5 wrong codes from 1 minute up to 1 day. */
export const resolveCodeConfig = (config: CodeConfig): ResolvedCodeConfig => ({
  otpLength: config.otpLength ?? 6,
  expiresIn: config.expiresIn ?? 5 * 60 * 1000,
  maxAttempts: config.maxAttempts ?? 3,
  disableSignUp: config.disableSignUp ?? false,
  resendCooldown: config.resendCooldown ?? 60 * 1000,
  backoff: {
    freeFailures: config.backoff?.freeFailures ?? 5,
    baseDelay: config.backoff?.baseDelay ?? 60 * 1000,
    maxDelay: config.backoff?.maxDelay ?? 24 * 60 * 60 * 1000,
  },
});

/** How long after its latest wrong code a pair with `count` wrong codes waits to send. */
const backoffDelay = (backoff: ResolvedCodeConfig["backoff"], count: number): number =>
  count < backoff.freeFailures
    ? 0
    : Math.min(backoff.maxDelay, backoff.baseDelay * 2 ** (count - backoff.freeFailures));

/**
 * How long a send must still wait, in ms (`0`: it may go now): the longer of
 * what is left of the resend cooldown on the outstanding record and of the
 * backoff on the pair's wrong codes.
 */
const sendWait = (options: {
  readonly now: number;
  readonly config: ResolvedCodeConfig;
  readonly existing: Option.Option<CodeRecord>;
  readonly failures: Option.Option<OtpFailures>;
}): number => {
  const cooldown = Option.match(options.existing, {
    onNone: () => 0,
    onSome: (existing) => existing.createdAt + options.config.resendCooldown - options.now,
  });
  const backoff = Option.match(options.failures, {
    onNone: () => 0,
    onSome: (failures) =>
      failures.lastFailureAt + backoffDelay(options.config.backoff, failures.count) - options.now,
  });
  return Math.max(0, cooldown, backoff);
};

/**
 * Refuse a send with {@link Errors.ResendTooSoonError} while {@link sendWait}
 * says to wait. It reads the same two things for every address, whether or
 * not it has an account: an unknown address holds a marker record and counts
 * wrong codes as a known one does, so the answer reveals nothing.
 */
export const gateSend = <P>(
  store: CodeStore<P>,
  address: string,
  purpose: P,
  config: ResolvedCodeConfig,
): Effect.Effect<void, Errors.AuthError | Errors.ResendTooSoonError> =>
  Effect.gen(function* () {
    const existing = yield* store.get(address, purpose);
    const failures = yield* store.getFailures(address, purpose);
    const wait = sendWait({ now: yield* Clock.currentTimeMillis, config, existing, failures });
    if (wait > 0) {
      return yield* new Errors.ResendTooSoonError({
        message: "Please wait before requesting another OTP",
        retryAfter: Duration.millis(wait),
      });
    }
    return yield* Effect.void;
  });

/** Why an OTP verification failed: no record, a wrong code, expiry or the attempt limit. */
export type VerifyFailure = "missing" | "mismatch" | "expired" | "attempts";

/** The generic answer to a failed verification. */
const invalidOtpMessage = "Invalid or expired OTP";

/** The message each verification failure answers where existence isn't hidden. */
const failureMessages: Record<VerifyFailure, string> = {
  missing: invalidOtpMessage,
  mismatch: invalidOtpMessage,
  expired: "OTP has expired",
  attempts: "Too many attempts",
};

/**
 * Build a flow's verification failure. Where `send` hides whether the
 * address has an account, every reason answers the generic message: the
 * marker record already gives a known and an unknown address the same record
 * states, and the generic message also makes one that holds a record answer
 * as one that holds none, so expiry and the attempt limit can't show whether
 * a code was requested for it. The reason stays on the span for operators.
 */
export const makeReject =
  <P, E>(hidesAccount: (purpose: P) => boolean, makeError: (message: string) => E) =>
  (purpose: P, reason: VerifyFailure): Effect.Effect<never, E> =>
    Effect.annotateCurrentSpan("auth.otp.failure", reason).pipe(
      Effect.andThen(
        Effect.fail(makeError(hidesAccount(purpose) ? invalidOtpMessage : failureMessages[reason])),
      ),
    );

/**
 * Verify `code` against the stored record for (address, purpose): expiry,
 * the per-code attempt limit, a constant-time hash comparison, and one-time
 * use on success. Every attempt is counted against the code before the
 * comparison, and one past `maxAttempts` is refused uncompared; a
 * wrong code is also counted against the pair's failure budget, and a
 * correct one clears the budget.
 */
export const verifyCode = <P, E>(
  store: CodeStore<P>,
  options: {
    readonly address: string;
    readonly code: string;
    readonly purpose: P;
    readonly maxAttempts: number;
    readonly reject: (purpose: P, reason: VerifyFailure) => Effect.Effect<never, E>;
    /** The digest a code is stored as. */
    readonly hash: (code: string) => Effect.Effect<string>;
  },
): Effect.Effect<void, E | Errors.AuthError> =>
  Effect.gen(function* () {
    const { address, code, purpose, maxAttempts, reject, hash } = options;
    if (!address || !code) {
      return yield* reject(purpose, "missing");
    }

    const found = yield* store.get(address, purpose);
    if (Option.isNone(found)) {
      return yield* reject(purpose, "missing");
    }
    const record = found.value;

    const now = yield* Clock.currentTimeMillis;
    if (now > record.expiresAt) {
      yield* store.delete(address, purpose);
      return yield* reject(purpose, "expired");
    }

    // Count the attempt before comparing: each concurrent guess gets
    // its own count from the store, so at most `maxAttempts` guesses are
    // ever compared, however many arrive at once. `None` is a code another
    // request consumed or exhausted since the read.
    const counted = yield* store.incrementAttempts(address, purpose);
    if (Option.isNone(counted)) {
      return yield* reject(purpose, "missing");
    }
    const attempts = counted.value;
    if (attempts > maxAttempts) {
      yield* store.delete(address, purpose);
      return yield* reject(purpose, "attempts");
    }

    if (!constantTimeHashEqual(record.otpHash, yield* hash(code))) {
      // Counted against the pair too, where a resend cannot reset it.
      yield* store.recordFailure(address, purpose, now);
      if (attempts >= maxAttempts) {
        yield* store.delete(address, purpose);
        return yield* reject(purpose, "attempts");
      }
      return yield* reject(purpose, "mismatch");
    }

    // Consume the code (one-time use) and reset the pair's failure budget.
    yield* store.delete(address, purpose);
    return yield* store.clearFailures(address, purpose);
  });

/**
 * Generate a numeric OTP with crypto-secure randomness (one unbiased
 * `intBetween` draw per digit — no modulo bias).
 */
export const generateOtp = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  length: number,
): Effect.Effect<string> =>
  Effect.replicateEffect(
    crypto.intBetween(0, 10, { halfOpen: true }),
    Math.max(0, Math.ceil(length)),
    { concurrency: 1 },
  ).pipe(Effect.map((digits) => digits.join("")));

/**
 * Draw a fresh code and the fields of its record. An address with no account
 * (`deliver: false`) gets a marker record instead, whose hash is of a random
 * 32-byte secret rather than of a code: no `otpLength`-digit guess can match
 * it, and the secret is never sent. Both values are drawn on every send, and
 * the record has the same attempts and expiry either way, so both branches do
 * the same random and store work and verification sees the same record states.
 */
export const issueCode = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  hash: (code: string) => Effect.Effect<string>,
  config: ResolvedCodeConfig,
  deliver: boolean,
): Effect.Effect<{ readonly code: string; readonly record: CodeRecord }> =>
  Effect.gen(function* () {
    const code = yield* generateOtp(crypto, config.otpLength);
    const markerSecret = yield* randomBase64UrlToken(crypto);
    const now = yield* Clock.currentTimeMillis;
    return {
      code,
      record: {
        otpHash: yield* hash(deliver ? code : markerSecret),
        attempts: 0,
        createdAt: now,
        expiresAt: now + config.expiresIn,
      },
    };
  });
