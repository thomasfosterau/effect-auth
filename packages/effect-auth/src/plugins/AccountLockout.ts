/**
 * Account lockout plugin (transform hook with short-circuit).
 *
 * Guards `beforeAuthenticate`, which every credential-verifying flow fires.
 * Each password, username, passkey and second-factor attempt is counted
 * before the credential is checked, and once `maxAttempts` attempts have been
 * counted without a session being issued, the account is locked for
 * `lockoutDurationMs`: `beforeAuthenticate` fails fast with
 * `AccountLockedError` while locked.
 *
 * - **Possession proofs are exempt** (#678). A one-time code by email or SMS
 *   and a magic link (`isPossessionMethod`) are neither refused by the lock
 *   nor counted toward it, so knowing a handle is not enough to block the
 *   owner's passwordless recovery. Their guesses stay bounded without it: a
 *   code accepts `maxAttempts` wrong guesses (default 3), the address's
 *   wrong codes put its sends into a backoff no resend resets (#590), a
 *   magic-link token is 256 random bits and an unknown one is an unkeyed
 *   attempt `IPRateLimitPlugin` counts, and `RateLimitPlugin` /
 *   `IPRateLimitPlugin` count every attempt. A session one of them issues
 *   clears the lock like any other the user earned.
 * - **Unkeyed attempts pass** (an unknown challenge or token names no
 *   account): there is nothing to count them under.
 *
 * - **Keyed on the account.** The counter is keyed on the resolved user
 *   (`lockout:user:<id>`), so every handle of one account (its email, its
 *   username, its phone number) shares one count. A handle no account holds
 *   is keyed on the handle itself (`lockout:email:<address>`, ...), so an
 *   unknown handle locks after the same number of attempts a known one does
 *   (see `authenticationSubject`).
 * - **Cleared only when the user earns a session** (`afterCreateSession`),
 *   never by a correct password that only earned a second-factor challenge
 *   (an attacker who has the password cannot reset the count by signing in
 *   again), and never by an admin impersonation (`isImpersonationSession`,
 *   #678), which the user did not earn.
 * - **Second factor has its own per-user count** (`lockout:second-factor:
 *   user:<id>`, `maxSecondFactorAttempts`), independent of the challenge
 *   tokens: each challenge caps its own wrong codes, but the user's count
 *   runs across every challenge, so fresh challenges buy no fresh guesses.
 *   While it is locked, second-factor redemption fails with
 *   `AccountLockedError`; only someone who passed the first factor can drive
 *   it, so it is not a lever for locking out an account by its handle alone.
 *
 * The clearing tap is isolated: a transient store error while clearing the
 * counter can never abort a sign-in that already succeeded.
 *
 * OWASP recommends account lockout as brute-force mitigation; better-auth does
 * not ship it.
 *
 * ## Deliberate tradeoff: lockout-as-DoS
 *
 * Because the counter is keyed on the target account and increments before
 * credentials are checked, anyone who knows a victim's email or username can
 * submit `maxAttempts` wrong passwords and lock that account for
 * `lockoutDurationMs`, repeatably, and the lock refuses the password,
 * passkey and second-factor methods of that account until it lapses (a magic
 * link or a one-time code still signs the owner in). That is inherent to account-keyed lockout (the same tradeoff OWASP
 * documents). Mitigations, in order of preference:
 *
 * - Stack {@link ../plugins/IPRateLimit.ts | IPRateLimitPlugin} alongside this
 *   plugin so a single origin can't grind an account down — the IP dimension
 *   throttles the attacker without hard-blocking the legitimate owner.
 * - Add a captcha (`CaptchaPlugin`) in front of sign-in to raise the cost of
 *   scripted re-locking.
 * - Keep `lockoutDurationMs` modest (the 15-minute default) so a targeted
 *   victim is inconvenienced, not locked out indefinitely.
 *
 * ## Store-outage behavior
 *
 * By default a lockout-store error fails the sign-in **closed** (an outage
 * blocks sign-ins, but brute-force protection never silently disappears).
 * Set `onStoreError: "fail-open"` to prefer availability: store errors are
 * logged and the sign-in proceeds without lockout protection for the
 * duration of the outage.
 *
 * @module plugins/account-lockout
 */
import { Clock, Context, Duration, Effect, MutableHashMap } from "effect";
import * as Option from "effect/Option";
import * as Errors from "../Errors.ts";
import {
  type AuthenticateAttempt,
  authenticationSubject,
  isPossessionMethod,
  makePlugin,
} from "../Hooks.ts";
import * as Types from "../Types.ts";

/** Per-identifier lockout state. `lockedUntil` is epoch-ms when present. */
export interface AccountLockoutRecord {
  readonly failures: number;
  readonly lockedUntil?: number;
}

/** Options passed to {@link AccountLockoutStore}'s `registerAttempt`. */
export interface RegisterAttemptOptions {
  /** Threshold at which the transition sets `lockedUntil`. */
  readonly maxAttempts: number;
  /** Lock duration in ms applied when the threshold is reached. */
  readonly lockoutDurationMs: number;
  /** The current time in epoch-ms (passed in for atomic SQL/testability). */
  readonly now: number;
}

/**
 * Persistence for lockout counters, keyed by the prefixed subject (see
 * {@link AccountLockoutPlugin}).
 * Implement over your database (see `@thomasfosterau/effect-auth/sql` for an
 * atomic SQL implementation), or use {@link memoryAccountLockoutStore} for
 * single-instance deployments. Entries can safely expire after
 * `lockoutDurationMs`.
 */
export class AccountLockoutStore extends Context.Service<
  AccountLockoutStore,
  {
    readonly get: (key: string) => Effect.Effect<AccountLockoutRecord | null, Errors.AuthError>;

    /**
     * Atomically register a sign-in attempt and return the resulting record.
     * The whole transition MUST be a single atomic operation (one SQL
     * statement or equivalent) so concurrent attempts cannot lose increments
     * — an undercounting store weakens brute-force protection.
     *
     * Transition semantics:
     * - active lock (`lockedUntil > now`): return the record unchanged
     *   (no increment, no lock extension);
     * - expired lock (`lockedUntil <= now`) or no record: reset to
     *   `failures = 1`;
     * - otherwise: `failures + 1`;
     * - when the resulting `failures >= maxAttempts`, set
     *   `lockedUntil = now + lockoutDurationMs`.
     */
    readonly registerAttempt: (
      key: string,
      options: RegisterAttemptOptions,
    ) => Effect.Effect<AccountLockoutRecord, Errors.AuthError>;

    readonly delete: (key: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/AccountLockoutStore") {}

/** Apply the documented `registerAttempt` transition to an in-memory record. */
const transition = (
  existing: AccountLockoutRecord | null,
  options: RegisterAttemptOptions,
): AccountLockoutRecord => {
  if (
    existing !== null &&
    existing.lockedUntil !== undefined &&
    existing.lockedUntil > options.now
  ) {
    return existing;
  }
  const expired =
    existing === null ||
    (existing.lockedUntil !== undefined && existing.lockedUntil <= options.now);
  const failures = (expired ? 0 : existing.failures) + 1;
  return failures >= options.maxAttempts
    ? { failures, lockedUntil: options.now + options.lockoutDurationMs }
    : { failures };
};

/**
 * In-memory {@link AccountLockoutStore} for tests and single-instance
 * deployments. Atomic by construction (synchronous, single-threaded);
 * multi-instance deployments need a shared store with an atomic
 * `registerAttempt` (e.g. the SQL implementation).
 *
 * Pass your own `MutableHashMap` to inspect or pre-seed state in tests.
 */
export const memoryAccountLockoutStore = (
  records: MutableHashMap.MutableHashMap<string, AccountLockoutRecord> = MutableHashMap.empty(),
): typeof AccountLockoutStore.Service => ({
  get: (key) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, key))),
  registerAttempt: (key, options) =>
    Effect.sync(() => {
      const next = transition(Option.getOrNull(MutableHashMap.get(records, key)), options);
      MutableHashMap.set(records, key, next);
      return next;
    }),
  delete: (key) => Effect.sync(() => void MutableHashMap.remove(records, key)),
});

/** Configuration for {@link AccountLockoutPlugin}. */
export interface AccountLockoutConfig {
  /** Consecutive failures before locking. Default 5. */
  readonly maxAttempts?: number;
  /** Lock duration in ms once `maxAttempts` is reached. Default 15 minutes. */
  readonly lockoutDurationMs?: number;
  /** Key namespace in the store. Default `"lockout:"`. */
  readonly keyPrefix?: string;
  /**
   * Second-factor redemptions per user, across every challenge, before
   * second-factor redemption is locked for `lockoutDurationMs`. Counted
   * apart from first-factor attempts and cleared, like them, only when a
   * session is issued. Default 5.
   */
  readonly maxSecondFactorAttempts?: number | undefined;
  /**
   * What a lockout-store error during `beforeAuthenticate` does to the attempt.
   * `"fail-closed"` (default): the sign-in fails — protection never silently
   * disappears. `"fail-open"`: the error is logged and the sign-in proceeds
   * without lockout protection (availability over brute-force hardening).
   */
  readonly onStoreError?: "fail-closed" | "fail-open";
}

/** The counter one attempt is registered on, its threshold and its refusal. */
interface Counter {
  readonly key: string;
  readonly maxAttempts: number;
  readonly message: string;
}

/**
 * Build an account-lockout plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | AccountLockoutStore>` - the store is acquired
 * when the layer is built and used by the `beforeAuthenticate` and
 * `afterCreateSession` hooks.
 */
export const AccountLockoutPlugin = (config: AccountLockoutConfig = {}) => {
  const maxAttempts = config.maxAttempts ?? 5;
  const maxSecondFactorAttempts = config.maxSecondFactorAttempts ?? 5;
  const lockoutDurationMs = config.lockoutDurationMs ?? 15 * 60 * 1000;
  const keyPrefix = config.keyPrefix ?? "lockout:";
  const failOpen = config.onStoreError === "fail-open";

  const firstFactorKey = (subject: string) => `${keyPrefix}${subject}`;
  const secondFactorKey = (subject: string) => `${keyPrefix}second-factor:${subject}`;

  /**
   * The counter an attempt draws on, or `null` for one the lock does not
   * cover: a possession proof (a one-time code or a magic link, #678) or an
   * unkeyed attempt, which names no account.
   */
  const counterFor = (attempt: AuthenticateAttempt): Counter | null => {
    const subject = authenticationSubject(attempt);
    if (subject === undefined || isPossessionMethod(attempt.method)) return null;
    return attempt.method === "second-factor"
      ? {
          key: secondFactorKey(subject),
          maxAttempts: maxSecondFactorAttempts,
          message: "Second-factor verification temporarily locked due to too many attempts",
        }
      : {
          key: firstFactorKey(subject),
          maxAttempts,
          message: "Account temporarily locked due to too many failed sign-in attempts",
        };
  };

  return makePlugin(
    Effect.gen(function* () {
      const store = yield* AccountLockoutStore;

      const guarded = <A>(
        effect: Effect.Effect<A, Errors.AuthError>,
        fallback: A,
      ): Effect.Effect<A, Errors.AuthError> =>
        failOpen
          ? effect.pipe(
              Effect.catchTag("AuthError", (error) =>
                Effect.logWarning("AccountLockout store error (fail-open): sign-in proceeds", {
                  error,
                }).pipe(Effect.as(fallback)),
              ),
            )
          : effect;

      return {
        beforeAuthenticate: (attempt: AuthenticateAttempt) =>
          Effect.gen(function* () {
            const counter = counterFor(attempt);
            if (counter === null) return attempt;
            const now = yield* Clock.currentTimeMillis;

            const existing = yield* guarded(store.get(counter.key), null);
            if (
              existing !== null &&
              existing.lockedUntil !== undefined &&
              existing.lockedUntil > now
            ) {
              return yield* new Errors.AccountLockedError({
                message: counter.message,
                retryAfter: Duration.millis(existing.lockedUntil - now),
              });
            }

            // Atomic increment-or-reset: concurrent attempts each count.
            yield* guarded(
              store.registerAttempt(counter.key, {
                maxAttempts: counter.maxAttempts,
                lockoutDurationMs,
                now,
              }),
              { failures: 0 },
            );

            return attempt;
          }),

        // Only a session the user earned clears the counts: a correct
        // password that earned a second-factor challenge leaves them
        // standing (#592), and so does an admin impersonation (#678).
        afterCreateSession: (session: Types.Session) =>
          Effect.gen(function* () {
            if (Types.isImpersonationSession(session)) return session;
            const subject = `user:${session.userId}`;
            yield* store.delete(firstFactorKey(subject));
            yield* store.delete(secondFactorKey(subject));
            return session;
          }),
      };
    }),
    // Isolate the clearing tap: a transient store error while clearing the
    // counter must not abort a sign-in that already succeeded.
    { isolateTaps: true },
  );
};
