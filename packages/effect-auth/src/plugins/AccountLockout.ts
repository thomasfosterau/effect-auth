/**
 * Account lockout: counts password, username and second-factor attempts per
 * account and refuses with `AccountLockedError` for `lockoutDurationMs` after
 * `maxAttempts`. Possession proofs and passkeys are exempt. Anyone who knows a
 * handle can lock its account, so pair it with `IPRateLimitPlugin`. Store
 * errors fail closed unless `onStoreError: "fail-open"`.
 *
 * @module plugins/account-lockout
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Option from "effect/Option";
import { amortizedPrune } from "../AmortizedPrune.ts";
import * as Errors from "../Errors.ts";
import * as Hooks from "../Hooks.ts";
import * as Types from "../Types.ts";

/**
 * Whether the lock leaves `method` alone: a possession proof or a
 * passkey.
 */
const isLockExempt = (method: Hooks.AuthenticationMethod): boolean =>
  Hooks.isPossessionMethod(method) || method === "passkey";

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
    readonly get: (
      key: string,
    ) => Effect.Effect<Option.Option<AccountLockoutRecord>, Errors.AuthError>;

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
 * Bounded by its live entries: each identifier tried adds one, so once the
 * map has doubled since it was last pruned, an attempt drops every entry whose
 * lock has ended, or which was never locked and has had no attempt for
 * `lockoutDurationMs`. An active lock always stays.
 *
 * Pass your own `MutableHashMap` to inspect or pre-seed state in tests.
 */
export const memoryAccountLockoutStore = (
  records: MutableHashMap.MutableHashMap<string, AccountLockoutRecord> = MutableHashMap.empty(),
): typeof AccountLockoutStore.Service => {
  const lastAttemptAt = MutableHashMap.empty<string, number>();
  const prune = amortizedPrune(records);
  return {
    get: (key) => Effect.sync(() => MutableHashMap.get(records, key)),
    registerAttempt: (key, options) =>
      Effect.sync(() => {
        prune((record, staleKey) => {
          const stale =
            record.lockedUntil === undefined
              ? Option.match(MutableHashMap.get(lastAttemptAt, staleKey), {
                  onNone: () => false,
                  onSome: (at) => at + options.lockoutDurationMs <= options.now,
                })
              : record.lockedUntil <= options.now;
          if (stale) MutableHashMap.remove(lastAttemptAt, staleKey);
          return stale;
        });
        const next = transition(Option.getOrNull(MutableHashMap.get(records, key)), options);
        MutableHashMap.set(records, key, next);
        MutableHashMap.set(lastAttemptAt, key, options.now);
        return next;
      }),
    delete: (key) =>
      Effect.sync(() => {
        MutableHashMap.remove(records, key);
        MutableHashMap.remove(lastAttemptAt, key);
      }),
  };
};

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
  readonly maxSecondFactorAttempts?: number;
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
   * cover: a possession proof (a one-time code or a magic link; a
   * passkey) or an unkeyed attempt, which names no account.
   */
  const counterFor = (attempt: Hooks.AuthenticateAttempt): Counter | null => {
    const subject = Hooks.authenticationSubject(attempt);
    if (subject === undefined || isLockExempt(attempt.method)) return null;
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

  return Hooks.makePlugin(
    Effect.gen(function* () {
      const store = yield* AccountLockoutStore;

      return {
        beforeAuthenticate: (attempt: Hooks.AuthenticateAttempt) =>
          Effect.gen(function* () {
            const counter = counterFor(attempt);
            if (counter === null) return attempt;
            const now = yield* Clock.currentTimeMillis;

            const existing = yield* guarded(store.get(counter.key), Option.none());
            const lockedUntil = Option.flatMap(existing, (record) =>
              Option.fromUndefinedOr(record.lockedUntil),
            );
            if (Option.isSome(lockedUntil) && lockedUntil.value > now) {
              return yield* new Errors.AccountLockedError({
                message: counter.message,
                retryAfter: Duration.millis(lockedUntil.value - now),
              });
            }

            // Count the attempt, atomically, and act on the count the store
            // returns: the `get` above is a cheap early refusal, but
            // concurrent attempts all pass it before any of them counts, so
            // only the returned record decides. The threshold handed over is
            // one past the cap, so attempts 1..maxAttempts proceed and the
            // first beyond it sets the lock and is refused; of a burst, at most
            // `maxAttempts` ever reach the credential check.
            const counted = yield* guarded(
              store.registerAttempt(counter.key, {
                maxAttempts: counter.maxAttempts + 1,
                lockoutDurationMs,
                now,
              }),
              { failures: 0 },
            );
            if (counted.lockedUntil !== undefined && counted.lockedUntil > now) {
              return yield* new Errors.AccountLockedError({
                message: counter.message,
                retryAfter: Duration.millis(counted.lockedUntil - now),
              });
            }

            return attempt;
          }),

        // Only a session the user earned clears the counts: a correct
        // password that earned a second-factor challenge leaves them
        // standing, and so does an admin impersonation.
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
