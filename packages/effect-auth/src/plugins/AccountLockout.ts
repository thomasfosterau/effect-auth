/**
 * Account lockout plugin (transform hook with short-circuit).
 *
 * Counts consecutive failed sign-in attempts per normalized email and, once
 * `maxAttempts` is reached, locks the identifier for `lockoutDurationMs`.
 * `beforeSignIn` fails fast with `AccountLockedError` while locked;
 * `afterSignIn` (only fired on success) clears the counter, so a successful
 * sign-in resets the streak. The reset tap is isolated — a transient store
 * error while clearing the counter can never abort a sign-in that already
 * succeeded.
 *
 * OWASP recommends account lockout as brute-force mitigation; better-auth does
 * not ship it. Hooks fire before user resolution, so the counter is keyed by
 * the normalized email rather than a user id.
 *
 * ## Deliberate tradeoff: lockout-as-DoS
 *
 * Because the counter is keyed solely on the target email and increments
 * before credentials are checked, anyone who knows a victim's email can
 * submit `maxAttempts` wrong passwords and lock that account for
 * `lockoutDurationMs`, repeatably. That is inherent to email-keyed lockout
 * (the same tradeoff OWASP documents). Mitigations, in order of preference:
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
import { Context, Effect } from "effect";
import type { SignInInput, AuthResult } from "../email/EmailPassword.ts";
import * as Errors from "../Errors.ts";
import { makePlugin } from "../Hooks.ts";

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
 * Persistence for lockout counters, keyed by the (prefixed, normalized) email.
 * Implement over your database (see `@thomasfosterau/effect-auth-sql` for an
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
 * Pass your own `Map` to inspect or pre-seed state in tests.
 */
export const memoryAccountLockoutStore = (
  records: Map<string, AccountLockoutRecord> = new Map(),
): typeof AccountLockoutStore.Service => ({
  get: (key) => Effect.sync(() => records.get(key) ?? null),
  registerAttempt: (key, options) =>
    Effect.sync(() => {
      const next = transition(records.get(key) ?? null, options);
      records.set(key, next);
      return next;
    }),
  delete: (key) => Effect.sync(() => void records.delete(key)),
});

export interface AccountLockoutConfig {
  /** Consecutive failures before locking. Default 5. */
  readonly maxAttempts?: number;
  /** Lock duration in ms once `maxAttempts` is reached. Default 15 minutes. */
  readonly lockoutDurationMs?: number;
  /** Key namespace in the store. Default `"lockout:"`. */
  readonly keyPrefix?: string;
  /**
   * What a lockout-store error during `beforeSignIn` does to the sign-in.
   * `"fail-closed"` (default): the sign-in fails — protection never silently
   * disappears. `"fail-open"`: the error is logged and the sign-in proceeds
   * without lockout protection (availability over brute-force hardening).
   */
  readonly onStoreError?: "fail-closed" | "fail-open";
}

const normalize = (email: string): string => email.trim().toLowerCase();

/**
 * Build an account-lockout plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | AccountLockoutStore>` - the store is acquired
 * when the layer is built and used by the `beforeSignIn`/`afterSignIn` hooks.
 */
export const AccountLockoutPlugin = (config: AccountLockoutConfig = {}) => {
  const maxAttempts = config.maxAttempts ?? 5;
  const lockoutDurationMs = config.lockoutDurationMs ?? 15 * 60 * 1000;
  const keyPrefix = config.keyPrefix ?? "lockout:";
  const failOpen = config.onStoreError === "fail-open";

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
        beforeSignIn: (input: SignInInput) =>
          Effect.gen(function* () {
            const key = `${keyPrefix}${normalize(input.email)}`;
            const now = Date.now();

            const existing = yield* guarded(store.get(key), null);
            if (
              existing !== null &&
              existing.lockedUntil !== undefined &&
              existing.lockedUntil > now
            ) {
              return yield* Effect.fail(
                new Errors.AccountLockedError({
                  message: "Account temporarily locked due to too many failed sign-in attempts",
                }),
              );
            }

            // Atomic increment-or-reset: concurrent attempts each count.
            yield* guarded(store.registerAttempt(key, { maxAttempts, lockoutDurationMs, now }), {
              failures: 0,
            });

            return input;
          }),

        afterSignIn: (result: AuthResult) =>
          Effect.gen(function* () {
            // Successful sign-in clears the counter (keyed by the email
            // handle used to sign in; other handles have no counter).
            if (result.identifier?.type === "email") {
              yield* store.delete(`${keyPrefix}${normalize(result.identifier.value)}`);
            }
            return result;
          }),
      };
    }),
    // Isolate the reset tap: a transient store error while clearing the
    // counter must not abort a sign-in that already succeeded.
    { isolateTaps: true },
  );
};
