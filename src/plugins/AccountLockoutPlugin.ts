/**
 * Account lockout plugin (transform hook with short-circuit).
 *
 * Counts consecutive failed sign-in attempts per normalized email and, once
 * `maxAttempts` is reached, locks the identifier for `lockoutDurationMs`.
 * `beforeSignIn` fails fast with `AuthError` while locked; `afterSignIn`
 * (only fired on success) clears the counter, so a successful sign-in resets
 * the streak.
 *
 * OWASP recommends account lockout as brute-force mitigation; better-auth does
 * not ship it. Hooks fire before user resolution, so the counter is keyed by
 * the normalized email rather than a user id.
 *
 * @module plugins/account-lockout
 */
import { Context, Effect } from "effect";
import type { SignInInput, AuthResult } from "../EmailPassword.ts";
import * as Errors from "../Errors.ts";
import { makePlugin } from "../Hooks.ts";

/** Per-identifier lockout state. `lockedUntil` is epoch-ms when present. */
export interface AccountLockoutRecord {
  readonly failures: number;
  readonly lockedUntil?: number;
}

/**
 * Persistence for lockout counters, keyed by the (prefixed, normalized) email.
 * Implement over your database, or reuse an in-memory map for single-instance
 * deployments. Entries can safely expire after `lockoutDurationMs`.
 */
export interface AccountLockoutStoreShape {
  readonly get: (key: string) => Effect.Effect<AccountLockoutRecord | null, Errors.AuthError>;
  readonly set: (
    key: string,
    record: AccountLockoutRecord,
  ) => Effect.Effect<void, Errors.AuthError>;
  readonly delete: (key: string) => Effect.Effect<void, Errors.AuthError>;
}

export class AccountLockoutStore extends Context.Service<
  AccountLockoutStore,
  AccountLockoutStoreShape
>()("@effect-auth/AccountLockoutStore") {}

export interface AccountLockoutConfig {
  /** Consecutive failures before locking. Default 5. */
  readonly maxAttempts?: number;
  /** Lock duration in ms once `maxAttempts` is reached. Default 15 minutes. */
  readonly lockoutDurationMs?: number;
  /** Key namespace in the store. Default `"lockout:"`. */
  readonly keyPrefix?: string;
}

const normalize = (email: string): string => email.trim().toLowerCase();

/**
 * Build an account-lockout plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | AccountLockoutStoreTag>` - the store is acquired
 * when the layer is built and used by the `beforeSignIn`/`afterSignIn` hooks.
 */
export const AccountLockoutPlugin = (config: AccountLockoutConfig = {}) => {
  const maxAttempts = config.maxAttempts ?? 5;
  const lockoutDurationMs = config.lockoutDurationMs ?? 15 * 60 * 1000;
  const keyPrefix = config.keyPrefix ?? "lockout:";

  return makePlugin(
    Effect.gen(function* () {
      const store = yield* AccountLockoutStore;

      return {
        beforeSignIn: (input: SignInInput) =>
          Effect.gen(function* () {
            const key = `${keyPrefix}${normalize(input.email)}`;
            const now = Date.now();
            const existing = yield* store.get(key);

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

            // A lock whose window has elapsed resets the streak.
            const priorFailures =
              existing === null ||
              (existing.lockedUntil !== undefined && existing.lockedUntil <= now)
                ? 0
                : existing.failures;

            const failures = priorFailures + 1;
            const record: AccountLockoutRecord =
              failures >= maxAttempts
                ? { failures, lockedUntil: now + lockoutDurationMs }
                : { failures };
            yield* store.set(key, record);

            return input;
          }),

        afterSignIn: (result: AuthResult) =>
          Effect.gen(function* () {
            // Successful sign-in clears the counter.
            yield* store.delete(`${keyPrefix}${normalize(result.user.email)}`);
            return result;
          }),
      };
    }),
  );
};
