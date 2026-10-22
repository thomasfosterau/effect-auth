/**
 * Constant-work password verification shared by the password sign-in flows
 * (`EmailPassword`, `Username`). Internal: not exported from any barrel.
 */

import { Effect, Option } from "effect";
import type * as Errors from "../Errors.ts";
import { MultiAlgorithmVerifier, type PasswordHasher } from "./Password.ts";

/**
 * A getter for a decoy hash, computed with `passwordHasher` on first use and
 * cached, so an attempt against a missing account does the same hashing work
 * as one against a real account.
 */
export const makeDecoyHash = (
  passwordHasher: typeof PasswordHasher.Service,
  spanName: string,
): (() => Effect.Effect<string, Errors.HashingError>) => {
  let cachedDecoyHash: string | undefined;
  return Effect.fn(spanName)(function* (): Effect.fn.Return<string, Errors.HashingError> {
    if (cachedDecoyHash !== undefined) return cachedDecoyHash;
    const result = yield* passwordHasher.hash("effect-auth-decoy");
    cachedDecoyHash = result.hash;
    return cachedDecoyHash;
  });
};

/**
 * Verify `password` against the stored hash, or against the decoy hash when
 * there is none, so timing is constant whether or not the account exists.
 * Routes through `MultiAlgorithmVerifier` when present so a hasher switch does
 * not lock out existing users, and reads a `HashingError` from the verifier as
 * `false` so sign-in answers invalid credentials, never a 500.
 */
export const verifyPasswordOrDecoy = (
  passwordHasher: typeof PasswordHasher.Service,
  password: string,
  passwordHash: string | null,
  decoyHash: () => Effect.Effect<string, Errors.HashingError>,
): Effect.Effect<boolean, Errors.HashingError> =>
  Effect.gen(function* () {
    const hashToVerify = passwordHash ?? (yield* decoyHash());
    const multiVerifier = yield* Effect.serviceOption(MultiAlgorithmVerifier);
    const verifyEffect = Option.isSome(multiVerifier)
      ? multiVerifier.value.verify(password, hashToVerify)
      : passwordHasher.verify(password, hashToVerify);
    return yield* verifyEffect.pipe(Effect.catchTag("HashingError", () => Effect.succeed(false)));
  });
