/**
 * Argon2id password hasher for effect-auth.
 *
 * Core `effect-auth` ships only dependency-free hashers (PBKDF2, scrypt).
 * Argon2id — OWASP's first-choice password hashing algorithm — needs a native
 * binding, so it lives in its own package. This wraps
 * [`@node-rs/argon2`](https://github.com/napi-rs/node-rs) (prebuilt binaries,
 * no build step) as a {@link PasswordHasher} that emits and accepts standard
 * PHC strings (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`), so hashes
 * interoperate with any other Argon2 implementation.
 *
 * @module argon2
 */
import { Effect, Layer } from "effect";
import { hash as argon2Hash, verify as argon2Verify } from "@node-rs/argon2";
import { PasswordHasher, type HashedPassword } from "./Password.ts";
import { HashingError } from "../Errors.ts";

/** PHC/`parseAlgorithm` identifier for the hashes this hasher produces. */
export const ARGON2ID = "argon2id";

/**
 * Argon2id cost parameters. Defaults follow the OWASP Password Storage Cheat
 * Sheet (m = 19 MiB, t = 2, p = 1).
 */
export interface Argon2Options {
  /** Memory cost in KiB. Default `19456` (19 MiB). */
  readonly memoryCost?: number;
  /** Time cost (iterations). Default `2`. */
  readonly timeCost?: number;
  /** Degree of parallelism (lanes). Default `1`. */
  readonly parallelism?: number;
}

/**
 * Create an Argon2id {@link PasswordHasher}. `@node-rs/argon2` defaults to the
 * Argon2id variant and version 0x13, so the emitted PHC strings begin with
 * `$argon2id$v=19$`.
 *
 * @example
 * ```ts
 * import { Password } from "@thomasfosterau/effect-auth";
 *
 * const hasher = Password.argon2Hasher();          // OWASP defaults
 * const layer = Password.argon2HasherLayer({ timeCost: 3 });
 * ```
 */
export const argon2Hasher = (options?: Argon2Options): typeof PasswordHasher.Service => {
  // Omit `algorithm`/`version`: the binding already defaults to Argon2id / 0x13.
  const params = {
    memoryCost: options?.memoryCost ?? 19456,
    timeCost: options?.timeCost ?? 2,
    parallelism: options?.parallelism ?? 1,
  };

  const requireNonEmpty = (password: string) =>
    typeof password === "string" && password.length > 0
      ? Effect.void
      : Effect.fail(new HashingError({ message: "Password must be a non-empty string" }));

  return {
    algorithm: ARGON2ID,

    hash: (password: string) =>
      Effect.gen(function* () {
        yield* requireNonEmpty(password);
        const phc = yield* Effect.tryPromise({
          try: () => argon2Hash(password, params),
          catch: (cause) =>
            new HashingError({ message: "Failed to hash password with Argon2id", cause }),
        });
        return { hash: phc, algorithm: ARGON2ID } satisfies HashedPassword;
      }),

    // `@node-rs/argon2` returns `false` for a wrong password and throws only on
    // a malformed hash string; the latter surfaces as a HashingError.
    verify: (password: string, hash: string) =>
      Effect.gen(function* () {
        yield* requireNonEmpty(password);
        return yield* Effect.tryPromise({
          try: () => argon2Verify(hash, password),
          catch: (cause) =>
            new HashingError({
              message: "Failed to verify password against Argon2id hash",
              cause,
            }),
        });
      }),
  };
};

/**
 * A `Layer` providing {@link PasswordHasher} backed by Argon2id. Use in place
 * of `PasswordHasher.layer()` to make Argon2id the default hasher for new
 * passwords.
 */
export const argon2HasherLayer = (options?: Argon2Options): Layer.Layer<PasswordHasher> =>
  Layer.succeed(PasswordHasher, argon2Hasher(options));
