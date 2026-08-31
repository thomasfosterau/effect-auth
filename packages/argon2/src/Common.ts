/**
 * Shared Argon2id vocabulary: the PHC algorithm identifier, the cost-parameter
 * interface, the recommended cost profiles, and the input guards the hasher
 * applies before running a KDF.
 *
 * This module intentionally depends on nothing but `effect` and
 * `@thomasfosterau/effect-auth`.
 *
 * @module argon2/common
 */
import { Effect } from "effect";
import { HashingError } from "@thomasfosterau/effect-auth";

/** PHC/`parseAlgorithm` identifier for the hashes this package produces. */
export const ARGON2ID = "argon2id";

/**
 * Argon2id cost parameters. Option names match `@node-rs/argon2` and previous
 * releases of this package, so a configuration object written for either
 * still works unchanged.
 *
 * Unset fields fall back to {@link defaultProfile}.
 */
export interface Argon2Options {
  /** Memory cost in KiB. Default `19456` (19 MiB). */
  readonly memoryCost?: number;
  /** Time cost (iterations). Default `2`. */
  readonly timeCost?: number;
  /** Degree of parallelism (lanes). Default `1`. */
  readonly parallelism?: number;
}

/** A fully-resolved set of Argon2id cost parameters — an {@link Argon2Options} with no holes. */
export interface Argon2Profile {
  /** Memory cost in KiB. */
  readonly memoryCost: number;
  /** Time cost (iterations). */
  readonly timeCost: number;
  /** Degree of parallelism (lanes). */
  readonly parallelism: number;
}

/**
 * The default profile: OWASP's **low-memory** Argon2id recommendation
 * (m = 19 MiB, t = 2, p = 1).
 *
 * Chosen so the defaults are safe everywhere the package can run, including
 * Cloudflare Workers (128 MiB isolate limit) and other constrained serverless
 * runtimes. On a plain Node server prefer {@link serverProfile}.
 */
export const defaultProfile: Argon2Profile = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/**
 * A stronger profile for plain-Node deployments with memory to spare
 * (m = 64 MiB, t = 3, p = 1). Roughly 5× the work of {@link defaultProfile};
 * measure it against your own latency budget before adopting it, and do not
 * use it on Cloudflare Workers.
 *
 * @example
 * ```ts
 * import { argon2HasherLayer, serverProfile } from "@thomasfosterau/effect-auth-argon2";
 *
 * const layer = argon2HasherLayer(serverProfile);
 * ```
 */
export const serverProfile: Argon2Profile = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};

/** Fill in any unset {@link Argon2Options} field from {@link defaultProfile}. */
export const resolveOptions = (options?: Argon2Options): Argon2Profile => ({
  memoryCost: options?.memoryCost ?? defaultProfile.memoryCost,
  timeCost: options?.timeCost ?? defaultProfile.timeCost,
  parallelism: options?.parallelism ?? defaultProfile.parallelism,
});

/** Salt length in bytes. Matches `@node-rs/argon2`'s default. */
export const SALT_LENGTH = 16;

/** Derived key length in bytes. Matches `@node-rs/argon2`'s default. */
export const HASH_LENGTH = 32;

/**
 * Anti-DoS ceiling: reject inputs longer than this before running any KDF.
 * Same value core `effect-auth` uses; legitimate passwords are far below it.
 */
export const MAX_PASSWORD_BYTES = 1024;

const encoder = new TextEncoder();

/** True when `password` is short enough to be worth running the KDF on. */
export const isWithinMaxLength = (password: string): boolean =>
  encoder.encode(password).length <= MAX_PASSWORD_BYTES;

/** Fails unless `password` is a non-empty string. */
export const requireNonEmptyPassword = (password: string): Effect.Effect<void, HashingError> =>
  typeof password === "string" && password.length > 0
    ? Effect.void
    : Effect.fail(new HashingError({ message: "Password must be a non-empty string" }));

/** Fails unless `hash` is a non-empty string. */
export const requireNonEmptyHash = (hash: string): Effect.Effect<void, HashingError> =>
  typeof hash === "string" && hash.length > 0
    ? Effect.void
    : Effect.fail(new HashingError({ message: "Hash must be a non-empty string" }));

/** Fails unless `password` is a non-empty string within {@link MAX_PASSWORD_BYTES}. */
export const requireHashablePassword = (password: string): Effect.Effect<void, HashingError> =>
  Effect.flatMap(requireNonEmptyPassword(password), () =>
    isWithinMaxLength(password)
      ? Effect.void
      : Effect.fail(new HashingError({ message: "Password exceeds maximum length" })),
  );
