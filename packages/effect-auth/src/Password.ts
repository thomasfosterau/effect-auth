/**
 * Password Hashing Traits and Multi-Algorithm Support
 *
 * Inspired by Rust's password_hash crate, this module provides:
 * - Trait-based API (PasswordHasher interface) for algorithm-agnostic hashing
 * - PHC string format support (algorithm$params$salt$hash)
 * - Multi-algorithm verification for seamless migration
 * - Extensible design for custom algorithms
 */

import { Context, Effect, Layer } from "effect";
import type * as Types from "./Types.js";
import * as Errors from "./Errors.js";

/**
 * Core password hashing interface (trait)
 * Implement this interface to support custom password hashing algorithms
 */
export interface PasswordHasher {
  /**
   * Unique identifier for this algorithm (used in PHC format)
   */
  readonly algorithm: string;

  /**
   * Hash a password using this algorithm
   */
  readonly hash: (password: string) => Effect.Effect<Types.HashedPassword, Errors.HashingError>;

  /**
   * Verify a password against a hash using this algorithm
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}

/**
 * Multi-algorithm password verifier
 * Supports verifying passwords against different hash formats,
 * enabling seamless migration between algorithms
 */
export interface MultiAlgorithmVerifier {
  /**
   * Verify a password against a hash, automatically detecting the algorithm
   * from the PHC format string
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}

/**
 * Tag for PasswordHasher service
 */
export class PasswordHasherTag extends Context.Service<PasswordHasherTag, PasswordHasher>()(
  "@effect-auth/PasswordHasher",
) {}

// Public ergonomic alias
export const PasswordHasher = PasswordHasherTag;

/**
 * Tag for MultiAlgorithmVerifier service
 */
export class MultiAlgorithmVerifierTag extends Context.Service<
  MultiAlgorithmVerifierTag,
  MultiAlgorithmVerifier
>()("@effect-auth/MultiAlgorithmVerifier") {}

// Public ergonomic alias
export const MultiAlgorithmVerifier = MultiAlgorithmVerifierTag;

/**
 * Parse a PHC format string to extract the algorithm identifier
 */
const parseAlgorithm = (hash: string): Effect.Effect<string, Errors.HashingError> =>
  Effect.sync(() => {
    const parts = hash.split("$");
    if (parts.length < 2) {
      return Effect.fail(
        new Errors.HashingError({
          message: "Invalid hash format: missing algorithm identifier",
        }),
      );
    }
    return Effect.succeed(parts[0]);
  }).pipe(Effect.flatten);

/**
 * Create a multi-algorithm verifier that supports multiple password hashers
 * This allows you to verify passwords that were hashed with different algorithms,
 * which is useful during algorithm migration
 *
 * @example
 * ```typescript
 * import { Effect } from "effect"
 *
 * declare const verifier: { verify: (p: string, h: string) => Effect.Effect<boolean> }
 * declare const password: string
 * declare const storedHash: string
 *
 * const program = Effect.gen(function* () {
 *   // Will automatically detect which algorithm was used.
 *   const isValid = yield* verifier.verify(password, storedHash)
 *   return isValid
 * })
 * ```
 */
export const makeMultiAlgorithmVerifier = (
  hashers: readonly PasswordHasher[],
): MultiAlgorithmVerifier => {
  const hasherMap = new Map(hashers.map((h) => [h.algorithm, h]));

  return {
    verify: (password, hash) =>
      Effect.gen(function* () {
        const algorithm = yield* parseAlgorithm(hash);
        const hasher = hasherMap.get(algorithm);

        if (!hasher) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: `Unsupported algorithm: ${algorithm}. Available: ${Array.from(hasherMap.keys()).join(", ")}`,
            }),
          );
        }

        return yield* hasher.verify(password, hash);
      }),
  };
};

/**
 * Create a layer that provides a multi-algorithm verifier
 */
export const makeMultiAlgorithmVerifierLayer = (hashers: readonly PasswordHasher[]) =>
  Layer.succeed(MultiAlgorithmVerifierTag, makeMultiAlgorithmVerifier(hashers));

import * as crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);

export type {
  /** Re-export of {@link Types.HashedPassword} for convenience. */
  HashedPassword,
} from "./Types.js";

/**
 * PBKDF2 Password Hasher implementing the PasswordHasher trait
 * Following Copenhagen/Oslo guidelines for secure password hashing
 */
export const makePBKDF2Hasher = (): PasswordHasher => {
  const ALGORITHM = "pbkdf2-sha256";
  const ITERATIONS = 210000; // OWASP recommended minimum
  const KEY_LENGTH = 64;
  const SALT_LENGTH = 16;

  return {
    algorithm: ALGORITHM,
    hash: (password: string) =>
      Effect.gen(function* () {
        // Validate input
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password must be a non-empty string",
            }),
          );
        }

        if (password.length < 1) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password cannot be empty",
            }),
          );
        }

        const salt = crypto.randomBytes(SALT_LENGTH);

        const derivedKey = yield* Effect.tryPromise({
          try: () => pbkdf2(password, salt, ITERATIONS, KEY_LENGTH, "sha256"),
          catch: (error) =>
            new Errors.HashingError({
              message: "Failed to hash password",
              cause: error,
            }),
        });

        // Format: algorithm$iterations$salt$hash
        const hash = `${ALGORITHM}$${ITERATIONS}$${salt.toString("hex")}$${derivedKey.toString("hex")}`;

        return {
          hash,
          algorithm: ALGORITHM,
        };
      }),

    verify: (password: string, hash: string) =>
      Effect.gen(function* () {
        // Validate inputs
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password must be a non-empty string",
            }),
          );
        }

        if (!hash || typeof hash !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Hash must be a non-empty string",
            }),
          );
        }

        const parts = hash.split("$");

        if (parts.length !== 4) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash format",
            }),
          );
        }

        const [algorithm, iterations, saltHex, hashHex] = parts;

        if (algorithm !== ALGORITHM) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: `Unsupported algorithm: ${algorithm}`,
            }),
          );
        }

        const salt = Buffer.from(saltHex, "hex");
        const expectedHash = Buffer.from(hashHex, "hex");

        const derivedKey = yield* Effect.tryPromise({
          try: () => pbkdf2(password, salt, parseInt(iterations), KEY_LENGTH, "sha256"),
          catch: (error) =>
            new Errors.HashingError({
              message: "Failed to verify password",
              cause: error,
            }),
        });

        // Use timing-safe comparison
        return crypto.timingSafeEqual(derivedKey, expectedHash);
      }),
  };
};

/**
 * scrypt Password Hasher implementing the PasswordHasher trait.
 *
 * Uses Node's built-in `crypto.scrypt` (dependency-free) with OWASP-recommended
 * parameters (N=2^17, r=8, p=1). scrypt is memory-hard, making it more
 * resistant to GPU/ASIC attacks than PBKDF2.
 *
 * PHC-style format: `scrypt$N$r$p$salt$hash` (N/r/p are stored so parameters
 * can be tuned without breaking existing hashes).
 */
export const makeScryptHasher = (options?: {
  readonly cost?: number;
  readonly blockSize?: number;
  readonly parallelization?: number;
}): PasswordHasher => {
  const ALGORITHM = "scrypt";
  const COST = options?.cost ?? 131072; // 2^17, OWASP recommended
  const BLOCK_SIZE = options?.blockSize ?? 8;
  const PARALLELIZATION = options?.parallelization ?? 1;
  const KEY_LENGTH = 64;
  const SALT_LENGTH = 16;

  const scrypt = (
    password: string,
    salt: Buffer,
    N: number,
    r: number,
    p: number,
  ): Effect.Effect<Buffer, Errors.HashingError> =>
    Effect.callback((resume) => {
      crypto.scrypt(
        password,
        salt,
        KEY_LENGTH,
        // maxmem must exceed 128 * N * r
        { N, r, p, maxmem: 128 * N * r * 2 },
        (error, derivedKey) => {
          if (error) {
            resume(
              Effect.fail(
                new Errors.HashingError({
                  message: "Failed to derive scrypt key",
                  cause: error,
                }),
              ),
            );
          } else {
            resume(Effect.succeed(derivedKey));
          }
        },
      );
    });

  return {
    algorithm: ALGORITHM,
    hash: (password: string) =>
      Effect.gen(function* () {
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password must be a non-empty string",
            }),
          );
        }

        const salt = crypto.randomBytes(SALT_LENGTH);
        const derivedKey = yield* scrypt(password, salt, COST, BLOCK_SIZE, PARALLELIZATION);

        const hash = `${ALGORITHM}$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${salt.toString("hex")}$${derivedKey.toString("hex")}`;

        return {
          hash,
          algorithm: ALGORITHM,
        };
      }),

    verify: (password: string, hash: string) =>
      Effect.gen(function* () {
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password must be a non-empty string",
            }),
          );
        }

        if (!hash || typeof hash !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Hash must be a non-empty string",
            }),
          );
        }

        const parts = hash.split("$");
        if (parts.length !== 6) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash format",
            }),
          );
        }

        const [algorithm, costStr, blockSizeStr, parallelizationStr, saltHex, hashHex] = parts;

        if (algorithm !== ALGORITHM) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: `Unsupported algorithm: ${algorithm}`,
            }),
          );
        }

        const N = parseInt(costStr, 10);
        const r = parseInt(blockSizeStr, 10);
        const p = parseInt(parallelizationStr, 10);
        if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash parameters",
            }),
          );
        }

        const salt = Buffer.from(saltHex, "hex");
        const expectedHash = Buffer.from(hashHex, "hex");
        const derivedKey = yield* scrypt(password, salt, N, r, p);

        if (derivedKey.length !== expectedHash.length) {
          return false;
        }

        // Use timing-safe comparison
        return crypto.timingSafeEqual(derivedKey, expectedHash);
      }),
  };
};

/**
 * Layer that provides the scrypt password hasher
 */
export const ScryptHasherLayer = Layer.succeed(PasswordHasherTag, makeScryptHasher());

/**
 * Backward compatibility: Default password hasher is PBKDF2
 */
export const makePasswordHasher = makePBKDF2Hasher;

/**
 * Backward-compatible Context value that provides the default PBKDF2 password hasher
 */
export const PasswordHasherLive = Context.make(PasswordHasherTag, makePBKDF2Hasher());

/**
 * Layer that provides the default PBKDF2 password hasher
 */
export const PasswordHasherLayer = Layer.succeed(PasswordHasherTag, makePBKDF2Hasher());

/**
 * Layer that provides PBKDF2 password hasher explicitly
 */
export const PBKDF2HasherLive = PasswordHasherLive;
