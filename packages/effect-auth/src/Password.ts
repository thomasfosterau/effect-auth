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
export interface PasswordHasherShape {
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

  /**
   * Returns true when the stored hash should be re-hashed using the current
   * algorithm and parameters (e.g. after upgrading iteration count or switching
   * algorithm). When present in `signIn`, the stored hash is silently upgraded
   * on a successful login so users are migrated without any downtime.
   */
  readonly needsRehash?: (hash: string) => boolean;
}

/**
 * Multi-algorithm password verifier
 * Supports verifying passwords against different hash formats,
 * enabling seamless migration between algorithms
 */
export interface MultiAlgorithmVerifierShape {
  /**
   * Verify a password against a hash, automatically detecting the algorithm
   * from the PHC format string
   */
  readonly verify: (password: string, hash: string) => Effect.Effect<boolean, Errors.HashingError>;
}

/**
 * Tag for PasswordHasher service
 */
export class PasswordHasher extends Context.Service<PasswordHasher, PasswordHasherShape>()(
  "@effect-auth/PasswordHasher",
) {
  /**
   * Layer providing the default hasher: PBKDF2-SHA256 with OWASP parameters
   * (see {@link makePBKDF2Hasher}).
   */
  static readonly layer = () => Layer.succeed(PasswordHasher, makePBKDF2Hasher());

  /**
   * Layer providing the scrypt hasher (memory-hard; PHC-format output, see
   * {@link makeScryptHasher}).
   */
  static readonly layerScrypt = (options?: {
    readonly cost?: number;
    readonly blockSize?: number;
    readonly parallelization?: number;
  }) => Layer.succeed(PasswordHasher, makeScryptHasher(options));
}

/**
 * Tag for MultiAlgorithmVerifier service
 */
export class MultiAlgorithmVerifier extends Context.Service<
  MultiAlgorithmVerifier,
  MultiAlgorithmVerifierShape
>()("@effect-auth/MultiAlgorithmVerifier") {
  /**
   * Layer that verifies passwords against any of the given hashers, sniffing
   * the algorithm from the PHC-format hash (see {@link makeMultiAlgorithmVerifier}).
   */
  static readonly layer = (hashers: readonly PasswordHasherShape[]) =>
    Layer.succeed(MultiAlgorithmVerifier, makeMultiAlgorithmVerifier(hashers));
}

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
    // PHC-string hashes (e.g. Argon2's `$argon2id$v=19$...`) begin with `$`,
    // so the algorithm id is the second segment; the library's own
    // `algo$...` format (pbkdf2/scrypt) carries it in the first.
    return Effect.succeed(parts[0] === "" ? parts[1]! : parts[0]!);
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
  hashers: readonly PasswordHasherShape[],
): MultiAlgorithmVerifierShape => {
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

import * as crypto from "node:crypto";

// Anti-DoS: reject inputs longer than this before running any KDF.
// Legitimate passwords are always well below this threshold.
const MAX_PASSWORD_BYTES = 1024;

const pbkdf2 = (
  password: string,
  salt: Buffer,
  iterations: number,
  keylen: number,
  digest: string,
): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, derivedKey) =>
      err ? reject(err) : resolve(derivedKey),
    );
  });

export type {
  /** Re-export of {@link Types.HashedPassword} for convenience. */
  HashedPassword,
} from "./Types.js";

/**
 * PBKDF2 Password Hasher implementing the PasswordHasher trait
 * Following OWASP guidelines for secure password hashing
 */
export const makePBKDF2Hasher = (): PasswordHasherShape => {
  const ALGORITHM = "pbkdf2-sha256";
  // OWASP recommended minimum for SHA-256: 600,000 iterations (2023)
  const ITERATIONS = 600000;
  // SHA-256 produces a 32-byte digest; using more bytes adds nothing and
  // reduces cost for the defender while an attacker can crack block-by-block.
  const KEY_LENGTH = 32;
  const SALT_LENGTH = 16;

  return {
    algorithm: ALGORITHM,

    needsRehash: (hash: string): boolean => {
      const parts = hash.split("$");
      if (parts.length !== 4) return true;
      const [algorithm, iterationsStr, , hashHex] = parts;
      if (algorithm !== ALGORITHM) return true;
      const iters = parseInt(iterationsStr!, 10);
      if (!Number.isFinite(iters) || iters < ITERATIONS) return true;
      // Stored key length must match current KEY_LENGTH.
      const storedKeyLen = Buffer.from(hashHex!, "hex").length;
      if (storedKeyLen !== KEY_LENGTH) return true;
      return false;
    },

    hash: (password: string) =>
      Effect.gen(function* () {
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

        if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password exceeds maximum length",
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

        // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
        if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
          return false;
        }

        const parts = hash.split("$");

        if (parts.length !== 4) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash format",
            }),
          );
        }

        const [algorithm, iterationsStr, saltHex, hashHex] = parts;

        if (algorithm !== ALGORITHM) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: `Unsupported algorithm: ${algorithm}`,
            }),
          );
        }

        const iterCount = parseInt(iterationsStr!, 10);
        if (!Number.isFinite(iterCount) || iterCount <= 0) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash parameters",
            }),
          );
        }

        const salt = Buffer.from(saltHex!, "hex");
        const expectedHash = Buffer.from(hashHex!, "hex");

        // Derive using the stored key length so hashes produced with an older
        // KEY_LENGTH value still verify correctly (needsRehash detects and
        // upgrades them on the next successful login).
        const derivedKey = yield* Effect.tryPromise({
          try: () => pbkdf2(password, salt, iterCount, expectedHash.length, "sha256"),
          catch: (error) =>
            new Errors.HashingError({
              message: "Failed to verify password",
              cause: error,
            }),
        });

        if (derivedKey.length !== expectedHash.length) {
          return false;
        }

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
}): PasswordHasherShape => {
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

    needsRehash: (hash: string): boolean => {
      const parts = hash.split("$");
      if (parts.length !== 6) return true;
      const [algorithm, costStr] = parts;
      if (algorithm !== ALGORITHM) return true;
      const N = parseInt(costStr!, 10);
      if (!Number.isFinite(N) || N < COST) return true;
      return false;
    },

    hash: (password: string) =>
      Effect.gen(function* () {
        if (!password || typeof password !== "string") {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password must be a non-empty string",
            }),
          );
        }

        if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Password exceeds maximum length",
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

        // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
        if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
          return false;
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

        const N = parseInt(costStr!, 10);
        const r = parseInt(blockSizeStr!, 10);
        const p = parseInt(parallelizationStr!, 10);
        if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) {
          return yield* Effect.fail(
            new Errors.HashingError({
              message: "Invalid hash parameters",
            }),
          );
        }

        const salt = Buffer.from(saltHex!, "hex");
        const expectedHash = Buffer.from(hashHex!, "hex");
        const derivedKey = yield* scrypt(password, salt, N, r, p);

        if (derivedKey.length !== expectedHash.length) {
          return false;
        }

        // Use timing-safe comparison
        return crypto.timingSafeEqual(derivedKey, expectedHash);
      }),
  };
};
