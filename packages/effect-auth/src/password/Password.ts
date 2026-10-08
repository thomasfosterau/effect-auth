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
import type * as Types from "../Types.ts";
import * as Errors from "../Errors.ts";

/**
 * Tag for PasswordHasher service
 *
 * Core password hashing interface (trait)
 * Implement this interface to support custom password hashing algorithms
 */
export class PasswordHasher extends Context.Service<
  PasswordHasher,
  {
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
    readonly verify: (
      password: string,
      hash: string,
    ) => Effect.Effect<boolean, Errors.HashingError>;

    /**
     * Returns true when the stored hash should be re-hashed using the current
     * algorithm and parameters (e.g. after upgrading iteration count or switching
     * algorithm). When present in `signIn`, the stored hash is silently upgraded
     * on a successful login so users are migrated without any downtime.
     */
    readonly needsRehash?: (hash: string) => boolean;
  }
>()("@effect-auth/PasswordHasher") {
  /**
   * Layer providing the default hasher: PBKDF2-SHA256 with OWASP parameters
   * (see {@link pbkdf2Hasher}).
   */
  static readonly layer = () => Layer.succeed(PasswordHasher, pbkdf2Hasher());

  /**
   * Layer providing the scrypt hasher (memory-hard; PHC-format output, see
   * {@link scryptHasher}).
   */
  static readonly layerScrypt = (options?: {
    readonly cost?: number;
    readonly blockSize?: number;
    readonly parallelization?: number;
  }) => Layer.succeed(PasswordHasher, scryptHasher(options));
}

/**
 * Tag for MultiAlgorithmVerifier service
 *
 * Multi-algorithm password verifier
 * Supports verifying passwords against different hash formats,
 * enabling seamless migration between algorithms
 */
export class MultiAlgorithmVerifier extends Context.Service<
  MultiAlgorithmVerifier,
  {
    /**
     * Verify a password against a hash, automatically detecting the algorithm
     * from the PHC format string
     */
    readonly verify: (
      password: string,
      hash: string,
    ) => Effect.Effect<boolean, Errors.HashingError>;
  }
>()("@effect-auth/MultiAlgorithmVerifier") {
  /**
   * Layer that verifies passwords against any of the given hashers, sniffing
   * the algorithm from the PHC-format hash (see {@link multiAlgorithmVerifier}).
   */
  static readonly layer = (hashers: readonly (typeof PasswordHasher.Service)[]) =>
    Layer.succeed(MultiAlgorithmVerifier, multiAlgorithmVerifier(hashers));
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
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { Password } from "@thomasfosterau/effect-auth"
 *
 * // During a migration, one verifier accepts hashes from both algorithms.
 * const verifier = Password.multiAlgorithmVerifier([Password.pbkdf2Hasher(), Password.scryptHasher()])
 *
 * const program = Effect.gen(function* () {
 *   // A hash written by the old algorithm still verifies.
 *   const legacy = yield* Password.pbkdf2Hasher().hash("correct horse battery")
 *   // Will automatically detect which algorithm was used.
 *   assert.equal(yield* verifier.verify("correct horse battery", legacy.hash), true)
 *   assert.equal(yield* verifier.verify("wrong password", legacy.hash), false)
 * })
 *
 * await Effect.runPromise(program)
 * ```
 */
export const multiAlgorithmVerifier = (
  hashers: readonly (typeof PasswordHasher.Service)[],
): typeof MultiAlgorithmVerifier.Service => {
  const hasherMap = new Map(hashers.map((h) => [h.algorithm, h]));

  return {
    verify: (password, hash) =>
      Effect.gen(function* () {
        const algorithm = yield* parseAlgorithm(hash);
        const hasher = hasherMap.get(algorithm);

        if (!hasher) {
          return yield* new Errors.HashingError({
            message: `Unsupported algorithm: ${algorithm}. Available: ${Array.from(hasherMap.keys()).join(", ")}`,
          });
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
} from "../Types.ts";

/**
 * PBKDF2 Password Hasher implementing the PasswordHasher trait
 * Following OWASP guidelines for secure password hashing
 */
export const pbkdf2Hasher = (): typeof PasswordHasher.Service => {
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

    hash: Effect.fn("effect-auth.password.hash", {
      attributes: { algorithm: ALGORITHM },
    })(function* (password: string) {
      if (!password || typeof password !== "string") {
        return yield* new Errors.HashingError({
          message: "Password must be a non-empty string",
        });
      }

      if (password.length < 1) {
        return yield* new Errors.HashingError({
          message: "Password cannot be empty",
        });
      }

      if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return yield* new Errors.HashingError({
          message: "Password exceeds maximum length",
        });
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

    verify: Effect.fn("effect-auth.password.verify", {
      attributes: { algorithm: ALGORITHM },
    })(function* (password: string, hash: string) {
      if (!password || typeof password !== "string") {
        return yield* new Errors.HashingError({
          message: "Password must be a non-empty string",
        });
      }

      if (!hash || typeof hash !== "string") {
        return yield* new Errors.HashingError({
          message: "Hash must be a non-empty string",
        });
      }

      // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
      if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return false;
      }

      const parts = hash.split("$");

      if (parts.length !== 4) {
        return yield* new Errors.HashingError({
          message: "Invalid hash format",
        });
      }

      const [algorithm, iterationsStr, saltHex, hashHex] = parts;

      if (algorithm !== ALGORITHM) {
        return yield* new Errors.HashingError({
          message: `Unsupported algorithm: ${algorithm}`,
        });
      }

      const iterCount = parseInt(iterationsStr!, 10);
      if (!Number.isFinite(iterCount) || iterCount <= 0) {
        return yield* new Errors.HashingError({
          message: "Invalid hash parameters",
        });
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

// Floors of the caps `verify` enforces on the N, r and p read from a stored
// hash. The effective caps are these or the hasher's own configured values,
// whichever is higher, so a hash the hasher itself writes always verifies.
const SCRYPT_MIN_MEMORY_CAP = 256 * 1024 * 1024; // 256 MiB
const SCRYPT_MAX_N_CAP = 2 ** 20;
const SCRYPT_MAX_R_CAP = 32;
const SCRYPT_MAX_P_CAP = 16;

/** Bytes OpenSSL's scrypt allocates for N, r and p; also the `maxmem` passed to Node. */
const scryptMemory = (N: number, r: number, p: number): number => 128 * r * (N + p + 2);

/** Parses a stored decimal parameter. Anything else (sign, hex, exponent, empty) is NaN. */
const parseStoredParam = (text: string): number => (/^[0-9]+$/.test(text) ? Number(text) : NaN);

/**
 * scrypt Password Hasher implementing the PasswordHasher trait.
 *
 * Uses Node's built-in `crypto.scrypt` (dependency-free) with OWASP-recommended
 * parameters (N=2^17, r=8, p=1). scrypt is memory-hard, making it more
 * resistant to GPU/ASIC attacks than PBKDF2.
 *
 * PHC-style format: `scrypt$N$r$p$salt$hash` (N/r/p are stored so parameters
 * can be tuned without breaking existing hashes).
 *
 * `verify` reads N, r and p from the stored hash and refuses, before running
 * the KDF, any set outside these limits. The refusal is a `HashingError`:
 * - N is a power of two with 2 ≤ N ≤ max(2^20, cost);
 * - r is an integer with 1 ≤ r ≤ max(32, blockSize);
 * - p is an integer with 1 ≤ p ≤ max(16, parallelization);
 * - the memory a derivation needs, 128 * r * (N + p + 2) bytes, is at most
 *   max(256 MiB, the memory the configured cost, blockSize and parallelization need).
 *
 * The defaults need about 128 MiB and pass. A hash written with valid
 * configured parameters always verifies, even above 256 MiB, but a crafted
 * stored hash cannot make verify allocate gigabytes. `hash` applies the same
 * checks to the configured parameters, so a hasher never writes a hash its own
 * `verify` would refuse (e.g. `blockSize: 0`, which Node itself accepts).
 *
 * `needsRehash` returns true for a hash that `verify` would refuse, and for one
 * whose N, r or p is below the configured value. A stored set that is at least
 * as strong in every parameter is kept; one that is weaker in any parameter is
 * replaced by the configured set, even where it was stronger in another.
 */
export const scryptHasher = (options?: {
  readonly cost?: number;
  readonly blockSize?: number;
  readonly parallelization?: number;
}): typeof PasswordHasher.Service => {
  const ALGORITHM = "scrypt";
  const COST = options?.cost ?? 131072; // 2^17, OWASP recommended
  const BLOCK_SIZE = options?.blockSize ?? 8;
  const PARALLELIZATION = options?.parallelization ?? 1;
  const KEY_LENGTH = 64;
  const SALT_LENGTH = 16;
  // Caps on the parameters `verify` accepts from a stored hash (see scryptHasher).
  // Only a usable configured value may raise a cap: a NaN, Infinity or
  // fractional option (which `hash` refuses anyway) must not turn a cap into
  // NaN or Infinity and so disable it.
  const usable = (n: number): number => (Number.isSafeInteger(n) && n > 0 ? n : 0);
  const MAX_N = Math.max(SCRYPT_MAX_N_CAP, usable(COST));
  const MAX_R = Math.max(SCRYPT_MAX_R_CAP, usable(BLOCK_SIZE));
  const MAX_P = Math.max(SCRYPT_MAX_P_CAP, usable(PARALLELIZATION));
  const MAX_MEMORY = Math.max(
    SCRYPT_MIN_MEMORY_CAP,
    scryptMemory(usable(COST), usable(BLOCK_SIZE), usable(PARALLELIZATION)),
  );

  /**
   * Why a parameter set is refused, or `undefined` when it is within the caps.
   * It runs before any allocation, so a crafted hash never makes Node allocate
   * past the caps.
   */
  const refusedParams = (N: number, r: number, p: number): string | undefined => {
    if (!Number.isSafeInteger(N) || N < 2 || 2 ** Math.round(Math.log2(N)) !== N) {
      return "N must be a power of two, at least 2";
    }
    if (N > MAX_N) return `N exceeds ${MAX_N}`;
    if (!Number.isSafeInteger(r) || r < 1 || r > MAX_R) {
      return `r must be an integer from 1 to ${MAX_R}`;
    }
    if (!Number.isSafeInteger(p) || p < 1 || p > MAX_P) {
      return `p must be an integer from 1 to ${MAX_P}`;
    }
    if (scryptMemory(N, r, p) > MAX_MEMORY) {
      return `scrypt would need more than ${MAX_MEMORY} bytes`;
    }
    return undefined;
  };

  const scrypt = (
    password: string,
    salt: Buffer,
    N: number,
    r: number,
    p: number,
  ): Effect.Effect<Buffer, Errors.HashingError> =>
    Effect.callback((resume) => {
      const fail = (cause: unknown) =>
        resume(
          Effect.fail(
            new Errors.HashingError({
              message: "Failed to derive scrypt key",
              cause,
            }),
          ),
        );
      try {
        crypto.scrypt(
          password,
          salt,
          KEY_LENGTH,
          // OpenSSL's scrypt allocates 128 * r * (N + p + 2) bytes and rejects
          // a smaller maxmem (ERR_CRYPTO_INVALID_SCRYPT_PARAMS). The old
          // 256 * N * r fell short whenever p + 2 > N.
          { N, r, p, maxmem: scryptMemory(N, r, p) },
          (error, derivedKey) => {
            if (error) {
              fail(error);
            } else {
              resume(Effect.succeed(derivedKey));
            }
          },
        );
      } catch (error) {
        // Node rejects invalid parameters by throwing synchronously (a
        // RangeError). That is a typed failure too, not a defect.
        fail(error);
      }
    });

  return {
    algorithm: ALGORITHM,

    needsRehash: (hash: string): boolean => {
      const parts = hash.split("$");
      if (parts.length !== 6) return true;
      const [algorithm, costStr, blockSizeStr, parallelizationStr] = parts;
      if (algorithm !== ALGORITHM) return true;
      const N = parseStoredParam(costStr!);
      const r = parseStoredParam(blockSizeStr!);
      const p = parseStoredParam(parallelizationStr!);
      // verify refuses this hash, so it has to be replaced.
      if (refusedParams(N, r, p) !== undefined) return true;
      // Each parameter raises the cost, so only a weaker stored set is upgraded.
      return N < COST || r < BLOCK_SIZE || p < PARALLELIZATION;
    },

    hash: Effect.fn("effect-auth.password.hash", {
      attributes: { algorithm: ALGORITHM },
    })(function* (password: string) {
      if (!password || typeof password !== "string") {
        return yield* new Errors.HashingError({
          message: "Password must be a non-empty string",
        });
      }

      if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return yield* new Errors.HashingError({
          message: "Password exceeds maximum length",
        });
      }

      // Never write a hash this hasher's own verify would refuse: Node accepts
      // some configurations (blockSize 0) that the stored-hash checks reject.
      const misconfigured = refusedParams(COST, BLOCK_SIZE, PARALLELIZATION);
      if (misconfigured !== undefined) {
        return yield* new Errors.HashingError({
          message: `Invalid scrypt configuration: ${misconfigured}`,
        });
      }

      const salt = crypto.randomBytes(SALT_LENGTH);
      const derivedKey = yield* scrypt(password, salt, COST, BLOCK_SIZE, PARALLELIZATION);

      const hash = `${ALGORITHM}$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${salt.toString("hex")}$${derivedKey.toString("hex")}`;

      return {
        hash,
        algorithm: ALGORITHM,
      };
    }),

    verify: Effect.fn("effect-auth.password.verify", {
      attributes: { algorithm: ALGORITHM },
    })(function* (password: string, hash: string) {
      if (!password || typeof password !== "string") {
        return yield* new Errors.HashingError({
          message: "Password must be a non-empty string",
        });
      }

      if (!hash || typeof hash !== "string") {
        return yield* new Errors.HashingError({
          message: "Hash must be a non-empty string",
        });
      }

      // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
      if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return false;
      }

      const parts = hash.split("$");
      if (parts.length !== 6) {
        return yield* new Errors.HashingError({
          message: "Invalid hash format",
        });
      }

      const [algorithm, costStr, blockSizeStr, parallelizationStr, saltHex, hashHex] = parts;

      if (algorithm !== ALGORITHM) {
        return yield* new Errors.HashingError({
          message: `Unsupported algorithm: ${algorithm}`,
        });
      }

      const N = parseStoredParam(costStr!);
      const r = parseStoredParam(blockSizeStr!);
      const p = parseStoredParam(parallelizationStr!);
      // Refuse out-of-range parameters before the KDF. Node can still reject a
      // set within the caps (OpenSSL's own limits); the scrypt helper maps that
      // to a HashingError too.
      const refused = refusedParams(N, r, p);
      if (refused !== undefined) {
        return yield* new Errors.HashingError({ message: `Invalid hash parameters: ${refused}` });
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
