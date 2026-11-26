/**
 * The scrypt password hasher, Node-only (or Workers with `nodejs_compat`)
 * because `effect/crypto` has no scrypt, hence its own subpath. Put it beside
 * the default in a `multiAlgorithmVerifier` to verify old hashes, and sign-in
 * rehashes them.
 *
 * @module scrypt
 */

import * as crypto from "node:crypto";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";
import { Hex } from "effect/encoding";
import * as Errors from "../Errors.ts";
import { hashFields6, kdfHash, kdfVerify, parseStoredParam, PasswordHasher } from "./Password.ts";

// Floors of the caps `verify` enforces on the N, r and p read from a stored
// hash. The effective caps are these or the hasher's own configured values,
// whichever is higher, so a hash the hasher itself writes always verifies.
const SCRYPT_MIN_MEMORY_CAP = 256 * 1024 * 1024; // 256 MiB
const SCRYPT_MAX_N_CAP = 2 ** 20;
const SCRYPT_MAX_R_CAP = 32;
const SCRYPT_MAX_P_CAP = 16;

/** Bytes OpenSSL's scrypt allocates for N, r and p; also the `maxmem` passed to Node. */
const scryptMemory = (N: number, r: number, p: number): number => 128 * r * (N + p + 2);

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
    salt: Uint8Array,
    N: number,
    r: number,
    p: number,
  ): Effect.Effect<Uint8Array, Errors.HashingError> =>
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
      const started = Result.try(() =>
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
        ),
      );
      if (Result.isFailure(started)) {
        // Node rejects invalid parameters by throwing synchronously (a
        // RangeError). That is a typed failure too, not a defect.
        fail(started.failure);
      }
    });

  return {
    algorithm: ALGORITHM,

    needsRehash: (hash: string): boolean => {
      const fields = hashFields6(hash);
      if (fields === undefined) return true;
      const [algorithm, costStr, blockSizeStr, parallelizationStr] = fields;
      if (algorithm !== ALGORITHM) return true;
      const N = parseStoredParam(costStr);
      const r = parseStoredParam(blockSizeStr);
      const p = parseStoredParam(parallelizationStr);
      // verify refuses this hash, so it has to be replaced.
      if (refusedParams(N, r, p) !== undefined) return true;
      // Each parameter raises the cost, so only a weaker stored set is upgraded.
      return N < COST || r < BLOCK_SIZE || p < PARALLELIZATION;
    },

    hash: kdfHash(ALGORITHM, (password) =>
      Effect.gen(function* () {
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

        return `${ALGORITHM}$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${Hex.encode(salt)}$${Hex.encode(derivedKey)}`;
      }),
    ),

    verify: kdfVerify(
      ALGORITHM,
      hashFields6,
      ([, costStr, blockSizeStr, parallelizationStr, saltHex, hashHex]) => {
        const N = parseStoredParam(costStr);
        const r = parseStoredParam(blockSizeStr);
        const p = parseStoredParam(parallelizationStr);
        // Refuse out-of-range parameters before the KDF. Node can still reject a
        // set within the caps (OpenSSL's own limits); the scrypt helper maps that
        // to a HashingError too.
        return { params: { N, r, p }, refused: refusedParams(N, r, p), saltHex, hashHex };
      },
      (password, salt, _keyLength, { N, r, p }) => scrypt(password, salt, N, r, p),
    ),
  };
};

/**
 * Layer providing the scrypt hasher as the {@link PasswordHasher} (see
 * {@link scryptHasher}). Node.js only.
 */
export const layer = (options?: {
  readonly cost?: number;
  readonly blockSize?: number;
  readonly parallelization?: number;
}): Layer.Layer<PasswordHasher> => Layer.succeed(PasswordHasher, scryptHasher(options));
