/**
 * Password Hashing Traits and Multi-Algorithm Support
 *
 * Inspired by Rust's password_hash crate, this module provides:
 * - Trait-based API (PasswordHasher interface) for algorithm-agnostic hashing
 * - PHC string format support (algorithm$params$salt$hash)
 * - Multi-algorithm verification for seamless migration
 * - Extensible design for custom algorithms
 */

import { Context, Effect, Layer, Result } from "effect";
import * as Arr from "effect/Array";
import { Digest, Kdf, SecureRandom } from "effect/crypto";
import { Hex } from "effect/encoding";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import type * as Types from "../Types.ts";
import * as Errors from "../Errors.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { timingSafeEqualBytes } from "../TokenHash.ts";

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
   * (see {@link pbkdf2Hasher}). `options.iterations` overrides the 600,000
   * default, e.g. a cheap count in tests; production should keep the default.
   */
  static readonly layer = (options?: { readonly iterations?: number | undefined }) =>
    Layer.succeed(PasswordHasher, pbkdf2Hasher(options));
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
    const [first, second] = hash.split("$");
    if (first === undefined || second === undefined) {
      return Effect.fail(
        new Errors.HashingError({
          message: "Invalid hash format: missing algorithm identifier",
        }),
      );
    }
    // PHC-string hashes (e.g. Argon2's `$argon2id$v=19$...`) begin with `$`,
    // so the algorithm id is the second segment; the library's own
    // `algo$...` format (pbkdf2/scrypt) carries it in the first.
    return Effect.succeed(first === "" ? second : first);
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
 * import { scryptHasher } from "@thomasfosterau/effect-auth/scrypt"
 *
 * // During a migration, one verifier accepts hashes from both algorithms.
 * const verifier = Password.multiAlgorithmVerifier([Password.pbkdf2Hasher(), scryptHasher()])
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
  // The last hasher registered for an algorithm wins; the error lists each
  // algorithm once, in first-registered order.
  const findHasher = (algorithm: string) =>
    Arr.findLast(hashers, (h) => h.algorithm === algorithm).pipe(Option.getOrUndefined);
  const available = Arr.dedupe(Arr.map(hashers, (h) => h.algorithm));

  return {
    verify: (password, hash) =>
      Effect.gen(function* () {
        const algorithm = yield* parseAlgorithm(hash);
        const hasher = findHasher(algorithm);

        if (!hasher) {
          return yield* new Errors.HashingError({
            message: `Unsupported algorithm: ${algorithm}. Available: ${available.join(", ")}`,
          });
        }

        return yield* hasher.verify(password, hash);
      }),
  };
};

const encoder = new TextEncoder();

/** The UTF-8 byte length of `text`. */
const utf8Length = (text: string): number => encoder.encode(text).length;

// Anti-DoS: reject inputs longer than this before running any KDF.
// Legitimate passwords are always well below this threshold.
/** Parses a stored decimal parameter. Anything else (sign, hex, exponent, empty) is NaN. */
/** @internal */
export const parseStoredParam = (text: string): number =>
  /^[0-9]+$/.test(text) ? Number(text) : NaN;
const MAX_PASSWORD_BYTES = 1024;

/** The `$`-separated fields of a stored hash, when there are exactly four. */
const hashFields4 = (hash: string): readonly [string, string, string, string] | undefined => {
  const [a, b, c, d, ...rest] = hash.split("$");
  return a !== undefined &&
    b !== undefined &&
    c !== undefined &&
    d !== undefined &&
    Arr.isReadonlyArrayEmpty(rest)
    ? [a, b, c, d]
    : undefined;
};

/**
 * The `$`-separated fields of a stored hash, when there are exactly six.
 *
 * @internal
 */
export const hashFields6 = (
  hash: string,
): readonly [string, string, string, string, string, string] | undefined => {
  const [a, b, c, d, e, f, ...rest] = hash.split("$");
  return a !== undefined &&
    b !== undefined &&
    c !== undefined &&
    d !== undefined &&
    e !== undefined &&
    f !== undefined &&
    Arr.isReadonlyArrayEmpty(rest)
    ? [a, b, c, d, e, f]
    : undefined;
};

/** Refuse a password `hash` will not hash: empty, not a string, or over the byte cap. */
const refuseUnhashablePassword = (password: string): Effect.Effect<void, Errors.HashingError> => {
  if (!password || !P.isString(password)) {
    return Effect.fail(
      new Errors.HashingError({
        message: "Password must be a non-empty string",
      }),
    );
  }
  if (utf8Length(password) > MAX_PASSWORD_BYTES) {
    return Effect.fail(
      new Errors.HashingError({
        message: "Password exceeds maximum length",
      }),
    );
  }
  return Effect.void;
};

/**
 * The checks every `verify` runs before its KDF: both inputs are non-empty
 * strings, the stored hash splits into the expected fields and names
 * `algorithm`. `undefined` means the password is over the byte cap, which
 * verifies as `false` without running the KDF (anti-DoS).
 */
const verifiableFields = <Fields extends ReadonlyArray<string>>(
  password: string,
  hash: string,
  algorithm: string,
  splitFields: (hash: string) => Fields | undefined,
): Effect.Effect<Fields | undefined, Errors.HashingError> =>
  Effect.gen(function* () {
    if (!password || !P.isString(password)) {
      return yield* new Errors.HashingError({
        message: "Password must be a non-empty string",
      });
    }

    if (!hash || !P.isString(hash)) {
      return yield* new Errors.HashingError({
        message: "Hash must be a non-empty string",
      });
    }

    // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
    if (utf8Length(password) > MAX_PASSWORD_BYTES) {
      return undefined;
    }

    const fields = splitFields(hash);
    if (fields === undefined) {
      return yield* new Errors.HashingError({
        message: "Invalid hash format",
      });
    }

    if (fields[0] !== algorithm) {
      return yield* new Errors.HashingError({
        message: `Unsupported algorithm: ${fields[0]}`,
      });
    }
    return fields;
  });

/** Compare a derived key with the stored one in constant time. */
const derivedKeyMatches = (derivedKey: Uint8Array, expectedHash: Uint8Array): boolean =>
  timingSafeEqualBytes(derivedKey, expectedHash);

/** Hex-decoded bytes, or `undefined` when `text` is not hex. */
const hexBytes = (text: string): Uint8Array | undefined => Result.getOrUndefined(Hex.decode(text));

/**
 * A hasher's `hash`: refuse an unhashable password, then let `encode` derive
 * the key and format the stored hash string.
 */
/** @internal */
export const kdfHash = (
  algorithm: string,
  encode: (password: string) => Effect.Effect<string, Errors.HashingError>,
) =>
  Effect.fn("effect-auth.password.hash", {
    attributes: { algorithm },
  })(function* (password: string) {
    yield* refuseUnhashablePassword(password);
    const hash = yield* encode(password);
    return { hash, algorithm };
  });

/**
 * What a `verify` reads from a stored hash's fields before running its KDF.
 *
 * @internal
 */
export interface StoredHash<Params> {
  /** The KDF parameters the hash was written with. */
  readonly params: Params;
  /** Why the parameters are refused, or `undefined` when they are within the caps. */
  readonly refused: string | undefined;
  readonly saltHex: string;
  readonly hashHex: string;
}

/**
 * A hasher's `verify`: run the shared pre-KDF checks, refuse out-of-range
 * stored parameters before the KDF, re-derive the key with `deriveKey`, and
 * compare in constant time.
 */
/** @internal */
export const kdfVerify = <Fields extends ReadonlyArray<string>, Params>(
  algorithm: string,
  splitFields: (hash: string) => Fields | undefined,
  readStored: (fields: Fields) => StoredHash<Params>,
  deriveKey: (
    password: string,
    salt: Uint8Array,
    keyLength: number,
    params: Params,
  ) => Effect.Effect<Uint8Array, Errors.HashingError>,
) =>
  Effect.fn("effect-auth.password.verify", {
    attributes: { algorithm },
  })(function* (password: string, hash: string) {
    const fields = yield* verifiableFields(password, hash, algorithm, splitFields);
    if (fields === undefined) return false;
    const stored = readStored(fields);
    if (stored.refused !== undefined) {
      return yield* new Errors.HashingError({
        message: `Invalid hash parameters: ${stored.refused}`,
      });
    }
    const salt = hexBytes(stored.saltHex);
    const expectedHash = hexBytes(stored.hashHex);
    if (salt === undefined || expectedHash === undefined) {
      return yield* new Errors.HashingError({ message: "Invalid hash format" });
    }
    const derivedKey = yield* deriveKey(password, salt, expectedHash.length, stored.params);
    return derivedKeyMatches(derivedKey, expectedHash);
  });

export type {
  /** Re-export of {@link Types.HashedPassword} for convenience. */
  HashedPassword,
} from "../Types.ts";

// The largest iteration count a hasher is configured with: an int32, as Node's
// `crypto.pbkdf2` took, which every hash written before WebCrypto kept to.
const PBKDF2_MAX_ITERATIONS = 2 ** 31 - 1;
// Floor of the cap `verify` enforces on the iteration count read from a stored
// hash (about 8x the 600,000 default). The effective cap is this or the
// hasher's configured count, whichever is higher (see pbkdf2Hasher).
const PBKDF2_ITERATIONS_CAP = 5000000;

/**
 * PBKDF2 Password Hasher implementing the PasswordHasher trait.
 * Following OWASP guidelines for secure password hashing.
 *
 * Hashes are `pbkdf2-sha256$iterations$salt$hash`. `verify` reads the
 * iteration count from the stored hash, so hashes made at any count still verify,
 * up to the cap described below.
 *
 * `iterations` defaults to 600,000, the OWASP figure for PBKDF2-HMAC-SHA256.
 * Lower it only where the cost is not the point (such as in tests); the default
 * is the production setting. On Cloudflare Workers the default costs about
 * 75 ms of CPU per hash or verify, more than the Free plan's 10 ms per request.
 * It must be an integer from 1 to 2147483647.
 * `hash` refuses any other value with a
 * `HashingError`, so a hasher never writes a hash its own `verify` would refuse.
 *
 * `verify` refuses, with a `HashingError` and before running PBKDF2, a stored
 * count above max(5,000,000, the configured count), so a crafted stored hash
 * cannot make it burn minutes of CPU. The configured count itself always
 * verifies, even above 5,000,000. A non-finite or otherwise unusable `iterations`
 * option does not raise the cap. A hash written at more than 5,000,000
 * iterations verifies only on a hasher configured at that count or higher, so
 * lowering `iterations` below such a count makes those hashes unverifiable.
 *
 * `needsRehash` returns true for a stored hash with fewer iterations than the
 * configured count, so a hash made at a lower count is upgraded on the next
 * successful sign-in, and for a hash `verify` would refuse.
 *
 * The key is derived with `effect/crypto`'s `Kdf` (WebCrypto PBKDF2 by default,
 * so it runs on Workers and in the browser) and the salt drawn from
 * `SecureRandom`; `options.kdf` and `options.random` substitute either.
 */
export const pbkdf2Hasher = (options?: {
  readonly iterations?: number | undefined;
  readonly kdf?: typeof Kdf.Kdf.Service | undefined;
  readonly random?: typeof SecureRandom.SecureRandom.Service | undefined;
}): typeof PasswordHasher.Service => {
  const kdf = options?.kdf ?? PlatformCrypto.kdf();
  const random = options?.random ?? PlatformCrypto.instance;
  const ALGORITHM = "pbkdf2-sha256";
  // OWASP recommended minimum for SHA-256: 600,000 iterations (2023)
  const ITERATIONS = options?.iterations ?? 600000;
  const iterationsUsable =
    Number.isSafeInteger(ITERATIONS) && ITERATIONS >= 1 && ITERATIONS <= PBKDF2_MAX_ITERATIONS;
  // Only a usable configured count may raise the cap: a NaN, Infinity or
  // out-of-range option (which `hash` refuses anyway) must not lift it.
  const MAX_ITERATIONS = Math.max(PBKDF2_ITERATIONS_CAP, iterationsUsable ? ITERATIONS : 0);
  // SHA-256 produces a 32-byte digest; using more bytes adds nothing and
  // reduces cost for the defender while an attacker can crack block-by-block.
  const KEY_LENGTH = 32;
  const SALT_LENGTH = 16;

  /**
   * Why a stored iteration count is refused, or `undefined` when it is within
   * the cap. It runs before the KDF, so a crafted hash never makes PBKDF2 run
   * past the cap.
   */
  const refusedIterations = (iters: number): string | undefined => {
    if (!Number.isSafeInteger(iters) || iters < 1) {
      return "iterations must be a positive integer";
    }
    if (iters > MAX_ITERATIONS) return `iterations exceeds ${MAX_ITERATIONS}`;
    return undefined;
  };

  const derive = (
    password: string,
    salt: Uint8Array,
    iterations: number,
    length: number,
    operation: "hash" | "verify",
  ): Effect.Effect<Uint8Array, Errors.HashingError> =>
    kdf
      .derive(Kdf.pbkdf2({ hash: Digest.sha256, iterations }), encoder.encode(password), {
        salt,
        length,
      })
      .pipe(
        Effect.mapError(
          (cause) =>
            new Errors.HashingError({
              message: `Failed to ${operation} password`,
              cause,
            }),
        ),
      );

  return {
    algorithm: ALGORITHM,

    needsRehash: (hash: string): boolean => {
      const fields = hashFields4(hash);
      if (fields === undefined) return true;
      const [algorithm, iterationsStr, , hashHex] = fields;
      if (algorithm !== ALGORITHM) return true;
      const iters = parseStoredParam(iterationsStr);
      // verify refuses this hash, so it has to be replaced.
      if (refusedIterations(iters) !== undefined || iters < ITERATIONS) return true;
      // Stored key length must match current KEY_LENGTH.
      const storedKeyLen = hexBytes(hashHex)?.length;
      if (storedKeyLen !== KEY_LENGTH) return true;
      return false;
    },

    hash: kdfHash(ALGORITHM, (password) =>
      Effect.gen(function* () {
        // Never write a hash this hasher's own verify would refuse.
        if (!iterationsUsable) {
          return yield* new Errors.HashingError({
            message: `Invalid PBKDF2 configuration: iterations must be an integer from 1 to ${PBKDF2_MAX_ITERATIONS}`,
          });
        }

        const salt = yield* random.randomBytes(SALT_LENGTH);
        const derivedKey = yield* derive(password, salt, ITERATIONS, KEY_LENGTH, "hash");

        // Format: algorithm$iterations$salt$hash
        return `${ALGORITHM}$${ITERATIONS}$${Hex.encode(salt)}$${Hex.encode(derivedKey)}`;
      }),
    ),

    verify: kdfVerify(
      ALGORITHM,
      hashFields4,
      ([, iterationsStr, saltHex, hashHex]) => {
        // Strict decimal parse, as for scrypt's N, r and p: `parseInt` would read
        // "1e9" as 1 and "600000abc" as 600000. Refused before the KDF, above the cap.
        const iterCount = parseStoredParam(iterationsStr);
        return { params: iterCount, refused: refusedIterations(iterCount), saltHex, hashHex };
      },
      // Derive using the stored key length so hashes produced with an older
      // KEY_LENGTH value still verify correctly (needsRehash detects and
      // upgrades them on the next successful login).
      (password, salt, keyLength, iterCount) =>
        derive(password, salt, iterCount, keyLength, "verify"),
    ),
  };
};
