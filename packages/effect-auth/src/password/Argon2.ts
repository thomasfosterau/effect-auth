/**
 * Argon2id over `effect/crypto`'s `Password` service, which writes and reads
 * the PHC strings. Only a `Kdf` with Argon2id (`NodeCrypto.layerKdf`, Node.js
 * 24.7+ or Bun 1.4+) derives it; on Workers use effect-auth-argon2.
 */
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import { CryptoError, Kdf, Password as CryptoPassword, SecureRandom } from "effect/crypto";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Str from "effect/String";
import * as Errors from "../Errors.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { PasswordHasher } from "./Password.ts";

/** The PHC identifier of the hashes {@link argon2idHasher} writes and verifies. */
export const ARGON2ID = "argon2id";

/**
 * Argon2id cost parameters: `memoryCost` in KiB, `timeCost` passes and
 * `parallelism` lanes.
 */
export interface Argon2Profile {
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

/**
 * The largest costs `verify` runs for a stored hash, so a corrupt or crafted
 * one cannot demand gigabytes of memory or billions of passes.
 */
export interface Argon2VerifyLimits {
  readonly maxMemoryKiB: number;
  readonly maxIterations: number;
  readonly maxParallelism: number;
}

/**
 * Options for {@link argon2idHasher}: costs for new hashes (unset ones from
 * {@link argon2DefaultProfile}) and the verify ceiling (unset ones from
 * {@link argon2DefaultVerifyLimits}).
 */
export interface Argon2Options extends Partial<Argon2Profile>, Partial<Argon2VerifyLimits> {}

/** OWASP's low-memory Argon2id profile: m = 19 MiB, t = 2, p = 1. */
export const argon2DefaultProfile: Argon2Profile = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/**
 * A stronger profile for servers with memory to spare: m = 64 MiB, t = 3,
 * p = 1, about five times the work of {@link argon2DefaultProfile}.
 */
export const argon2ServerProfile: Argon2Profile = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};

/** The default verify ceiling (m ≤ 128 MiB, t ≤ 10, p ≤ 8), above {@link argon2ServerProfile}. */
export const argon2DefaultVerifyLimits: Argon2VerifyLimits = {
  maxMemoryKiB: 131072,
  maxIterations: 10,
  maxParallelism: 8,
};

const MAX_PASSWORD_BYTES = 1024;
// `Password.decode` bounds none of these: a multi-megabyte stored value is
// refused before it is parsed, a salt or digest out of range before the KDF.
const MAX_STORED_HASH_LENGTH = 512;
const MIN_SALT_BYTES = 8;
const MAX_SALT_BYTES = 64;
const MIN_HASH_BYTES = 4;
const MAX_HASH_BYTES = 64;

const encoder = new TextEncoder();

const fail = (message: string, cause?: unknown): Effect.Effect<never, Errors.HashingError> =>
  Effect.fail(new Errors.HashingError(cause === undefined ? { message } : { message, cause }));

const isPositiveInteger = (value: number): boolean => Number.isSafeInteger(value) && value > 0;

const isNonEmptyString = (value: unknown): value is string =>
  P.isString(value) && Str.isNonEmpty(value);

const resolveCosts = (options?: Argon2Options): Argon2Profile => ({
  memoryCost: options?.memoryCost ?? argon2DefaultProfile.memoryCost,
  timeCost: options?.timeCost ?? argon2DefaultProfile.timeCost,
  parallelism: options?.parallelism ?? argon2DefaultProfile.parallelism,
});

const resolveLimits = (options?: Argon2Options): Argon2VerifyLimits => ({
  maxMemoryKiB: options?.maxMemoryKiB ?? argon2DefaultVerifyLimits.maxMemoryKiB,
  maxIterations: options?.maxIterations ?? argon2DefaultVerifyLimits.maxIterations,
  maxParallelism: options?.maxParallelism ?? argon2DefaultVerifyLimits.maxParallelism,
});

/** Why stored costs are over the ceiling, or `undefined` when they are within it. */
const overCeiling = (costs: Argon2Profile, limits: Argon2VerifyLimits): string | undefined => {
  if (costs.memoryCost > limits.maxMemoryKiB) {
    return `m=${costs.memoryCost} is over maxMemoryKiB=${limits.maxMemoryKiB}`;
  }
  if (costs.timeCost > limits.maxIterations) {
    return `t=${costs.timeCost} is over maxIterations=${limits.maxIterations}`;
  }
  if (costs.parallelism > limits.maxParallelism) {
    return `p=${costs.parallelism} is over maxParallelism=${limits.maxParallelism}`;
  }
  return undefined;
};

/**
 * Refuse a configuration whose costs or limits are not positive integers, or
 * whose costs exceed the ceiling: such a hasher would write hashes its own
 * `verify` refuses.
 */
const requireUsableConfig = (costs: Argon2Profile, limits: Argon2VerifyLimits): void => {
  const invalid = Arr.findFirst(
    [
      ["memoryCost", costs.memoryCost],
      ["timeCost", costs.timeCost],
      ["parallelism", costs.parallelism],
      ["maxMemoryKiB", limits.maxMemoryKiB],
      ["maxIterations", limits.maxIterations],
      ["maxParallelism", limits.maxParallelism],
    ] as const,
    ([, value]) => !isPositiveInteger(value),
  );
  if (Option.isSome(invalid)) {
    const [name, value] = invalid.value;
    throw new RangeError(`Argon2 ${name} must be a positive integer, got ${value}`);
  }
  const over = overCeiling(costs, limits);
  if (over !== undefined) {
    throw new RangeError(`Argon2 ${over}: its hashes would not verify`);
  }
};

/**
 * Decode a stored hash and check it is one `verify` runs: argon2id, within
 * the ceiling, with a salt and digest in range. Fails with the reason.
 */
const readStored = (
  hash: string,
  limits: Argon2VerifyLimits,
): Effect.Effect<CryptoPassword.PasswordHash, Errors.HashingError> =>
  Effect.gen(function* () {
    if (hash.length > MAX_STORED_HASH_LENGTH) {
      return yield* fail(`Invalid Argon2 hash: longer than ${MAX_STORED_HASH_LENGTH} characters`);
    }
    const stored = yield* CryptoPassword.decode(hash).pipe(
      Effect.catchTag("CryptoError", (error) =>
        fail("Invalid Argon2 hash: expected $argon2id$v=19$m=...,t=...,p=...$salt$hash", error),
      ),
    );
    const { algorithm } = stored;
    if (!P.isTagged(algorithm, "Argon2id")) {
      return yield* fail(`Invalid Argon2 hash: unsupported algorithm "${algorithm.name}"`);
    }
    const over = overCeiling(
      {
        memoryCost: algorithm.memory,
        timeCost: algorithm.passes,
        parallelism: algorithm.parallelism,
      },
      limits,
    );
    if (over !== undefined) return yield* fail(`Argon2 hash exceeds the verify ceiling: ${over}`);
    if (stored.salt.length < MIN_SALT_BYTES || stored.salt.length > MAX_SALT_BYTES) {
      return yield* fail(
        `Invalid Argon2 hash: salt must be ${MIN_SALT_BYTES} to ${MAX_SALT_BYTES} bytes`,
      );
    }
    if (stored.hash.length < MIN_HASH_BYTES || stored.hash.length > MAX_HASH_BYTES) {
      return yield* fail(
        `Invalid Argon2 hash: digest must be ${MIN_HASH_BYTES} to ${MAX_HASH_BYTES} bytes`,
      );
    }
    return stored;
  });

const kdfFailure = (action: string) => (error: CryptoError.CryptoError) =>
  fail(
    P.isTagged(error.reason, "Unsupported")
      ? "Argon2id is not available on this Kdf layer (it needs NodeCrypto.layerKdf on Node.js 24.7+ or Bun 1.4+)"
      : `Failed to ${action} with Argon2id`,
    error,
  );

/**
 * Adapts an `effect/crypto` {@link CryptoPassword.Password} service that
 * hashes with Argon2id into a {@link PasswordHasher}, adding what the seam
 * promises on top of it.
 *
 * Hashes are standard PHC strings (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`),
 * so hashes written by any other Argon2id implementation, effect-auth-argon2
 * included, verify. `verify` reads every cost from the stored hash; from
 * `options` it reads only the ceiling, and a stored hash over it fails with a
 * `HashingError` before the KDF runs (`Password.verify` itself trusts stored
 * costs). A malformed or non-argon2id hash fails too; a wrong password is
 * `false`; a password over 1,024 UTF-8 bytes is `false` without the KDF.
 * `needsRehash` is true for a hash `hash` would not write now, or one
 * `verify` refuses.
 *
 * `passwords` must hash with `Kdf.argon2id` at the costs in `options`; use
 * {@link argon2idHasherLayer}, which builds it. Throws a `RangeError` when a
 * cost or limit is not a positive integer, or a cost is over the ceiling.
 */
export const argon2idHasher = (
  passwords: typeof CryptoPassword.Password.Service,
  options?: Argon2Options,
): typeof PasswordHasher.Service => {
  const costs = resolveCosts(options);
  const limits = resolveLimits(options);
  requireUsableConfig(costs, limits);

  const refused = (hash: string): boolean =>
    Exit.isFailure(Effect.runSyncExit(readStored(hash, limits)));

  return {
    algorithm: ARGON2ID,

    needsRehash: (hash: string): boolean =>
      refused(hash) ||
      Exit.match(Effect.runSyncExit(passwords.needsRehash(hash)), {
        onFailure: () => true,
        onSuccess: (stale) => stale,
      }),

    hash: Effect.fn("effect-auth.password.hash", { attributes: { algorithm: ARGON2ID } })(
      function* (password: string) {
        if (!isNonEmptyString(password)) {
          return yield* fail("Password must be a non-empty string");
        }
        if (encoder.encode(password).length > MAX_PASSWORD_BYTES) {
          return yield* fail("Password exceeds maximum length");
        }
        const hash = yield* passwords
          .hash(password)
          .pipe(Effect.catchTag("CryptoError", kdfFailure("hash")));
        return { hash, algorithm: ARGON2ID };
      },
    ),

    verify: Effect.fn("effect-auth.password.verify", { attributes: { algorithm: ARGON2ID } })(
      function* (password: string, hash: string) {
        if (!isNonEmptyString(password)) {
          return yield* fail("Password must be a non-empty string");
        }
        if (!isNonEmptyString(hash)) return yield* fail("Hash must be a non-empty string");
        // Anti-DoS: an absurdly long password never reaches the KDF.
        if (encoder.encode(password).length > MAX_PASSWORD_BYTES) return false;
        yield* readStored(hash, limits);
        return yield* passwords
          .verify(password, hash)
          .pipe(Effect.catchTag("CryptoError", kdfFailure("verify")));
      },
    ),
  };
};

/**
 * A layer providing {@link argon2idHasher} as the {@link PasswordHasher}: an
 * `effect/crypto` `Password` service hashing with `Kdf.argon2id` at the
 * configured costs, over the `Kdf` the application provides
 * (`NodeCrypto.layerKdf` from `@effect/platform-node` or `@effect/platform-bun`).
 *
 * @example
 * ```ts
 * import { Effect, Layer } from "effect"
 * import { Kdf } from "effect/crypto"
 * import { Password } from "@thomasfosterau/effect-auth"
 *
 * // In an application: Layer.provide(NodeCrypto.layerKdf) from @effect/platform-node.
 * const HasherLive = Password.argon2idHasherLayer(Password.argon2ServerProfile)
 *
 * const program = Effect.gen(function* () {
 *   const hasher = yield* Password.PasswordHasher
 *   return hasher.algorithm
 * }).pipe(Effect.provide(HasherLive.pipe(Layer.provide(Kdf.layerWebCrypto))))
 *
 * console.log(await Effect.runPromise(program)) // "argon2id"
 * ```
 */
export const argon2idHasherLayer = (
  options?: Argon2Options,
): Layer.Layer<PasswordHasher, never, Kdf.Kdf> => {
  const costs = resolveCosts(options);
  return Layer.effect(
    PasswordHasher,
    Effect.gen(function* () {
      return argon2idHasher(yield* CryptoPassword.Password, options);
    }),
  ).pipe(
    Layer.provide(
      CryptoPassword.layer({
        algorithm: Kdf.argon2id({
          memory: costs.memoryCost,
          passes: costs.timeCost,
          parallelism: costs.parallelism,
        }),
      }),
    ),
    Layer.provide(Layer.succeed(SecureRandom.SecureRandom, PlatformCrypto.instance)),
  );
};
