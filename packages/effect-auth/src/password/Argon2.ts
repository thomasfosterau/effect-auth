/**
 * Argon2id password hashing over Effect's `Kdf` service (`effect/crypto`).
 *
 * The core writes and reads the PHC string; the derivation is the `Kdf`
 * layer's. Only `NodeCrypto.layerKdf` (`@effect/platform-node` or
 * `@effect/platform-bun`, on Node.js 24.7+ or Bun 1.4+) derives Argon2id:
 * `Kdf.layerWebCrypto` and Cloudflare Workers cannot, so use PBKDF2 there.
 */
import { Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import { Kdf, SecureRandom } from "effect/crypto";
import { Base64 } from "effect/encoding";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Result from "effect/Result";
import * as Str from "effect/String";
import * as Errors from "../Errors.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { timingSafeEqualBytes } from "../TokenHash.ts";
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

const SALT_LENGTH = 16;
const HASH_LENGTH = 32;
const MAX_PASSWORD_BYTES = 1024;
// Bounds on a stored salt and digest: RFC 9106's 8-byte salt floor, and the
// largest any common implementation writes (64 bytes each).
const MIN_SALT_BYTES = 8;
const MAX_SALT_BYTES = 64;
const MIN_HASH_BYTES = 4;
const MAX_HASH_BYTES = 64;
const MAX_STORED_HASH_LENGTH = 512;
const COST_NAMES: ReadonlyArray<string> = ["m", "t", "p"];

const encoder = new TextEncoder();

const fail = (message: string, cause?: unknown): Effect.Effect<never, Errors.HashingError> =>
  Effect.fail(new Errors.HashingError(cause === undefined ? { message } : { message, cause }));

const invalidHash = (detail: string) => fail(`Invalid Argon2 hash: ${detail}`);

const isPositiveInteger = (value: number): boolean => Number.isSafeInteger(value) && value > 0;

const parsePositiveInt = (value: string | undefined): number =>
  value !== undefined && /^[0-9]+$/.test(value) && Number(value) > 0 ? Number(value) : Number.NaN;

/** PHC base64: standard alphabet, no padding. Refuses any non-canonical spelling. */
const decodePhcBase64 = (text: string): Uint8Array | undefined => {
  if (!/^[A-Za-z0-9+/]*$/.test(text) || text.length % 4 === 1) return undefined;
  const decoded = Base64.decode(text.padEnd(text.length + ((4 - (text.length % 4)) % 4), "="));
  if (Result.isFailure(decoded) || encodePhcBase64(decoded.success) !== text) return undefined;
  return decoded.success;
};

const encodePhcBase64 = (bytes: Uint8Array): string => Base64.encode(bytes).replace(/=+$/, "");

interface StoredArgon2 {
  readonly costs: Argon2Profile;
  readonly salt: Uint8Array;
  readonly digest: Uint8Array;
}

/**
 * Parse the `m=..,t=..,p=..` segment, in any order. A malformed pair, an
 * unknown or repeated name (`m=4294967295,m=256` must not read as either) or
 * a value that is not a positive decimal integer is refused.
 */
const parseCosts = (parameters: string): Result.Result<Argon2Profile, string> => {
  const pairs = Arr.map(parameters.split(","), (parameter) => {
    const [name, value, ...rest] = parameter.split("=");
    return { parameter, name, value, extra: Arr.isReadonlyArrayNonEmpty(rest) };
  });
  const malformed = Arr.findFirst(
    pairs,
    ({ name, value, extra }) => name === undefined || value === undefined || extra,
  );
  if (Option.isSome(malformed)) {
    return Result.fail(`malformed parameter "${malformed.value.parameter}"`);
  }
  const names = Arr.map(pairs, ({ name }) => name);
  const unexpected = Arr.findFirst(names, (name) => !Arr.contains(COST_NAMES, name));
  if (Option.isSome(unexpected)) return Result.fail(`unknown parameter "${unexpected.value}"`);
  if (Arr.dedupe(names).length !== names.length) {
    return Result.fail(`repeated parameter in "${parameters}"`);
  }
  const costs: Record<string, number> = R.fromEntries(
    Arr.map(pairs, ({ name, value }): readonly [string, number] => [name, parsePositiveInt(value)]),
  );
  const profile = {
    memoryCost: costs["m"] ?? Number.NaN,
    timeCost: costs["t"] ?? Number.NaN,
    parallelism: costs["p"] ?? Number.NaN,
  };
  return Arr.every([profile.memoryCost, profile.timeCost, profile.parallelism], Number.isFinite)
    ? Result.succeed(profile)
    : Result.fail(`malformed parameters "${parameters}"`);
};

/**
 * Read a stored `$argon2id$v=19$m=…,t=…,p=…$salt$hash`, refusing anything
 * this hasher cannot recompute: another variant (the `Kdf` service derives
 * only Argon2id), another version, malformed costs, salt or digest.
 */
const parseStored = (hash: string): Result.Result<StoredArgon2, string> => {
  if (hash.length > MAX_STORED_HASH_LENGTH) {
    return Result.fail(`longer than ${MAX_STORED_HASH_LENGTH} characters`);
  }
  const segments = hash.split("$");
  const [empty, variant, version, parameters, saltText, digestText] = segments;
  if (
    segments.length !== 6 ||
    empty !== "" ||
    variant === undefined ||
    version === undefined ||
    parameters === undefined ||
    saltText === undefined ||
    digestText === undefined
  ) {
    return Result.fail("expected $argon2id$v=19$m=...,t=...,p=...$salt$hash");
  }
  if (variant !== ARGON2ID) return Result.fail(`unsupported variant "${variant}"`);
  if (version !== "v=19") {
    return Result.fail(`unsupported version "${version}" (only v=19 is supported)`);
  }
  const costs = parseCosts(parameters);
  if (Result.isFailure(costs)) return Result.fail(costs.failure);
  const salt = decodePhcBase64(saltText);
  if (salt === undefined || salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) {
    return Result.fail("malformed salt");
  }
  const digest = decodePhcBase64(digestText);
  if (digest === undefined || digest.length < MIN_HASH_BYTES || digest.length > MAX_HASH_BYTES) {
    return Result.fail("malformed digest");
  }
  return Result.succeed({ costs: costs.success, salt, digest });
};

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

const isNonEmptyString = (value: unknown): value is string =>
  P.isString(value) && Str.isNonEmpty(value);

/**
 * Builds an Argon2id {@link PasswordHasher} over the given `Kdf` service.
 *
 * Hashes are standard PHC strings (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`,
 * 16-byte salt, 32-byte digest), so hashes written by any other Argon2id
 * implementation, effect-auth-argon2 included, verify. `verify` reads every
 * cost, the salt and the digest length from the stored hash; the one thing it
 * reads from `options` is the ceiling, and a stored hash over it fails with a
 * `HashingError` before the KDF runs. A malformed or non-argon2id hash fails
 * too; a wrong password is `false`. `needsRehash` is true for a hash with a
 * cost below the configured one, or one `verify` refuses.
 *
 * Throws a `RangeError` when a cost or limit is not a positive integer, or a
 * cost is over the ceiling.
 *
 * On a `Kdf` without Argon2id (`Kdf.layerWebCrypto`, Cloudflare Workers, Node
 * before 24.7), `hash` and `verify` fail with a `HashingError`.
 */
export const argon2idHasher = (
  kdf: typeof Kdf.Kdf.Service,
  random: typeof SecureRandom.SecureRandom.Service,
  options?: Argon2Options,
): typeof PasswordHasher.Service => {
  const costs: Argon2Profile = {
    memoryCost: options?.memoryCost ?? argon2DefaultProfile.memoryCost,
    timeCost: options?.timeCost ?? argon2DefaultProfile.timeCost,
    parallelism: options?.parallelism ?? argon2DefaultProfile.parallelism,
  };
  const limits: Argon2VerifyLimits = {
    maxMemoryKiB: options?.maxMemoryKiB ?? argon2DefaultVerifyLimits.maxMemoryKiB,
    maxIterations: options?.maxIterations ?? argon2DefaultVerifyLimits.maxIterations,
    maxParallelism: options?.maxParallelism ?? argon2DefaultVerifyLimits.maxParallelism,
  };
  requireUsableConfig(costs, limits);

  const derive = (password: Uint8Array, salt: Uint8Array, length: number, at: Argon2Profile) =>
    kdf
      .derive(
        Kdf.argon2id({ memory: at.memoryCost, passes: at.timeCost, parallelism: at.parallelism }),
        password,
        { salt, length },
      )
      .pipe(
        Effect.catchTag("CryptoError", (error) =>
          fail(
            error.reason._tag === "Unsupported"
              ? "Argon2id is not available on this Kdf layer (it needs NodeCrypto.layerKdf on Node.js 24.7+ or Bun 1.4+)"
              : "Failed to derive Argon2id key",
            error,
          ),
        ),
      );

  return {
    algorithm: ARGON2ID,

    needsRehash: (hash: string): boolean => {
      const stored = parseStored(hash);
      if (Result.isFailure(stored)) return true;
      const { memoryCost, timeCost, parallelism } = stored.success.costs;
      return (
        overCeiling(stored.success.costs, limits) !== undefined ||
        memoryCost < costs.memoryCost ||
        timeCost < costs.timeCost ||
        parallelism < costs.parallelism ||
        stored.success.digest.length !== HASH_LENGTH
      );
    },

    hash: Effect.fn("effect-auth.password.hash", { attributes: { algorithm: ARGON2ID } })(
      function* (password: string) {
        if (!isNonEmptyString(password)) {
          return yield* fail("Password must be a non-empty string");
        }
        const secret = encoder.encode(password);
        if (secret.length > MAX_PASSWORD_BYTES) {
          return yield* fail("Password exceeds maximum length");
        }
        const salt = yield* random.randomBytes(SALT_LENGTH);
        const digest = yield* derive(secret, salt, HASH_LENGTH, costs);
        const params = `m=${costs.memoryCost},t=${costs.timeCost},p=${costs.parallelism}`;
        const hash = `$${ARGON2ID}$v=19$${params}$${encodePhcBase64(salt)}$${encodePhcBase64(digest)}`;
        return { hash, algorithm: ARGON2ID };
      },
    ),

    verify: Effect.fn("effect-auth.password.verify", { attributes: { algorithm: ARGON2ID } })(
      function* (password: string, hash: string) {
        if (!isNonEmptyString(password)) {
          return yield* fail("Password must be a non-empty string");
        }
        if (!isNonEmptyString(hash)) return yield* fail("Hash must be a non-empty string");
        const secret = encoder.encode(password);
        // Anti-DoS: an absurdly long password never reaches the KDF.
        if (secret.length > MAX_PASSWORD_BYTES) return false;
        const stored = parseStored(hash);
        if (Result.isFailure(stored)) return yield* invalidHash(stored.failure);
        const over = overCeiling(stored.success.costs, limits);
        if (over !== undefined) {
          return yield* fail(`Argon2 hash exceeds the verify ceiling: ${over}`);
        }
        const { costs: at, salt, digest } = stored.success;
        const derived = yield* derive(secret, salt, digest.length, at);
        return timingSafeEqualBytes(derived, digest);
      },
    ),
  };
};

/**
 * A layer providing {@link argon2idHasher} as the {@link PasswordHasher}, over
 * the `Kdf` service the application provides: `NodeCrypto.layerKdf` from
 * `@effect/platform-node` or `@effect/platform-bun`.
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
): Layer.Layer<PasswordHasher, never, Kdf.Kdf> =>
  Layer.effect(
    PasswordHasher,
    Effect.gen(function* () {
      const kdf = yield* Kdf.Kdf;
      return argon2idHasher(kdf, PlatformCrypto.instance, options);
    }),
  );
