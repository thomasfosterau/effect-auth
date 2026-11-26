/**
 * Argon2id over WebAssembly (the RustCrypto crate built by
 * `@thomasfosterau/argon2`), compiled once at module scope, so it runs on Node,
 * Bun, Deno and Workers. `verify` reads the costs from the stored PHC string,
 * so older hashes keep verifying, and refuses one over the verify ceiling
 * before hashing.
 *
 * @module argon2/argon2
 */
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { HashingError } from "@thomasfosterau/effect-auth/Errors";
import { Password } from "@thomasfosterau/effect-auth";
import {
  ARGON2ID,
  HASH_LENGTH,
  SALT_LENGTH,
  isWithinMaxLength,
  resolveVerifyLimits,
  requireHashablePassword,
  requireNonEmptyHash,
  requireNonEmptyPassword,
  resolveOptions,
  type Argon2Options,
  type Argon2Profile,
  type Argon2VerifyLimits,
} from "./Common.ts";
import { hashArgon2id, verifyArgon2 } from "./Wasm.ts";

const { PasswordHasher } = Password;
type HashedPassword = Password.HashedPassword;
type PasswordHasherService = typeof Password.PasswordHasher.Service;

/** The three Argon2 variants `verify` accepts in a stored PHC string. */
const variants: ReadonlyArray<string> = ["argon2d", "argon2i", "argon2id"];

/**
 * Salt bytes from the platform Web Crypto API — available on Node ≥ 20, Bun,
 * Deno and Workers alike, which `node:crypto.randomBytes` is not.
 */
const randomSalt = (): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

const invalidHash = (detail: string): Effect.Effect<never, HashingError> =>
  Effect.fail(new HashingError({ message: `Invalid Argon2 hash: ${detail}` }));

const parsePositiveInt = (value?: string): number => {
  if (value === undefined || !/^\d+$/.test(value)) return Number.NaN;
  const parsed = Number.parseInt(value, 10);
  return parsed > 0 ? parsed : Number.NaN;
};

/**
 * The longest stored hash `verify` copies into the kernel. The longest PHC
 * string the kernel can verify is about 210 characters: the header with
 * ten-digit `m`, `t` and `p`, a 48-byte salt (64 base64 characters) and a
 * 64-byte digest (86), the crate's maxima. 512 leaves room for any honest
 * hash and keeps a multi-megabyte stored value from being copied into linear
 * memory, which would grow it for the isolate's life.
 */
const MAX_STORED_HASH_LENGTH = 512;

/** The cost parameters a stored PHC string must carry, each exactly once. */
const COST_NAMES: ReadonlyArray<string> = ["m", "t", "p"];

/**
 * Parse the `m=..,t=..,p=..` segment, in any order. A parameter that is not
 * `name=value`, an unknown or repeated name (`m=4294967295,m=256` must not
 * read as either), a missing cost, or a value that is not a positive decimal
 * integer is refused with the reason.
 */
const parseCosts = (
  parameters: string,
): { readonly costs: Argon2Profile } | { readonly refused: string } => {
  const pairs = Arr.map(parameters.split(","), (parameter) => {
    const [name, value, ...rest] = parameter.split("=");
    return { parameter, name, value, extra: Arr.isReadonlyArrayNonEmpty(rest) };
  });
  const malformed = Arr.findFirst(
    pairs,
    ({ name, value, extra }) => name === undefined || value === undefined || extra,
  );
  if (Option.isSome(malformed)) {
    return { refused: `malformed parameter "${malformed.value.parameter}"` };
  }
  const names = Arr.map(pairs, ({ name }) => name);
  const unexpected = Arr.findFirst(names, (name) => !Arr.contains(COST_NAMES, name));
  if (Option.isSome(unexpected)) return { refused: `unknown parameter "${unexpected.value}"` };
  if (Arr.dedupe(names).length !== names.length) {
    return { refused: `repeated parameter in "${parameters}"` };
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
    ? { costs: profile }
    : { refused: `malformed parameters "${parameters}"` };
};

const overCeiling = (detail: string): Effect.Effect<never, HashingError> =>
  Effect.fail(new HashingError({ message: `Argon2 hash exceeds the verify ceiling: ${detail}` }));

/** What a stored PHC string's header states, once {@link readHash} accepts it. */
interface StoredHash {
  readonly variant: string;
  readonly costs: Argon2Profile;
  /** Salt length in bytes, from its unpadded base64 length. */
  readonly saltBytes: number;
  /** Digest length in bytes, from its unpadded base64 length. */
  readonly digestBytes: number;
}

/** A refused header: why, and whether only the verify ceiling refused it. */
interface RefusedHash {
  readonly refused: string;
  readonly overCeiling: boolean;
}

type ReadHash = { readonly stored: StoredHash } | RefusedHash;

const malformedHeader = (detail: string): RefusedHash => ({ refused: detail, overCeiling: false });
const overCeilingHeader = (detail: string): RefusedHash => ({ refused: detail, overCeiling: true });

/** Bytes an unpadded base64 string of `length` characters decodes to. */
const base64Bytes = (length: number): number => Math.floor((length * 3) / 4);

/**
 * Read a stored PHC string's header before handing it to the kernel, or say
 * why it is refused (`overCeiling` when only the verify ceiling refuses it).
 *
 * Deliberately tolerant about the order of the `m`/`t`/`p` parameters (the PHC
 * spec does not fix it) and about which Argon2 variant produced the hash, but
 * strict about everything else: a hash we cannot recompute must surface as a
 * `HashingError` rather than a silent `false`. The kernel would also verify
 * Argon2 `v=16`; this check keeps refusing it, as earlier releases did. The
 * salt and digest are left to the kernel, which reports a malformed or
 * out-of-range one as unverifiable.
 *
 * The costs must also sit within `limits`. The kernel allocates `m`
 * KiB in linear memory, which never shrinks, so a stored hash with a huge `m`
 * would leave the isolate holding it (on Workers, past its 128 MiB, killing
 * it); a huge `t` or `p` would spin. Such a hash is refused here, before the
 * kernel is entered. So is a stored string over `MAX_STORED_HASH_LENGTH`,
 * before anything is copied into linear memory, and one whose parameters
 * repeat or add a name (so the ceiling reads the costs the kernel would).
 */
const readHash = (hash: string, limits: Argon2VerifyLimits): ReadHash => {
  if (hash.length > MAX_STORED_HASH_LENGTH) {
    return malformedHeader(`longer than ${MAX_STORED_HASH_LENGTH} characters`);
  }
  const segments = hash.split("$");
  // "$argon2id$v=19$m=..,t=..,p=..$salt$digest" splits into a leading empty
  // segment plus five fields.
  if (segments.length !== 6 || segments[0] !== "") {
    return malformedHeader("expected $argon2<variant>$v=19$m=...,t=...,p=...$salt$hash");
  }
  // The length check above guarantees all six segments exist, so the
  // defaults are never used.
  const [, variant = "", version = "", parameters = "", salt = "", digest = ""] = segments;

  if (!Arr.contains(variants, variant)) return malformedHeader(`unsupported variant "${variant}"`);
  if (version !== "v=19") {
    return malformedHeader(`unsupported version "${version}" (only v=19 is supported)`);
  }

  const parsed = parseCosts(parameters);
  if ("refused" in parsed) return malformedHeader(parsed.refused);
  const { memoryCost, timeCost, parallelism } = parsed.costs;
  if (memoryCost > limits.maxMemoryKiB) {
    return overCeilingHeader(`m=${memoryCost} is over maxMemoryKiB=${limits.maxMemoryKiB}`);
  }
  if (timeCost > limits.maxIterations) {
    return overCeilingHeader(`t=${timeCost} is over maxIterations=${limits.maxIterations}`);
  }
  if (parallelism > limits.maxParallelism) {
    return overCeilingHeader(`p=${parallelism} is over maxParallelism=${limits.maxParallelism}`);
  }
  return {
    stored: {
      variant,
      costs: parsed.costs,
      saltBytes: base64Bytes(salt.length),
      digestBytes: base64Bytes(digest.length),
    },
  };
};

/** {@link readHash} as an effect: a refused header is a `HashingError`. */
const checkHash = (hash: string, limits: Argon2VerifyLimits): Effect.Effect<void, HashingError> =>
  Effect.suspend(() => {
    const read = readHash(hash, limits);
    if ("stored" in read) return Effect.void;
    return read.overCeiling ? overCeiling(read.refused) : invalidHash(read.refused);
  });

/**
 * True when `stored` is weaker than what the hasher writes now: another
 * variant, or a lower `m`, `t` or `p`, or a shorter salt or digest. A stored
 * set stronger in every respect is kept; one weaker in any is replaced,
 * even where it was stronger in another.
 */
const isWeaker = (stored: StoredHash, costs: Argon2Profile): boolean =>
  stored.variant !== ARGON2ID ||
  stored.costs.memoryCost < costs.memoryCost ||
  stored.costs.timeCost < costs.timeCost ||
  stored.costs.parallelism < costs.parallelism ||
  stored.saltBytes < SALT_LENGTH ||
  stored.digestBytes < HASH_LENGTH;

const isPositiveInteger = (value: number): boolean => Number.isSafeInteger(value) && value > 0;

/**
 * Refuse a configuration whose costs or verify limits are not positive
 * integers (a `NaN` cost would slip past every `>` check), or whose hashing
 * costs exceed the limits: such a hasher would write hashes its own `verify`
 * refuses, locking out every user it signs up.
 */
const requireWithinCeiling = (costs: Argon2Profile, limits: Argon2VerifyLimits): void => {
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
  const checks = [
    ["memoryCost", costs.memoryCost, "maxMemoryKiB", limits.maxMemoryKiB],
    ["timeCost", costs.timeCost, "maxIterations", limits.maxIterations],
    ["parallelism", costs.parallelism, "maxParallelism", limits.maxParallelism],
  ] as const;
  const over = Arr.findFirst(checks, ([, value, , max]) => value > max);
  if (Option.isNone(over)) return;
  const [cost, value, limit, max] = over.value;
  throw new RangeError(
    `Argon2 ${cost}=${value} is over ${limit}=${max}: its hashes would not verify`,
  );
};

/**
 * Create an Argon2id {@link Password.PasswordHasher} backed by WebAssembly.
 *
 * Defaults to OWASP's low-memory profile (m = 19 MiB, t = 2, p = 1) so the
 * hasher is safe to run on Cloudflare Workers; pass `serverProfile` (or your
 * own numbers) on a plain Node deployment.
 *
 * `verify` refuses, with a `HashingError` and before running the KDF, a
 * stored hash whose costs exceed the verify ceiling (`maxMemoryKiB` 131072,
 * `maxIterations` 10, `maxParallelism` 8 unless configured). Throws a
 * `RangeError` when a limit is not a positive integer, or when the configured
 * costs exceed the ceiling, since their hashes would not verify.
 *
 * `needsRehash` is true for a stored hash `verify` refuses, and for one weaker
 * than the configured costs: another variant (argon2i, argon2d), a lower `m`,
 * `t` or `p`, or a shorter salt or digest. The core's sign-in flows call it
 * after a successful verify and store a fresh hash, so raising the costs
 * upgrades each user on their next sign-in. A hash at least as strong in
 * every parameter is kept.
 *
 * @example
 * ```ts
 * import { argon2Hasher, argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2/Argon2";
 * import { serverProfile } from "@thomasfosterau/effect-auth-argon2/Common";
 *
 * const hasher = argon2Hasher();               // OWASP low-memory defaults
 * const layer = argon2HasherLayer(serverProfile); // 64 MiB, t = 3 on Node
 * ```
 */
export const argon2Hasher = (options?: Argon2Options): PasswordHasherService => {
  const costs = resolveOptions(options);
  const limits = resolveVerifyLimits(options);
  requireWithinCeiling(costs, limits);

  return {
    algorithm: ARGON2ID,

    needsRehash: (hash: string): boolean => {
      const read = readHash(hash, limits);
      return "refused" in read || isWeaker(read.stored, costs);
    },

    hash: Effect.fn("effect-auth.password.hash", {
      attributes: { algorithm: ARGON2ID },
    })(function* (password: string) {
      yield* requireHashablePassword(password);

      const phc = yield* Effect.mapError(
        Effect.suspend(() => Effect.fromResult(hashArgon2id(password, randomSalt(), costs))),
        (cause) => new HashingError({ message: "Failed to hash password with Argon2id", cause }),
      );

      return { hash: phc, algorithm: ARGON2ID } satisfies HashedPassword;
    }),

    verify: Effect.fn("effect-auth.password.verify", {
      attributes: { algorithm: ARGON2ID },
    })(function* (password: string, hash: string) {
      yield* requireNonEmptyPassword(password);
      yield* requireNonEmptyHash(hash);

      // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
      if (!isWithinMaxLength(password)) return false;

      // Cost parameters come from the stored hash, never from `options`, so
      // hashes written under a different configuration still verify; only the
      // ceiling comes from `options`.
      yield* checkHash(hash, limits);

      const verdict = yield* Effect.mapError(
        Effect.suspend(() => Effect.fromResult(verifyArgon2(password, hash))),
        (cause) =>
          new HashingError({ message: "Failed to verify password against Argon2 hash", cause }),
      );
      if (verdict === "unverifiable") {
        return yield* invalidHash("its costs, salt or digest cannot be recomputed");
      }
      return verdict === "match";
    }),
  };
};

/**
 * A `Layer` providing {@link Password.PasswordHasher} backed by the WASM
 * Argon2id hasher. Use in place of `PasswordHasher.layer()` to make Argon2id
 * the default hasher for new passwords. Like {@link argon2Hasher}, it throws
 * a `RangeError` when the configured costs exceed the verify ceiling.
 */
export const argon2HasherLayer = (options?: Argon2Options): Layer.Layer<Password.PasswordHasher> =>
  Layer.succeed(PasswordHasher, argon2Hasher(options));
