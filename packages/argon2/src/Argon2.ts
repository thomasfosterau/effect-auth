/**
 * Argon2id password hasher backed by pure WebAssembly
 * ([`hash-wasm`](https://github.com/Daninet/hash-wasm), MIT).
 *
 * This is the package's default backend: it has no native module and no
 * `node:` imports, so it runs unchanged on Node, Bun, Deno, and edge runtimes
 * such as Cloudflare Workers. Randomness comes from the platform Web Crypto
 * API (`globalThis.crypto`), the same source core effect-auth's
 * `PlatformCrypto` layer uses.
 *
 * Emitted hashes are standard PHC strings
 * (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) and `verify` parses the cost
 * parameters, salt and digest length out of the *stored* hash rather than
 * assuming the configured ones — so hashes written by `@node-rs/argon2`, by an
 * older configuration of this package, or by any other Argon2 implementation
 * keep verifying after a parameter change.
 *
 * @module argon2/argon2
 */
import { Array as Arr, Effect, Layer, Option, Record as Rec } from "effect";
import { argon2d, argon2i, argon2id } from "hash-wasm";
import { HashingError, Password } from "@thomasfosterau/effect-auth";
import {
  ARGON2ID,
  HASH_LENGTH,
  SALT_LENGTH,
  isWithinMaxLength,
  requireHashablePassword,
  requireNonEmptyHash,
  requireNonEmptyPassword,
  resolveOptions,
  type Argon2Options,
} from "./Common.ts";

const { PasswordHasher } = Password;
type HashedPassword = Password.HashedPassword;
type PasswordHasherService = typeof Password.PasswordHasher.Service;

/** The three Argon2 variants `verify` accepts in a stored PHC string. */
const variants = { argon2d, argon2i, argon2id };

type Variant = keyof typeof variants;

const isVariant = (value: string): value is Variant => value in variants;

/**
 * Salt bytes from the platform Web Crypto API — available on Node ≥ 20, Bun,
 * Deno and Workers alike, which `node:crypto.randomBytes` is not.
 */
const randomSalt = (): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

const decodeBase64 = (value: string): Uint8Array => {
  // PHC uses the standard base64 alphabet with the padding stripped; `atob`
  // tolerates the missing padding and is available on every target runtime.
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
};

/** Constant-time comparison; `node:crypto.timingSafeEqual` is not portable to Workers. */
const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  // Every byte is visited regardless of where the first mismatch is; the
  // lengths are equal, so `b[index]` is always defined.
  const difference = a.reduce((acc, byte, index) => acc | (byte ^ (b[index] ?? 0)), 0);
  return difference === 0;
};

/** The parameters recovered from a stored PHC string. */
interface ParsedHash {
  readonly variant: Variant;
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
  readonly salt: Uint8Array;
  readonly digest: Uint8Array;
}

const invalidHash = (detail: string): Effect.Effect<never, HashingError> =>
  Effect.fail(new HashingError({ message: `Invalid Argon2 hash: ${detail}` }));

const parsePositiveInt = (value: string | undefined): number => {
  if (value === undefined || !/^\d+$/.test(value)) return Number.NaN;
  const parsed = Number.parseInt(value, 10);
  return parsed > 0 ? parsed : Number.NaN;
};

/**
 * Parse a PHC string into the parameters needed to recompute its digest.
 *
 * Deliberately tolerant about the order of the `m`/`t`/`p` parameters (the PHC
 * spec does not fix it) and about which Argon2 variant produced the hash, but
 * strict about everything else: a hash we cannot recompute must surface as a
 * `HashingError` rather than a silent `false`.
 */
const parseHash = (hash: string): Effect.Effect<ParsedHash, HashingError> =>
  Effect.suspend(() => {
    const segments = hash.split("$");
    // "$argon2id$v=19$m=..,t=..,p=..$salt$digest" splits into a leading empty
    // segment plus five fields.
    if (segments.length !== 6 || segments[0] !== "") {
      return invalidHash("expected $argon2<variant>$v=19$m=...,t=...,p=...$salt$hash");
    }
    // The length check above guarantees all six segments exist, so the
    // defaults are never used.
    const [, variant = "", version = "", parameters = "", salt = "", digest = ""] = segments;

    if (!isVariant(variant)) {
      return invalidHash(`unsupported variant "${variant}"`);
    }
    if (version !== "v=19") {
      return invalidHash(`unsupported version "${version}" (only v=19 is supported)`);
    }

    const pairs = Arr.map(parameters.split(","), (parameter) => {
      const [name, value] = parameter.split("=");
      return { parameter, name, value };
    });
    const malformed = Arr.findFirst(
      pairs,
      ({ name, value }) => name === undefined || value === undefined,
    );
    if (Option.isSome(malformed)) {
      return invalidHash(`malformed parameter "${malformed.value.parameter}"`);
    }
    const costs: Record<string, number> = Rec.fromEntries(
      Arr.map(pairs, ({ name = "", value }): readonly [string, number] => [
        name,
        parsePositiveInt(value),
      ]),
    );
    const memoryCost = costs["m"] ?? Number.NaN;
    const timeCost = costs["t"] ?? Number.NaN;
    const parallelism = costs["p"] ?? Number.NaN;
    if (
      !Number.isFinite(memoryCost) ||
      !Number.isFinite(timeCost) ||
      !Number.isFinite(parallelism)
    ) {
      return invalidHash(`malformed parameters "${parameters}"`);
    }

    return Effect.try({
      try: (): ParsedHash => ({
        variant,
        memoryCost,
        timeCost,
        parallelism,
        salt: decodeBase64(salt),
        digest: decodeBase64(digest),
      }),
      catch: (cause) =>
        new HashingError({ message: "Invalid Argon2 hash: malformed base64", cause }),
    });
  });

/**
 * Create an Argon2id {@link Password.PasswordHasher} backed by WebAssembly.
 *
 * Defaults to OWASP's low-memory profile (m = 19 MiB, t = 2, p = 1) so the
 * hasher is safe to run on Cloudflare Workers; pass `serverProfile` (or your
 * own numbers) on a plain Node deployment.
 *
 * @example
 * ```ts
 * import { argon2Hasher, argon2HasherLayer, serverProfile } from "@thomasfosterau/effect-auth-argon2";
 *
 * const hasher = argon2Hasher();               // OWASP low-memory defaults
 * const layer = argon2HasherLayer(serverProfile); // 64 MiB, t = 3 on Node
 * ```
 */
export const argon2Hasher = (options?: Argon2Options): PasswordHasherService => {
  const { memoryCost, parallelism, timeCost } = resolveOptions(options);

  return {
    algorithm: ARGON2ID,

    hash: Effect.fn("effect-auth.password.hash", {
      attributes: { algorithm: ARGON2ID },
    })(function* (password: string) {
      yield* requireHashablePassword(password);

      const phc = yield* Effect.tryPromise({
        try: () =>
          argon2id({
            password,
            salt: randomSalt(),
            iterations: timeCost,
            parallelism,
            memorySize: memoryCost,
            hashLength: HASH_LENGTH,
            outputType: "encoded" as const,
          }),
        catch: (cause) =>
          new HashingError({ message: "Failed to hash password with Argon2id", cause }),
      });

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
      // hashes written under a different configuration still verify.
      const parsed = yield* parseHash(hash);

      const computed = yield* Effect.tryPromise({
        try: () =>
          variants[parsed.variant]({
            password,
            salt: parsed.salt,
            iterations: parsed.timeCost,
            parallelism: parsed.parallelism,
            memorySize: parsed.memoryCost,
            hashLength: parsed.digest.length,
            outputType: "binary" as const,
          }),
        catch: (cause) =>
          new HashingError({
            message: "Failed to verify password against Argon2 hash",
            cause,
          }),
      });

      return timingSafeEqual(computed, parsed.digest);
    }),
  };
};

/**
 * A `Layer` providing {@link Password.PasswordHasher} backed by the WASM
 * Argon2id hasher. Use in place of `PasswordHasher.layer()` to make Argon2id
 * the default hasher for new passwords.
 */
export const argon2HasherLayer = (options?: Argon2Options): Layer.Layer<Password.PasswordHasher> =>
  Layer.succeed(PasswordHasher, argon2Hasher(options));
