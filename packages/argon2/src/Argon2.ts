/**
 * Argon2id password hasher backed by WebAssembly: the RustCrypto `argon2`
 * crate as built by
 * [`@thomasfosterau/argon2`](https://www.npmjs.com/package/@thomasfosterau/argon2)
 * (MIT), compiled once at module scope.
 *
 * It has no native module and no `node:` imports, and it generates no wasm
 * code after startup, so it runs unchanged on Node, Bun, Deno, and edge
 * runtimes such as Cloudflare Workers, which refuse wasm compilation inside a
 * request (#744). Randomness comes from the platform Web Crypto API
 * (`globalThis.crypto`), the same source core effect-auth's `PlatformCrypto`
 * layer uses.
 *
 * Emitted hashes are standard PHC strings
 * (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) and `verify` parses the cost
 * parameters, salt and digest length out of the *stored* hash rather than
 * assuming the configured ones — so hashes written by `hash-wasm` (this
 * package's backend through 0.1.x), by `@node-rs/argon2`, by an older
 * configuration of this package, or by any other Argon2 implementation keep
 * verifying after a parameter change.
 *
 * @module argon2/argon2
 */
import { Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { HashingError, Password } from "@thomasfosterau/effect-auth";
import {
  ARGON2ID,
  SALT_LENGTH,
  isWithinMaxLength,
  requireHashablePassword,
  requireNonEmptyHash,
  requireNonEmptyPassword,
  resolveOptions,
  type Argon2Options,
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

const parsePositiveInt = (value: string | undefined): number => {
  if (value === undefined || !/^\d+$/.test(value)) return Number.NaN;
  const parsed = Number.parseInt(value, 10);
  return parsed > 0 ? parsed : Number.NaN;
};

/**
 * Check a stored PHC string's header before handing it to the kernel.
 *
 * Deliberately tolerant about the order of the `m`/`t`/`p` parameters (the PHC
 * spec does not fix it) and about which Argon2 variant produced the hash, but
 * strict about everything else: a hash we cannot recompute must surface as a
 * `HashingError` rather than a silent `false`. The kernel would also verify
 * Argon2 `v=16`; this check keeps refusing it, as earlier releases did. The
 * salt and digest are left to the kernel, which reports a malformed or
 * out-of-range one as unverifiable.
 */
const checkHash = (hash: string): Effect.Effect<void, HashingError> =>
  Effect.suspend(() => {
    const segments = hash.split("$");
    // "$argon2id$v=19$m=..,t=..,p=..$salt$digest" splits into a leading empty
    // segment plus five fields.
    if (segments.length !== 6 || segments[0] !== "") {
      return invalidHash("expected $argon2<variant>$v=19$m=...,t=...,p=...$salt$hash");
    }
    // The length check above guarantees all six segments exist, so the
    // defaults are never used.
    const [, variant = "", version = "", parameters = ""] = segments;

    if (!Arr.contains(variants, variant)) {
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
    const costs: Record<string, number> = R.fromEntries(
      Arr.map(pairs, ({ name, value }): readonly [string, number] => [
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
    return Effect.void;
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
  const costs = resolveOptions(options);

  return {
    algorithm: ARGON2ID,

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
      // hashes written under a different configuration still verify.
      yield* checkHash(hash);

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
 * the default hasher for new passwords.
 */
export const argon2HasherLayer = (options?: Argon2Options): Layer.Layer<Password.PasswordHasher> =>
  Layer.succeed(PasswordHasher, argon2Hasher(options));
