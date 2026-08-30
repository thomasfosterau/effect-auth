/**
 * Argon2id password hasher backed by the native
 * [`@node-rs/argon2`](https://github.com/napi-rs/node-rs) binding — an opt-in
 * fast path for plain-Node deployments.
 *
 * `@node-rs/argon2` is an **optional peer dependency**: install it yourself to
 * use this module. It is loaded with a dynamic `import()`, and this file is
 * published behind its own entry point
 * (`@thomasfosterau/effect-auth-argon2/native`) that the default WASM hasher
 * never imports, so a bundler targeting Cloudflare Workers or another edge
 * runtime never sees the native module.
 *
 * ```sh
 * npm install @node-rs/argon2
 * ```
 *
 * ```ts
 * import { nativeArgon2Hasher } from "@thomasfosterau/effect-auth-argon2/native";
 * ```
 *
 * Hashes are interchangeable with the WASM hasher's in both directions: both
 * emit and accept standard PHC strings.
 *
 * @module argon2/native
 */
import { Effect, Layer } from "effect";
import { HashingError, Password } from "@thomasfosterau/effect-auth";
import {
  ARGON2ID,
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

type NativeModule = typeof import("@node-rs/argon2");

const MISSING_PEER =
  "@node-rs/argon2 is not installed. It is an optional peer dependency of " +
  "@thomasfosterau/effect-auth-argon2 — run `npm install @node-rs/argon2`, or use the " +
  "WebAssembly-backed argon2Hasher() from the package root, which needs no native module.";

let loaded: Promise<NativeModule> | undefined;

/**
 * Load `@node-rs/argon2` once per process. A failed load is not cached, so a
 * later attempt (e.g. after the peer is installed in a dev server) can succeed.
 */
const loadNative = (): Promise<NativeModule> =>
  (loaded ??= import("@node-rs/argon2").catch((cause: unknown) => {
    loaded = undefined;
    throw cause;
  }));

const isModuleNotFound = (cause: unknown): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  (cause.code === "ERR_MODULE_NOT_FOUND" || cause.code === "MODULE_NOT_FOUND");

const nativeModule: Effect.Effect<NativeModule, HashingError> = Effect.tryPromise({
  try: loadNative,
  catch: (cause) =>
    new HashingError({
      // A missing optional peer is the common case and gets the actionable
      // message; anything else (an unsupported platform, a broken binary) is
      // reported as a load failure with the original error attached.
      message: isModuleNotFound(cause) ? MISSING_PEER : "Failed to load @node-rs/argon2",
      cause,
    }),
});

/**
 * Create an Argon2id {@link Password.PasswordHasher} backed by the native
 * `@node-rs/argon2` binding.
 *
 * Same defaults, option names and PHC output as the WASM
 * `argon2Hasher` — roughly an order of magnitude faster, but it needs a native
 * module and is unsuitable for edge runtimes. Every `hash`/`verify` fails with
 * a `HashingError` explaining the install step when the peer is absent.
 *
 * @example
 * ```ts
 * import { nativeArgon2Hasher, nativeArgon2HasherLayer } from "@thomasfosterau/effect-auth-argon2/native";
 * import { serverProfile } from "@thomasfosterau/effect-auth-argon2";
 *
 * const hasher = nativeArgon2Hasher();
 * const layer = nativeArgon2HasherLayer(serverProfile);
 * ```
 */
export const nativeArgon2Hasher = (options?: Argon2Options): PasswordHasherService => {
  // Omit `algorithm`/`version`: the binding already defaults to Argon2id / 0x13.
  const params = resolveOptions(options);

  return {
    algorithm: ARGON2ID,

    hash: (password: string) =>
      Effect.gen(function* () {
        yield* requireHashablePassword(password);
        const argon2 = yield* nativeModule;

        const phc = yield* Effect.tryPromise({
          try: () => argon2.hash(password, params),
          catch: (cause) =>
            new HashingError({ message: "Failed to hash password with Argon2id", cause }),
        });

        return { hash: phc, algorithm: ARGON2ID } satisfies HashedPassword;
      }).pipe(
        Effect.withSpan("effect-auth.password.hash", { attributes: { algorithm: ARGON2ID } }),
      ),

    // `@node-rs/argon2` reads the cost parameters out of the stored PHC string,
    // returns `false` for a wrong password, and throws only on a malformed
    // hash; the latter surfaces as a HashingError.
    verify: (password: string, hash: string) =>
      Effect.gen(function* () {
        yield* requireNonEmptyPassword(password);
        yield* requireNonEmptyHash(hash);

        // Anti-DoS: bail out before the expensive KDF for absurdly long inputs.
        if (!isWithinMaxLength(password)) return false;

        const argon2 = yield* nativeModule;

        return yield* Effect.tryPromise({
          try: () => argon2.verify(hash, password),
          catch: (cause) =>
            new HashingError({
              message: "Failed to verify password against Argon2id hash",
              cause,
            }),
        });
      }).pipe(
        Effect.withSpan("effect-auth.password.verify", { attributes: { algorithm: ARGON2ID } }),
      ),
  };
};

/**
 * A `Layer` providing {@link Password.PasswordHasher} backed by the native
 * `@node-rs/argon2` binding. Node-only — see {@link nativeArgon2Hasher}.
 */
export const nativeArgon2HasherLayer = (
  options?: Argon2Options,
): Layer.Layer<Password.PasswordHasher> =>
  Layer.succeed(PasswordHasher, nativeArgon2Hasher(options));

export {
  /** Re-exported so `/native` consumers can type their configuration without a second import. */
  type Argon2Options,
  /** Re-exported for convenience; see the package root. */
  type Argon2Profile,
  defaultProfile,
  serverProfile,
} from "./Common.ts";
