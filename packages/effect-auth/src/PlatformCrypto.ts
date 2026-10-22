/**
 * Default `Crypto` service layer for effect-auth, backed by the platform Web
 * Crypto API (`globalThis.crypto`).
 *
 * Every service that needs secure randomness or a digest yields
 * `Crypto.Crypto` at Layer construction; this module supplies the concrete
 * implementation those layers are composed with.
 *
 * @module platform-crypto
 */
import { Crypto, Effect, Layer, PlatformError } from "effect";

const randomBytes = (size: number): Uint8Array =>
  globalThis.crypto.getRandomValues(new Uint8Array(size));

const digest = (
  algorithm: Crypto.DigestAlgorithm,
  data: Uint8Array,
): Effect.Effect<Uint8Array, PlatformError.PlatformError> =>
  Effect.tryPromise({
    try: async () =>
      new Uint8Array(
        // SAFETY: `subtle.digest` reads any `Uint8Array` view; the lib type only
        // narrows the backing buffer, and a rejected buffer surfaces via `catch`.
        await globalThis.crypto.subtle.digest(algorithm, data as NodeJS.BufferSource),
      ),
    catch: (cause) =>
      PlatformError.badArgument({
        module: "Crypto",
        method: "digest",
        description: `failed to compute ${algorithm} digest`,
        cause,
      }),
  });

/**
 * The default `Crypto.Crypto` implementation, backed by `globalThis.crypto`.
 * Exposed directly (in addition to {@link layer}) for the rare call site that
 * needs an instance without threading it through the Effect context — e.g.
 * a free function that takes it as a plain parameter.
 */
export const instance: Crypto.Crypto = Crypto.make({ randomBytes, digest });

/**
 * Default `Crypto.Crypto` layer, backed by `globalThis.crypto`. Compose this
 * into every `static layer` that yields `Crypto.Crypto` so the requirement
 * does not leak to consumers.
 */
export const layer: Layer.Layer<Crypto.Crypto> = Layer.succeed(Crypto.Crypto, instance);
