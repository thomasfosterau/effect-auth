/**
 * Default crypto service layer for effect-auth, backed by the platform Web
 * Crypto API (`globalThis.crypto`).
 *
 * Every service that needs secure randomness yields
 * `SecureRandom.SecureRandom` (`effect/crypto`) at Layer construction, and the
 * few that hash yield `Digest.Digest`; this module supplies the concrete
 * implementations those layers are composed with.
 *
 * @module platform-crypto
 */
import { Layer } from "effect";
import { Digest, SecureRandom } from "effect/crypto";

/**
 * The default `SecureRandom.SecureRandom` implementation, backed by
 * `globalThis.crypto.getRandomValues`. Exposed directly (in addition to
 * {@link layer}) for the rare call site that needs an instance without
 * threading it through the Effect context — e.g. a free function that takes it
 * as a plain parameter.
 */
export const instance: typeof SecureRandom.SecureRandom.Service = SecureRandom.make(
  SecureRandom.randomBytesUnsafe,
);

/**
 * Default crypto layer, backed by `globalThis.crypto`: `SecureRandom.SecureRandom`
 * (the {@link instance} above) and `Digest.Digest` over `crypto.subtle`. Compose
 * this into every `static layer` that yields either so the requirement does not
 * leak to consumers.
 */
export const layer: Layer.Layer<SecureRandom.SecureRandom | Digest.Digest> = Layer.mergeAll(
  Layer.succeed(SecureRandom.SecureRandom, instance),
  Digest.layerWebCrypto,
);
