/**
 * Default crypto service layer for effect-auth, backed by the platform Web
 * Crypto API (`globalThis.crypto`).
 *
 * Every service resolves the `effect/crypto` services it needs (`SecureRandom`,
 * `Digest`, `Mac`, `Aead`, `Kdf`, `Signature`) at Layer construction; this
 * module supplies the WebCrypto implementations those layers are composed with.
 *
 * @module platform-crypto
 */
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { Aead, Digest, Kdf, Mac, SecureRandom, Signature } from "effect/crypto";

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

/** Every service {@link layer} provides. */
export type Services =
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Mac.Mac
  | Aead.Aead
  | Kdf.Kdf
  | Signature.Signature;

const random = Layer.succeed(SecureRandom.SecureRandom, instance);

/**
 * Default crypto layer, backed by `globalThis.crypto`: `SecureRandom` (the
 * {@link instance} above), and `Digest`, `Mac`, `Aead`, `Kdf` and `Signature`
 * over `crypto.subtle`. Compose this into every `static layer` that yields one
 * of them so the requirement does not leak to consumers.
 */
export const layer: Layer.Layer<Services> = Layer.mergeAll(
  random,
  Digest.layerWebCrypto,
  Kdf.layerWebCrypto,
  Layer.mergeAll(Mac.layerWebCrypto, Aead.layerWebCrypto, Signature.layerWebCrypto).pipe(
    Layer.provide(random),
  ),
);

let built: Context.Context<Services> | undefined;

/**
 * {@link layer}'s services, built once on first use, for code with no layer of
 * its own to resolve them in (the HTTP tier's request helpers, a hasher
 * constructed as a plain value). Its layers hold no resources.
 */
export const context = (): Context.Context<Services> =>
  (built ??= Effect.runSync(Effect.scoped(Layer.build(layer))));

/** Provide {@link context} to `self`. */
export const provide = <A, E, R>(
  self: Effect.Effect<A, E, R>,
): Effect.Effect<A, E, Exclude<R, Services>> => Effect.provideContext(self, context());

/** The default `Kdf.Kdf` implementation, from {@link context}. */
export const kdf = (): typeof Kdf.Kdf.Service => Context.get(context(), Kdf.Kdf);
