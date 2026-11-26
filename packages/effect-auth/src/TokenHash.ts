/**
 * Shared token-hashing primitives for effect-auth.
 *
 * Bearer tokens (magic links, email-verification tokens, password-reset
 * tokens, device codes) are high-entropy secrets that grant account access.
 * They are stored as their SHA-256 digest so that a stolen database does not
 * allow replay attacks.
 *
 * The raw token is delivered to the end user (via email, SMS, URL, …) and
 * never persisted. All store lookups use the digest as the key.
 *
 * @module token-hash
 */
import { Effect, Result } from "effect";
import { Digest, Mac } from "effect/crypto";
import { Hex } from "effect/encoding";

const encoder = new TextEncoder();

/** The SHA-256 hex digest of `token` under the given `Digest` service. */
const digestToken =
  (digest: typeof Digest.Digest.Service) =>
  (token: string): Effect.Effect<string> =>
    digest.digestHex(Digest.sha256, encoder.encode(token));

/**
 * SHA-256 hex digest of a token string.
 *
 * Use for any high-entropy secret that must be stored at rest (bearer tokens,
 * API keys, OIDC codes). The same input always produces the same output, so
 * this can be used as a deterministic store key.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { Digest } from "effect/crypto"
 * import { hashToken } from "@thomasfosterau/effect-auth"
 *
 * const digest = await Effect.runPromise(
 *   hashToken("abc").pipe(Effect.provide(Digest.layerWebCrypto)),
 * )
 * assert.equal(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
 * ```
 */
export const hashToken = (token: string): Effect.Effect<string, never, Digest.Digest> =>
  Digest.Digest.use((digest) => digestToken(digest)(token));

/**
 * {@link hashToken} bound to the `Digest` service in context, for a service's
 * `make` to resolve once so its methods carry `R = never`.
 */
export const tokenHasher: Effect.Effect<
  (token: string) => Effect.Effect<string>,
  never,
  Digest.Digest
> = Digest.Digest.useSync(digestToken);

/**
 * Constant-time comparison of two byte sequences (raw digests, HMACs,
 * signatures). Sequences of different lengths are unequal.
 */
export const timingSafeEqualBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  Mac.timingSafeEqual(a, b);

/**
 * Constant-time comparison of two hex-encoded SHA-256 digests.
 *
 * Always compare hashes with this function rather than `===` to prevent
 * timing side-channels. A value that is not hex equals nothing.
 */
export const constantTimeHashEqual = (a: string, b: string): boolean => {
  const left = Hex.decode(a);
  const right = Hex.decode(b);
  return (
    Result.isSuccess(left) &&
    Result.isSuccess(right) &&
    timingSafeEqualBytes(left.success, right.success)
  );
};
