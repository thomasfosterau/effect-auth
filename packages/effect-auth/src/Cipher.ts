/**
 * The AEAD cipher seam shared across JWT private-key storage, TOTP secret
 * storage and OAuth token storage, keyed HMAC and the WebAuthn signature
 * primitives, all over `effect/crypto`. JWS and JWK work is `effect/jose`'s.
 *
 * @module cipher
 */

import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import {
  Aead,
  type CryptoError,
  Digest,
  KeyFormat,
  Mac,
  SecureRandom,
  Signature,
} from "effect/crypto";
import { Base64Url } from "effect/encoding";
import * as P from "effect/Predicate";
import * as Result from "effect/Result";
import { AuthError } from "./Errors.ts";

/**
 * Pluggable encryption/decryption interface for secrets stored at rest.
 * Implement this to use an HSM, envelope encryption, or any other custom
 * cipher. The built-in {@link aes256GcmCipher} covers most use-cases.
 */
export interface TokenCipher {
  /** Encrypt a plaintext string; returns an opaque encoded string. */
  readonly encrypt: (plaintext: string) => Effect.Effect<string, AuthError>;
  /** Decrypt a previously-encrypted string back to the original plaintext. */
  readonly decrypt: (ciphertext: string) => Effect.Effect<string, AuthError>;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const utf8 = (data: Uint8Array | string): Uint8Array =>
  P.isString(data) ? encoder.encode(data) : data;

const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Seal `plaintext` under an AES-256-GCM key as
 * `base64url(iv[12] ‖ tag[16] ‖ ciphertext)`. WebCrypto appends the tag to
 * the ciphertext; the stored layout puts it first, as it always has.
 */
const sealWith =
  (aead: typeof Aead.Aead.Service, random: typeof SecureRandom.SecureRandom.Service) =>
  (
    key: Aead.Key,
    plaintext: string,
    aad?: Uint8Array,
  ): Effect.Effect<string, CryptoError.CryptoError> =>
    Effect.gen(function* () {
      const nonce = yield* random.randomBytes(NONCE_LENGTH);
      const sealed = yield* aead.encrypt(key, encoder.encode(plaintext), {
        nonce,
        ...(aad !== undefined && { aad }),
      });
      const body = sealed.subarray(0, sealed.length - TAG_LENGTH);
      const tag = sealed.subarray(sealed.length - TAG_LENGTH);
      const out = new Uint8Array(NONCE_LENGTH + sealed.length);
      out.set(nonce, 0);
      out.set(tag, NONCE_LENGTH);
      out.set(body, NONCE_LENGTH + TAG_LENGTH);
      return Base64Url.encode(out);
    });

/**
 * Open what {@link sealWith} sealed, or `undefined` when it is malformed,
 * fails authentication or is not UTF-8.
 */
const openWith =
  (aead: typeof Aead.Aead.Service) =>
  (key: Aead.Key, sealed: string, aad?: Uint8Array): Effect.Effect<string | undefined> =>
    Effect.gen(function* () {
      const bytes = Result.getOrUndefined(Base64Url.decode(sealed));
      if (bytes === undefined || bytes.length < NONCE_LENGTH + TAG_LENGTH + 1) return undefined;
      const nonce = bytes.subarray(0, NONCE_LENGTH);
      const tag = bytes.subarray(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH);
      const body = bytes.subarray(NONCE_LENGTH + TAG_LENGTH);
      const joined = new Uint8Array(body.length + TAG_LENGTH);
      joined.set(body, 0);
      joined.set(tag, body.length);
      const opened = yield* Effect.option(
        aead.decrypt(key, joined, { nonce, ...(aad !== undefined && { aad }) }),
      );
      if (Option.isNone(opened)) return undefined;
      return Result.getOrUndefined(Result.try(() => decoder.decode(opened.value)));
    });

const aesKey = (bytes: Uint8Array): Effect.Effect<Aead.Key<Aead.AesGcm>, AuthError> =>
  Aead.key(Aead.aes256Gcm, bytes).pipe(
    Effect.mapError(
      (cause) => new AuthError({ message: `Invalid AES-256-GCM key: ${cause.message}`, cause }),
    ),
  );

/**
 * Create an AES-256-GCM {@link TokenCipher} from a secret string.
 *
 * The 256-bit key is derived from `secret` with SHA-256. Each call to
 * `encrypt` generates a fresh random 12-byte IV; the encoded output is
 * `base64url(iv[12] ‖ tag[16] ‖ ciphertext)`. The GCM auth-tag ensures
 * integrity: decryption fails loudly on any tampering.
 *
 * The same cipher instance can be shared across JWT private-key storage,
 * TOTP secret storage, and OAuth token storage — or each can use a
 * separate instance (different secrets / key rotation policies).
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import { aes256GcmCipher, PlatformCrypto } from "@thomasfosterau/effect-auth"
 *
 * const program = Effect.gen(function* () {
 *   const cipher = yield* aes256GcmCipher("example-encryption-secret")
 *   // The cipher round-trips, and tampering is detected by the GCM tag.
 *   const sealed = yield* cipher.encrypt("refresh-token-123")
 *   assert.notEqual(sealed, "refresh-token-123")
 *   assert.equal(yield* cipher.decrypt(sealed), "refresh-token-123")
 *   assert.ok(yield* Effect.isFailure(cipher.decrypt(`${sealed.slice(0, -2)}AA`)))
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(PlatformCrypto.layer)))
 * ```
 */
export const aes256GcmCipher = (
  secret: string,
): Effect.Effect<TokenCipher, AuthError, Aead.Aead | Digest.Digest | SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
    const aead = yield* Aead.Aead;
    const random = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;
    const key = yield* aesKey(yield* digest.digest(Digest.sha256, encoder.encode(secret)));
    const seal = sealWith(aead, random);
    const open = openWith(aead);
    return {
      encrypt: (plaintext) =>
        seal(key, plaintext).pipe(
          Effect.mapError(
            (cause) => new AuthError({ message: `Encryption failed: ${cause.message}`, cause }),
          ),
        ),
      decrypt: (ciphertext) =>
        Effect.filterOrFail(
          open(key, ciphertext),
          P.isNotUndefined,
          () => new AuthError({ message: "Decryption failed" }),
        ),
    };
  });

// ---------------------------------------------------------------------------
// Secrets sealed at rest
// ---------------------------------------------------------------------------

/**
 * Seals one purpose's secrets at rest (TOTP secrets, provider tokens, JWT
 * private keys), each bound to the row it is stored in: a ciphertext moved to
 * another row or purpose does not open.
 */
export interface SecretSealer {
  /** Seal `plaintext` for the row named `row`. */
  readonly seal: (plaintext: string, row: string) => Effect.Effect<string, AuthError>;
  /**
   * Open what `seal` wrote for `row`. A value in an earlier format still
   * opens: a legacy ciphertext under the override secret, else plaintext.
   */
  readonly open: (stored: string, row: string) => Effect.Effect<string, AuthError>;
}

/** The prefix of a value {@link secretSealer} sealed. */
export const SEALED_PREFIX = "v2.";

/**
 * The default {@link SecretSealer}: AES-256-GCM under `key` (a 32-byte key
 * derived for `purpose`), with `purpose` and the row as associated data,
 * written as `v2.` + `base64url(iv ‖ tag ‖ ciphertext)`. A stored value
 * without the prefix predates it: `legacy` (the {@link aes256GcmCipher} of an
 * override secret) opens it when it can, and otherwise it is read as the
 * plaintext an unencrypted deployment wrote.
 */
export const secretSealer = <RK = never, RL = never>(options: {
  readonly key: Effect.Effect<Uint8Array, never, RK>;
  readonly purpose: string;
  readonly legacy?: Effect.Effect<TokenCipher, AuthError, RL>;
}): Effect.Effect<SecretSealer, never, Aead.Aead | SecureRandom.SecureRandom | RK | RL> =>
  Effect.gen(function* () {
    const context = yield* Effect.context<RK | RL>();
    const key = yield* Effect.cached(
      Effect.flatMap(options.key, aesKey).pipe(Effect.provideContext(context)),
    );
    const legacyCipher =
      options.legacy === undefined
        ? undefined
        : yield* Effect.cached(Effect.provideContext(options.legacy, context));
    const seal = sealWith(yield* Aead.Aead, yield* SecureRandom.SecureRandom);
    const open = openWith(yield* Aead.Aead);
    const aad = (row: string) => encoder.encode(`effect-auth/${options.purpose}\u0000${row}`);
    return {
      seal: (plaintext, row) =>
        Effect.flatMap(key, (k) => seal(k, plaintext, aad(row))).pipe(
          Effect.map((sealed) => SEALED_PREFIX + sealed),
          Effect.mapError(
            (cause) => new AuthError({ message: `Encryption failed: ${cause.message}`, cause }),
          ),
        ),
      open: (stored, row) => {
        if (stored.startsWith(SEALED_PREFIX)) {
          return Effect.filterOrFail(
            Effect.flatMap(key, (k) => open(k, stored.slice(SEALED_PREFIX.length), aad(row))),
            P.isNotUndefined,
            () => new AuthError({ message: "Decryption failed" }),
          );
        }
        if (legacyCipher === undefined) return Effect.succeed(stored);
        return Effect.flatMap(legacyCipher, (cipher) => cipher.decrypt(stored)).pipe(
          Effect.orElseSucceed(() => stored),
        );
      },
    };
  });

/** A {@link SecretSealer} over a custom {@link TokenCipher}, which keeps its own format. */
export const cipherSealer = (cipher: TokenCipher): SecretSealer => ({
  seal: (plaintext) => cipher.encrypt(plaintext),
  open: (stored) => cipher.decrypt(stored),
});

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/** SHA-256 digest of `data` (a string is UTF-8 encoded). */
export const sha256 = (
  data: Uint8Array | string,
): Effect.Effect<Uint8Array, never, Digest.Digest> =>
  Digest.Digest.use((digest) => digest.digest(Digest.sha256, utf8(data)));

// ---------------------------------------------------------------------------
// Keyed HMAC
// ---------------------------------------------------------------------------

const MAC_ALGORITHMS = {
  sha1: Mac.hmacSha1,
  sha256: Mac.hmacSha256,
  sha512: Mac.hmacSha512,
} as const;

/**
 * Compute a keyed HMAC digest. Used for signed cookies (session cache,
 * trusted-device tokens) and RFC 4226/6238 HOTP/TOTP. An empty `secret` is
 * refused with an {@link AuthError}.
 */
export const hmac = (
  algorithm: "sha1" | "sha256" | "sha512",
  secret: Uint8Array | string,
  data: Uint8Array | string,
): Effect.Effect<Uint8Array, AuthError, Mac.Mac> =>
  Mac.Mac.use((mac) =>
    Mac.key(MAC_ALGORITHMS[algorithm], utf8(secret)).pipe(
      Effect.flatMap((key) => mac.sign(key, utf8(data))),
      Effect.mapError(
        (cause) => new AuthError({ message: `HMAC failed: ${cause.message}`, cause }),
      ),
    ),
  );

/**
 * AES-256-GCM seal under a 32-byte `key`:
 * `base64url(iv[12] ‖ tag[16] ‖ ciphertext)`, the {@link aes256GcmCipher}
 * format.
 *
 * @internal
 */
export const aes256GcmSeal = (
  key: Uint8Array,
  plaintext: string,
): Effect.Effect<string, AuthError, Aead.Aead | SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
    const seal = sealWith(yield* Aead.Aead, yield* SecureRandom.SecureRandom);
    return yield* seal(yield* aesKey(key), plaintext).pipe(
      Effect.mapError(
        (cause) => new AuthError({ message: `Encryption failed: ${cause.message}`, cause }),
      ),
    );
  });

/**
 * Open what {@link aes256GcmSeal} sealed, or `None` when it is malformed or
 * fails authentication.
 *
 * @internal
 */
export const aes256GcmOpen = (
  key: Uint8Array,
  sealed: string,
): Effect.Effect<Option.Option<string>, never, Aead.Aead> =>
  Effect.gen(function* () {
    const open = openWith(yield* Aead.Aead);
    const aes = yield* Effect.option(aesKey(key));
    if (Option.isNone(aes)) return Option.none();
    return Option.fromUndefinedOr(yield* open(aes.value, sealed));
  });

// ---------------------------------------------------------------------------
// SPKI primitives for WebAuthn. Authenticators produce algorithm-native
// signature encodings (DER ECDSA, PKCS1-v1.5 RSA, raw EdDSA); ECDSA is
// converted to the IEEE P1363 `r || s` form WebCrypto verifies.
// ---------------------------------------------------------------------------

/** The signature algorithms a stored SPKI public key is verified under. */
export type SpkiAlgorithm = "ES256" | "RS256" | "EdDSA";

const SPKI_ALGORITHMS = {
  ES256: Signature.ecdsaP256,
  RS256: Signature.rsaPkcs1v15Sha256,
  EdDSA: Signature.ed25519,
} as const;

/** Convert a public JWK to SPKI DER, for compact storage. */
export const jwkToSpkiDer = (
  algorithm: SpkiAlgorithm,
  jwk: KeyFormat.JsonWebKey,
): Effect.Effect<Uint8Array, CryptoError.CryptoError> =>
  KeyFormat.decodePublic(KeyFormat.jwk, SPKI_ALGORITHMS[algorithm], jwk).pipe(
    Effect.flatMap((key) => KeyFormat.encode(KeyFormat.spki, key)),
  );

/**
 * The DER `INTEGER` at `offset`, as `size` big-endian bytes, and the offset
 * after it; `undefined` when it is not a minimal positive integer that fits.
 */
const derInteger = (
  der: Uint8Array,
  offset: number,
  size: number,
): { readonly value: Uint8Array; readonly next: number } | undefined => {
  if (der[offset] !== 0x02) return undefined;
  const length = der[offset + 1];
  if (length === undefined || length === 0 || length > 0x7f) return undefined;
  const start = offset + 2;
  const end = start + length;
  if (end > der.length) return undefined;
  let bytes = der.subarray(start, end);
  // A leading 0x00 only marks a high-bit-set positive value.
  if ((bytes[0] ?? 0) & 0x80) return undefined;
  if (bytes.length > 1 && bytes[0] === 0 && ((bytes[1] ?? 0) & 0x80) === 0) return undefined;
  if (bytes[0] === 0) bytes = bytes.subarray(1);
  if (bytes.length > size) return undefined;
  const value = new Uint8Array(size);
  value.set(bytes, size - bytes.length);
  return { value, next: end };
};

/**
 * A DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`) as the
 * IEEE P1363 `r || s` of `size`-byte halves, or `undefined` when malformed.
 *
 * @internal
 */
export const derToP1363 = (der: Uint8Array, size: number): Uint8Array | undefined => {
  if (der[0] !== 0x30) return undefined;
  const length = der[1];
  if (length === undefined || length > 0x7f || length + 2 !== der.length) return undefined;
  const r = derInteger(der, 2, size);
  if (r === undefined) return undefined;
  const s = derInteger(der, r.next, size);
  if (s === undefined || s.next !== der.length) return undefined;
  const out = new Uint8Array(size * 2);
  out.set(r.value, 0);
  out.set(s.value, size);
  return out;
};

/**
 * Verify `signature` over `message` against an SPKI DER public key: ES256
 * takes a DER-encoded ECDSA signature (a malformed one verifies `false`),
 * RS256 RSASSA-PKCS1-v1_5 over SHA-256, EdDSA a raw Ed25519 signature. Fails
 * only when the key itself cannot be imported.
 */
export const verifySpkiSignature = (
  algorithm: SpkiAlgorithm,
  publicKeyDer: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Effect.Effect<boolean, CryptoError.CryptoError, Signature.Signature> =>
  Effect.gen(function* () {
    const verifier = yield* Signature.Signature;
    const key = yield* KeyFormat.decodePublic(
      KeyFormat.spki,
      SPKI_ALGORITHMS[algorithm],
      publicKeyDer,
    );
    const encoded = algorithm === "ES256" ? derToP1363(signature, 32) : signature;
    if (encoded === undefined) return false;
    return yield* verifier.verify(key, encoded, message);
  });
