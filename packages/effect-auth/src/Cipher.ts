/**
 * The AEAD cipher seam shared across JWT private-key storage, TOTP secret
 * storage and OAuth token storage, keyed HMAC and the WebAuthn signature
 * primitives, all over `effect/crypto`; plus the JWS key-pair, sign and verify
 * helpers, the last of the core's `node:crypto` use.
 *
 * @module cipher
 */

import * as crypto from "node:crypto";
import { Effect } from "effect";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
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
import * as R from "effect/Record";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { AuthError } from "./Errors.ts";
import * as Types from "./Types.ts";

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
  (key: Aead.Key, plaintext: string): Effect.Effect<string, CryptoError.CryptoError> =>
    Effect.gen(function* () {
      const nonce = yield* random.randomBytes(NONCE_LENGTH);
      const sealed = yield* aead.encrypt(key, encoder.encode(plaintext), { nonce });
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
  (key: Aead.Key, sealed: string): Effect.Effect<string | undefined> =>
    Effect.gen(function* () {
      const bytes = Result.getOrUndefined(Base64Url.decode(sealed));
      if (bytes === undefined || bytes.length < NONCE_LENGTH + TAG_LENGTH + 1) return undefined;
      const nonce = bytes.subarray(0, NONCE_LENGTH);
      const tag = bytes.subarray(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH);
      const body = bytes.subarray(NONCE_LENGTH + TAG_LENGTH);
      const joined = new Uint8Array(body.length + TAG_LENGTH);
      joined.set(body, 0);
      joined.set(tag, body.length);
      const opened = yield* Effect.option(aead.decrypt(key, joined, { nonce }));
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
 * Open what {@link aes256GcmSeal} sealed, or `null` when it is malformed or
 * fails authentication.
 *
 * @internal
 */
export const aes256GcmOpen = (
  key: Uint8Array,
  sealed: string,
): Effect.Effect<string | null, never, Aead.Aead> =>
  Effect.gen(function* () {
    const open = openWith(yield* Aead.Aead);
    const aes = yield* Effect.option(aesKey(key));
    if (Option.isNone(aes)) return null;
    return (yield* open(aes.value, sealed)) ?? null;
  });

// ---------------------------------------------------------------------------
// JWS (JSON Web Signature) asymmetric primitives — used by Jwt.ts and
// oauth/OAuth.ts (signing/verifying compact JWS tokens).
// ---------------------------------------------------------------------------

/** Signing/verification algorithms supported for compact JWS tokens. */
export type JwsAlgorithm = "ES256" | "EdDSA" | "RS256";

/**
 * An exported JWK whose members are JSON or `undefined`. From compatibility
 * date 2025-12-03 on, workerd's `KeyObject.export({ format: "jwk" })` carries
 * every absent member (`use`, `alg`, `d`, …) as `undefined`.
 */
const decodeExportedJwk = Schema.decodeUnknownSync(
  Schema.Record(Schema.String, Schema.UndefinedOr(Schema.Json)),
);

/** The members a public JWK of each algorithm must carry to be usable. */
const REQUIRED_JWK_MEMBERS: Readonly<Record<"ES256" | "EdDSA", ReadonlyArray<string>>> = {
  ES256: ["kty", "crv", "x", "y"],
  EdDSA: ["kty", "crv", "x"],
};

/**
 * The public JWK {@link generateJwsKeyPair} returns, from what
 * `KeyObject.export({ format: "jwk" })` gave: `undefined` members dropped,
 * then every member the algorithm's key needs (`kty`, `crv`, `x`, and `y` for
 * ES256) checked present as a string. Throws an {@link AuthError} naming the
 * missing members rather than return a JWK no verifier can use. `exported`
 * is the JWK as Node types it, or as workerd returns it (string members, any
 * of them `undefined`).
 *
 * @internal
 */
export const exportedPublicJwk = (
  algorithm: "ES256" | "EdDSA",
  exported: crypto.JsonWebKeyInput["key"] | Readonly<Record<string, string | undefined>>,
): Types.JsonObject => {
  // A JWK is JSON by construction, but for workerd's `undefined` members,
  // which are dropped; the decode turns node's open-ended `JsonWebKey` into
  // the JSON object type without a cast.
  const jwk = R.filter(decodeExportedJwk(exported), P.isNotUndefined);
  const missing = REQUIRED_JWK_MEMBERS[algorithm].filter((member) => !P.isString(jwk[member]));
  if (Arr.isReadonlyArrayNonEmpty(missing))
    throw new AuthError({
      message: `The exported ${algorithm} public JWK lacks ${missing.join(", ")}`,
    });
  return jwk;
};

/**
 * Generate a fresh ES256 (P-256) or EdDSA (Ed25519) signing key pair. The
 * public key is exported as a JWK; the private key as a PKCS#8 PEM string.
 * Throws an {@link AuthError} when the exported JWK lacks a member the key
 * needs (`kty`, `crv`, `x`, and `y` for ES256).
 */
export const generateJwsKeyPair = (
  algorithm: "ES256" | "EdDSA",
): { readonly publicKeyJwk: Types.JsonObject; readonly privateKeyPem: string } => {
  const { publicKey, privateKey } =
    algorithm === "ES256"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : crypto.generateKeyPairSync("ed25519");

  return {
    publicKeyJwk: exportedPublicJwk(algorithm, publicKey.export({ format: "jwk" })),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
};

/**
 * Sign `data` with a PKCS#8 PEM private key. ES256 signatures are emitted in
 * raw JOSE `r || s` form via `dsaEncoding: "ieee-p1363"` (Node defaults to
 * DER, which JWS does not accept); EdDSA signs with a null digest.
 *
 * The ES256 options carry the PEM itself, never a `KeyObject`: workerd's
 * `node:crypto` rejects `{ key: KeyObject, dsaEncoding }` with
 * `ERR_INVALID_ARG_TYPE` on every compatibility date, and accepts a PEM or
 * JWK key input there. `Workerd.test.ts` pins both forms.
 */
export const signJws = (
  algorithm: "ES256" | "EdDSA",
  data: Uint8Array,
  privateKeyPem: string,
): Uint8Array =>
  algorithm === "EdDSA"
    ? crypto.sign(null, data, crypto.createPrivateKey(privateKeyPem))
    : crypto.sign("sha256", data, { key: privateKeyPem, dsaEncoding: "ieee-p1363" });

/**
 * Verify `signature` over `data` against a public JWK. ES256 uses the raw
 * JOSE `r || s` encoding (`dsaEncoding: "ieee-p1363"`), with the JWK as a
 * `{ key, format: "jwk" }` input for the reason {@link signJws} gives; EdDSA
 * verifies with a null digest; RS256 is plain RSASSA-PKCS1-v1_5 over SHA-256.
 */
export const verifyJws = (
  algorithm: JwsAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: Types.JsonObject,
): boolean => {
  // SAFETY: `jwk` is a JSON Web Key object (from a JWKS or a stored key pair);
  // `createPublicKey` validates its members and throws on a malformed key.
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (algorithm === "RS256") return crypto.verify("sha256", data, key, signature);
  if (algorithm === "ES256")
    return crypto.verify(
      "sha256",
      data,
      { key: jwk, format: "jwk", dsaEncoding: "ieee-p1363" },
      signature,
    );
  return crypto.verify(null, data, key, signature);
};

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
