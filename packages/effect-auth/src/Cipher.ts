/**
 * Raw `node:crypto` primitives for effect-auth: the AEAD cipher seam shared
 * across JWT private-key storage, TOTP secret storage, and OAuth token
 * storage, plus every other primitive Effect's `Crypto` service does not
 * cover (keyed HMAC, and asymmetric key generation/signing/verification for
 * JWS and WebAuthn). This is one of the three modules allowed to import
 * `node:crypto` directly — see `docs/ARCHITECTURE.md` § Dependencies.
 *
 * @module cipher
 */

import * as crypto from "node:crypto";
import { Effect } from "effect";
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
 * import { Effect, Layer, Redacted } from "effect"
 * import {
 *   aes256GcmCipher,
 *   Hooks,
 *   JwtKeyStore,
 *   JwtService,
 *   SessionService,
 * } from "@thomasfosterau/effect-auth"
 * import { MultiFactorService } from "@thomasfosterau/effect-auth/multifactor"
 * import { GoogleProvider, OAuthService } from "@thomasfosterau/effect-auth/oauth"
 * import { PasswordHasher } from "@thomasfosterau/effect-auth/password"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * // The app's OAuth provider list (see OAuthService.layer).
 * const providers = {
 *   google: GoogleProvider({
 *     clientId: "example-client-id",
 *     clientSecret: Redacted.make("example-client-secret"),
 *     redirectUri: "https://app.example.com/callback/google",
 *   }),
 * }
 *
 * // One cipher, derived from the app's encryption secret.
 * const cipher = aes256GcmCipher("example-encryption-secret")
 *
 * // JWT private key at rest
 * const jwtLayer = JwtService.layer({ issuer: "https://app.example.com", encryptPrivateKey: { cipher } })
 * // TOTP secret at rest
 * const totpLayer = MultiFactorService.layer({ issuer: "MyApp", encryptSecret: { cipher } })
 * // OAuth tokens at rest
 * const oauthLayer = OAuthService.layer(providers, { encryptTokens: { cipher } })
 *
 * // The three services with the cipher wired in, over the app's persistence
 * // stores: here the in-memory reference stores.
 * export const services = Layer.mergeAll(jwtLayer, totpLayer, oauthLayer).pipe(
 *   Layer.provideMerge(
 *     SessionService.layer({ sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 } }),
 *   ),
 *   Layer.provideMerge(Layer.mergeAll(Testing.memoryStores, PasswordHasher.layer(), Hooks.Default)),
 * )
 *
 * const program = Effect.gen(function* () {
 *   // The cipher itself round-trips, and tampering is detected by the GCM tag.
 *   const sealed = yield* cipher.encrypt("refresh-token-123")
 *   assert.notEqual(sealed, "refresh-token-123")
 *   assert.equal(yield* cipher.decrypt(sealed), "refresh-token-123")
 *   assert.ok(yield* Effect.isFailure(cipher.decrypt(`${sealed.slice(0, -2)}AA`)))
 *
 *   // A signed JWT verifies, and the signing key's private half is stored sealed.
 *   const jwt = yield* JwtService
 *   const now = new Date()
 *   const { token } = yield* jwt.sign({ id: "u-1", createdAt: now, updatedAt: now, attributes: {} })
 *   assert.equal((yield* jwt.verify(token))["sub"], "u-1")
 *   const [key] = yield* (yield* JwtKeyStore).list()
 *   assert.ok(key !== undefined && !key.privateKeyPem.includes("PRIVATE KEY"))
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(services)))
 * ```
 */
export const aes256GcmCipher = (secret: string): TokenCipher => {
  const key = crypto.createHash("sha256").update(Buffer.from(secret, "utf8")).digest();
  return {
    encrypt: (plaintext) =>
      Effect.try({
        try: () => {
          const iv = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
          const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
          const tag = cipher.getAuthTag();
          return Buffer.concat([iv, tag, encrypted]).toString("base64url");
        },
        catch: (cause) => new AuthError({ message: `Encryption failed: ${String(cause)}` }),
      }),
    decrypt: (ciphertext) =>
      Effect.try({
        try: () => {
          const buf = Buffer.from(ciphertext, "base64url");
          if (buf.length < 29) throw new Error("ciphertext too short");
          const iv = buf.subarray(0, 12);
          const tag = buf.subarray(12, 28);
          const encrypted = buf.subarray(28);
          const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
          decipher.setAuthTag(tag);
          return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
        },
        catch: (cause) => new AuthError({ message: `Decryption failed: ${String(cause)}` }),
      }),
  };
};

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/**
 * Synchronous SHA-256 digest.
 *
 * Prefer the `Crypto.Crypto` service (`crypto.digest`) wherever an `Effect` is
 * available; this exists for the synchronous parsing paths that cannot suspend
 * — notably WebAuthn relying-party ID hash verification — and keeps
 * `node:crypto` corralled to this module.
 */
export const sha256 = (data: Uint8Array | string): Uint8Array =>
  new Uint8Array(crypto.createHash("sha256").update(data).digest());

// ---------------------------------------------------------------------------
// Keyed HMAC
// ---------------------------------------------------------------------------

/**
 * Compute a keyed HMAC digest. Used for signed cookies (session cache,
 * trusted-device tokens) and RFC 4226/6238 HOTP/TOTP, none of which are
 * covered by Effect's `Crypto` service (digest-only, no HMAC).
 */
export const hmac = (
  algorithm: "sha1" | "sha256" | "sha512",
  secret: Uint8Array | string,
  data: Uint8Array | string,
): Uint8Array => new Uint8Array(crypto.createHmac(algorithm, secret).update(data).digest());

// ---------------------------------------------------------------------------
// JWS (JSON Web Signature) asymmetric primitives — used by Jwt.ts and
// oauth/OAuth.ts (signing/verifying compact JWS tokens).
// ---------------------------------------------------------------------------

/** Signing/verification algorithms supported for compact JWS tokens. */
export type JwsAlgorithm = "ES256" | "EdDSA" | "RS256";

/**
 * Generate a fresh ES256 (P-256) or EdDSA (Ed25519) signing key pair. The
 * public key is exported as a JWK; the private key as a PKCS#8 PEM string.
 */
export const generateJwsKeyPair = (
  algorithm: "ES256" | "EdDSA",
): { readonly publicKeyJwk: Record<string, unknown>; readonly privateKeyPem: string } => {
  const { publicKey, privateKey } =
    algorithm === "ES256"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : crypto.generateKeyPairSync("ed25519");

  return {
    publicKeyJwk: publicKey.export({ format: "jwk" }) as Record<string, unknown>,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
};

/**
 * Sign `data` with a PKCS#8 PEM private key. ES256 signatures are emitted in
 * raw JOSE `r || s` form via `dsaEncoding: "ieee-p1363"` (Node defaults to
 * DER, which JWS does not accept); EdDSA signs with a null digest.
 */
export const signJws = (
  algorithm: "ES256" | "EdDSA",
  data: Uint8Array,
  privateKeyPem: string,
): Uint8Array => {
  const key = crypto.createPrivateKey(privateKeyPem);
  return algorithm === "EdDSA"
    ? crypto.sign(null, data, key)
    : crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
};

/**
 * Verify `signature` over `data` against a public JWK. ES256 uses the raw
 * JOSE `r || s` encoding (`dsaEncoding: "ieee-p1363"`); EdDSA verifies with a
 * null digest; RS256 is plain RSASSA-PKCS1-v1_5 over SHA-256.
 */
export const verifyJws = (
  algorithm: JwsAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: Record<string, unknown>,
): boolean => {
  const key = crypto.createPublicKey({ key: jwk as crypto.webcrypto.JsonWebKey, format: "jwk" });
  if (algorithm === "RS256") return crypto.verify("sha256", data, key, signature);
  if (algorithm === "ES256")
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  return crypto.verify(null, data, key, signature);
};

// ---------------------------------------------------------------------------
// DER/SPKI asymmetric primitives — used by WebAuthn.ts. Authenticators
// produce algorithm-native signature encodings (DER ECDSA, PKCS1-v1.5 RSA,
// raw EdDSA), so verification stays on `node:crypto` rather than WebCrypto.
// ---------------------------------------------------------------------------

/** Convert a JWK public key to SPKI DER, for compact storage. */
export const jwkToSpkiDer = (jwk: crypto.JsonWebKeyInput["key"]): Uint8Array => {
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return new Uint8Array(key.export({ type: "spki", format: "der" }));
};

/**
 * Verify `signature` over `message` against an SPKI DER public key.
 * `digestAlgorithm` must be `null` for EdDSA (which hashes internally) and
 * `"sha256"` for ECDSA/RSA.
 */
export const verifyDerSignature = (
  digestAlgorithm: "sha256" | null,
  publicKeyDer: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean => {
  const key = crypto.createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: "der",
    type: "spki",
  });
  return crypto.verify(digestAlgorithm, Buffer.from(message), key, Buffer.from(signature));
};
