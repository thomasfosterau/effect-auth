/**
 * Pluggable AEAD cipher seam shared across JWT private-key storage, TOTP
 * secret storage, and OAuth token storage.
 *
 * @module cipher
 */

import * as crypto from "node:crypto";
import { Effect } from "effect";
import { AuthError } from "./Errors.js";

/**
 * Pluggable encryption/decryption interface for secrets stored at rest.
 * Implement this to use an HSM, envelope encryption, or any other custom
 * cipher. The built-in {@link makeAes256GcmCipher} covers most use-cases.
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
 * const cipher = makeAes256GcmCipher(process.env.ENCRYPTION_SECRET!)
 * // JWT private key at rest
 * const jwtLayer = JwtService.layer({ issuer: "...", encryptPrivateKey: { cipher } })
 * // TOTP secret at rest
 * const totpLayer = TwoFactorService.layer({ issuer: "...", encryptSecret: { cipher } })
 * // OAuth tokens at rest
 * const oauthLayer = OAuthService.layer(providers, { encryptTokens: { cipher } })
 * // or use the shorthand (each option accepts { secret } instead of { cipher }):
 * const jwtLayer = JwtService.layer({
 *   issuer: "...",
 *   encryptPrivateKey: { secret: process.env.ENCRYPTION_SECRET! },
 * })
 * ```
 */
export const makeAes256GcmCipher = (secret: string): TokenCipher => {
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
