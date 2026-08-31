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
/**
 * SHA-256 hex digest of a token string.
 *
 * Use for any high-entropy secret that must be stored at rest (bearer tokens,
 * OTPs, API keys, OIDC codes). The same input always produces the same
 * output, so this can be used as a deterministic store key.
 */
import { createHash, timingSafeEqual } from "node:crypto";

export const hashToken = (token: string): string =>
  createHash("sha256").update(token).digest("hex");

/**
 * Constant-time comparison of two equal-length byte sequences (raw digests,
 * HMACs, signatures). Every timing-safe comparison in effect-auth routes
 * through this function so `node:crypto`'s `timingSafeEqual` stays corralled
 * to this module.
 */
export const timingSafeEqualBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
};

/**
 * Constant-time comparison of two hex-encoded SHA-256 digests.
 *
 * Always compare hashes with this function rather than `===` to prevent
 * timing side-channels.
 */
export const constantTimeHashEqual = (a: string, b: string): boolean =>
  timingSafeEqualBytes(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
