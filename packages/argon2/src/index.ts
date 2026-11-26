/**
 * Argon2id for effect-auth on every runtime without a native Argon2 `Kdf`,
 * Cloudflare Workers above all (compatibility date 2025-06-01 or later). The
 * defaults follow OWASP's low-memory profile (19 MiB, t = 2); {@link
 * serverProfile} is 64 MiB, t = 3. Hashes are standard PHC strings.
 *
 * @module argon2
 */
export * from "./Common.ts";
export * from "./Argon2.ts";
