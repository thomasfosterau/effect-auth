/**
 * Argon2id password hasher for effect-auth.
 *
 * Core `effect-auth` ships only dependency-free hashers (PBKDF2, scrypt).
 * Argon2id — OWASP's first-choice password hashing algorithm — needs a KDF the
 * platform does not provide, so it lives in its own package.
 *
 * This package is **pure WebAssembly**
 * ([`hash-wasm`](https://github.com/Daninet/hash-wasm)): no native module, no
 * `node:` imports, so the same code runs on Node, Bun, Deno and edge runtimes
 * such as Cloudflare Workers. Default cost parameters follow OWASP's
 * *low-memory* Argon2id profile (m = 19 MiB, t = 2, p = 1) so they fit inside a
 * Workers isolate; {@link serverProfile} (m = 64 MiB, t = 3, p = 1) is
 * available for plain-Node deployments.
 *
 * Hashes are standard PHC strings
 * (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`), and `verify` reads the cost
 * parameters out of the stored hash, so hashes interoperate with older
 * configurations of this package and with any other Argon2 implementation.
 *
 * @module argon2
 */
export * from "./Common.ts";
export * from "./Argon2.ts";
