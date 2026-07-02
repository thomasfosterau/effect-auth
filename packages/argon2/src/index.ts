/**
 * @effect-auth/argon2
 *
 * Argon2id password hasher for effect-auth, backed by the prebuilt
 * `@node-rs/argon2` native bindings. Emits and accepts standard PHC strings so
 * hashes interoperate with other Argon2 tooling.
 *
 * @example
 * ```ts
 * import { makeArgon2Hasher, Argon2HasherLayer } from "@effect-auth/argon2";
 * import { makeMultiAlgorithmVerifier, makePBKDF2Hasher } from "effect-auth";
 *
 * // Hash new passwords with Argon2id; verify legacy PBKDF2 hashes too.
 * const verifier = makeMultiAlgorithmVerifier([makeArgon2Hasher(), makePBKDF2Hasher()]);
 * ```
 */
export * from "./Argon2.js";
