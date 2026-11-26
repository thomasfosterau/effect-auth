/**
 * BetterAuth's scrypt password hashes as a core `PasswordHasher`: the seam
 * that keeps BetterAuth's hashes verifying after a move to native effect-auth.
 *
 * @since 0.1.0
 */
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { hashPassword, verifyPassword } from "better-auth/crypto";

/**
 * The algorithm id, and the prefix that routes a hash to this hasher under
 * `Auth.Password.MultiAlgorithmVerifier`.
 *
 * @since 0.1.0
 * @category constants
 */
export const ALGORITHM = "better-auth-scrypt";

const PREFIX = `${ALGORITHM}$`;

/** Longest password hashed or verified, in UTF-8 bytes (anti-DoS, as in the core). */
const MAX_PASSWORD_BYTES = 1024;

const encoder = new TextEncoder();

const hashingError = (message: string, cause?: unknown) =>
  new Auth.HashingError({ message, ...(cause !== undefined && { cause }) });

/**
 * BetterAuth's `salt:key` scrypt hash (hex, through `better-auth/crypto`),
 * byte for byte what BetterAuth's `account.password` column holds.
 *
 * `hash` writes BetterAuth's own format, so a hash it writes still verifies
 * in BetterAuth. `verify` accepts that format and the same hash prefixed with
 * `better-auth-scrypt$`, which is how to store moved hashes beside the
 * core's own: `MultiAlgorithmVerifier` routes on the segment before the first
 * `$`, and a bare `salt:key` has none.
 *
 * @since 0.1.0
 * @category constructors
 */
export const betterAuthHasher = (): typeof Auth.Password.PasswordHasher.Service => ({
  algorithm: ALGORITHM,
  hash: (password) =>
    Effect.gen(function* () {
      if (password === "") return yield* hashingError("Password must not be empty");
      if (encoder.encode(password).length > MAX_PASSWORD_BYTES) {
        return yield* hashingError("Password is too long");
      }
      const hash = yield* Effect.tryPromise({
        try: () => hashPassword(password),
        catch: (cause) => hashingError("BetterAuth scrypt hashing failed", cause),
      });
      return { hash, algorithm: ALGORITHM };
    }),
  verify: (password, stored) =>
    Effect.gen(function* () {
      const hash = stored.startsWith(PREFIX) ? stored.slice(PREFIX.length) : stored;
      if (!/^[0-9a-f]+:[0-9a-f]+$/.test(hash)) {
        return yield* hashingError("Not a BetterAuth scrypt hash");
      }
      if (password === "" || encoder.encode(password).length > MAX_PASSWORD_BYTES) return false;
      return yield* Effect.tryPromise({
        try: () => verifyPassword({ hash, password }),
        catch: (cause) => hashingError("BetterAuth scrypt verification failed", cause),
      });
    }),
});

/**
 * {@link betterAuthHasher} as the `PasswordHasher` layer.
 *
 * @since 0.1.0
 * @category layers
 */
export const layer: Layer.Layer<Auth.Password.PasswordHasher> = Layer.sync(
  Auth.Password.PasswordHasher,
  betterAuthHasher,
);
