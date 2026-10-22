/**
 * Random bearer-token generation shared by the token-issuing services.
 * Internal: not exported from any barrel.
 */

import { type Crypto, Effect } from "effect";
import * as Errors from "./Errors.ts";

/**
 * A 256-bit random token, base64url-encoded, drawn from the `Crypto` service.
 * A failure to draw randomness becomes an `AuthError` with `failureMessage`.
 */
export const randomBase64UrlToken = (
  crypto: Crypto.Crypto,
  failureMessage = "Failed to generate token",
): Effect.Effect<string, Errors.AuthError> =>
  crypto.randomBytes(32).pipe(
    Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
    Effect.mapError((cause) => new Errors.AuthError({ message: failureMessage, cause })),
  );
