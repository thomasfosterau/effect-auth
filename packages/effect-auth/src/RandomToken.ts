/**
 * Random bearer-token generation shared by the token-issuing services.
 * Internal: not exported from any barrel.
 */

import { Effect } from "effect";
import { Base64Url } from "effect/encoding";
import type { SecureRandom } from "effect/crypto";
import * as Errors from "./Errors.ts";

/**
 * A 256-bit random token, base64url-encoded, drawn from the `SecureRandom` service.
 * A failure to draw randomness becomes an `AuthError` with `failureMessage`.
 */
export const randomBase64UrlToken = (
  crypto: typeof SecureRandom.SecureRandom.Service,
  failureMessage = "Failed to generate token",
): Effect.Effect<string, Errors.AuthError> =>
  crypto.randomBytes(32).pipe(
    Effect.map(Base64Url.encode),
    Effect.mapError((cause) => new Errors.AuthError({ message: failureMessage, cause })),
  );
