/**
 * Random bearer-token generation shared by the token-issuing services.
 * Internal: not exported from any barrel.
 */

import { Effect } from "effect";
import { Base64Url } from "effect/encoding";
import type { SecureRandom } from "effect/crypto";

/**
 * A 256-bit random token, base64url-encoded, drawn from the `SecureRandom` service.
 * Drawing randomness cannot fail (`SecureRandom`'s error channel is `never`).
 */
export const randomBase64UrlToken = (
  crypto: typeof SecureRandom.SecureRandom.Service,
): Effect.Effect<string> => crypto.randomBytes(32).pipe(Effect.map(Base64Url.encode));
