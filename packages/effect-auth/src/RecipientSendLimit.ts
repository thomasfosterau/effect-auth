/**
 * The per-recipient send cap (#684), shared by every flow that sends a code or
 * a link to an address the caller names: the email and phone OTPs, the magic
 * link, the password reset and the email-verification resend. Internal: not
 * exported from any barrel.
 *
 * The per-IP limit (#582, #583) bounds what one client sends, and the OTP
 * failure backoff (#590) bounds guessing; neither bounds what one recipient
 * receives from many clients. This counts sends per (recipient, purpose)
 * through the `RateLimiter` over the host's `RateLimitStore`, under the key
 * `recipient-send:<purpose>:<digest>`, where the digest is the `hashToken` of
 * the normalized address, so no raw address sits in the store. A flow counts a
 * request whatever the lookup of the address finds, so an unknown address is
 * capped exactly as a known one.
 */
import { Effect } from "effect";
import { type AuthError, RateLimitError } from "./Errors.ts";
import * as RateLimit from "./RateLimit.ts";
import { hashToken } from "./TokenHash.ts";
import type { RecipientSendLimit } from "./Types.ts";

/** The default cap: 5 sends per recipient per purpose per hour. */
export const defaultRecipientSendLimit: RecipientSendLimit = {
  max: 5,
  windowMs: 60 * 60 * 1000,
};

/** The prefix of every cap's `RateLimitStore` key (and its metric label). */
const keyPrefix = "recipient-send";

/** The `RateLimitStore` key of a (purpose, recipient) pair: the recipient only as its digest. */
export const recipientSendKey = (purpose: string, recipient: string): string =>
  `${keyPrefix}:${purpose}:${hashToken(recipient)}`;

/**
 * Whether `error` is a cap's refusal, as opposed to a hook's or another
 * limiter's `RateLimitError`. A caller that hides whether an address has an
 * account (the email-verification resends) answers it as any other request.
 */
export const isRecipientSendCapped = (error: { readonly _tag: string }): boolean =>
  error instanceof RateLimitError && error.key.startsWith(`${keyPrefix}:`);

/** Count one send to `recipient` for `purpose`, failing once the pair is past its cap. */
export type RecipientSendGate = (
  purpose: string,
  recipient: string,
) => Effect.Effect<void, RateLimitError | AuthError>;

/**
 * Build a flow's gate from its `recipientSendLimit` option: `undefined` means
 * {@link defaultRecipientSendLimit}, `false` a gate that counts nothing. The
 * refusal carries the time left in the window as `retryAfter`, and a message
 * that names neither the address nor the key.
 */
export const makeRecipientSendGate = (
  limit: RecipientSendLimit | false | undefined,
): Effect.Effect<RecipientSendGate, never, RateLimit.RateLimitStore> =>
  Effect.gen(function* () {
    if (limit === false) {
      return () => Effect.void;
    }
    const { max, windowMs } = limit ?? defaultRecipientSendLimit;
    const limiter = yield* RateLimit.make();
    const config: RateLimit.RateLimitConfig = { maxRequests: max, windowMs };
    return (purpose: string, recipient: string) =>
      limiter.consumeToken(recipientSendKey(purpose, recipient), config).pipe(
        Effect.catchTag("RateLimitError", (error) =>
          Effect.fail(
            new RateLimitError({
              message: "Too many messages sent to this recipient; try again later",
              key: error.key,
              retryAfter: error.retryAfter,
            }),
          ),
        ),
      );
  });
