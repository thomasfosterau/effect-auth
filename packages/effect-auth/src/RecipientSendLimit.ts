/**
 * The per-recipient send cap for every flow that sends a code or link to an
 * address the caller names: sends per (purpose, recipient) through the
 * `RateLimiter`, keyed by the address's digest. An unknown address is capped
 * exactly as a known one. Internal.
 */
import { Effect } from "effect";
import type { Digest } from "effect/crypto";
import { type AuthError, RateLimitError } from "./Errors.ts";
import * as RateLimit from "./RateLimit.ts";
import { tokenHasher } from "./TokenHash.ts";
import type { RecipientSendLimit } from "./Types.ts";

/** The default cap: 5 sends per recipient per purpose per hour. */
export const defaultRecipientSendLimit: RecipientSendLimit = {
  max: 5,
  windowMs: 60 * 60 * 1000,
};

/** The prefix of every cap's `RateLimitStore` key (and its metric label). */
const keyPrefix = "recipient-send";

/** The `RateLimitStore` key of a (purpose, recipient) pair: the recipient only as its digest. */
const keyFor = (purpose: string, digest: string): string => `${keyPrefix}:${purpose}:${digest}`;

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
): Effect.Effect<RecipientSendGate, never, RateLimit.RateLimitStore | Digest.Digest> =>
  Effect.gen(function* () {
    if (limit === false) {
      return () => Effect.void;
    }
    const { max, windowMs } = limit ?? defaultRecipientSendLimit;
    const limiter = yield* RateLimit.make;
    const hash = yield* tokenHasher;
    const config: RateLimit.RateLimitConfig = { maxRequests: max, windowMs };
    return (purpose: string, recipient: string) =>
      Effect.flatMap(hash(recipient), (digest) =>
        limiter.consumeToken(keyFor(purpose, digest), config),
      ).pipe(
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
