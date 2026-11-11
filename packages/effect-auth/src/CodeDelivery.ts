/**
 * The send step the one-time-code flows (`EmailOtp`, `PhoneOtp`) share once
 * the code's record is stored. Internal: not exported from any barrel.
 */

import { Effect } from "effect";
import type { DeliveryPurpose } from "./Delivery.ts";
import type { DetachedSend } from "./DeliveryScheduler.ts";

/** What {@link deliverCode} sends, and how. */
interface CodeDeliveryOptions<E, E2> {
  /** False for an address with no account: its record is a marker and nothing is sent. */
  readonly deliver: boolean;
  /**
   * True where only a known address gets a code, so an inline send would
   * answer it later (and fail it when the vendor does) than an unknown one:
   * the send then goes off the response path (#196).
   */
  readonly hidesAccount: boolean;
  readonly purpose: DeliveryPurpose;
  /** The code to send. */
  readonly code: string;
  /** Builds the send of `code`; called only when the code is delivered. */
  readonly send: (code: string) => Effect.Effect<void, E>;
  /** The caller's error for an inline send that failed. */
  readonly onFailure: (error: E) => E2;
}

/**
 * Send a stored code: nothing when there is no account to send to, detached
 * when awaiting the send would reveal whether the account exists, and
 * otherwise inline, where a failed send is the caller's to see.
 */
export const deliverCode = <E, E2>(
  detached: DetachedSend,
  options: CodeDeliveryOptions<E, E2>,
): Effect.Effect<void, E2> => {
  if (!options.deliver) {
    return Effect.void;
  }
  if (options.hidesAccount) {
    return detached(options.purpose, options.send(options.code));
  }
  return Effect.mapError(options.send(options.code), options.onFailure);
};
