/**
 * The submit lifecycle every bundled form shares, as a rune-backed factory: a
 * `.svelte.ts` module so `$state` works, and one form may own several.
 *
 * @module forms/submission
 */
import * as Option from "effect/Option";
import { messageOf, type FormFailure } from "./internal.ts";

/** One form's submit lifecycle. @internal */
export interface Submission {
  /** `true` while a request is in flight. */
  readonly pending: boolean;
  /** The failure to render, or `None`. */
  readonly failure: Option.Option<FormFailure>;
  /** `true` once a submit has resolved and nothing has been re-submitted. */
  readonly succeeded: boolean;
  /** Record a client-side validation failure against `field`. */
  readonly fail: (message: string, field: string) => void;
  /**
   * Run `work`, tracking pending/error state and firing the callbacks;
   * `fallback` is the message shown when the thrown value carries none.
   */
  readonly run: <T>(
    work: () => Promise<T>,
    fallback: string,
    onSuccess?: (result: T) => void,
    onError?: (error: unknown) => void,
  ) => Promise<void>;
}

/** Own the submit/pending/error state of one form (or one step of one). @internal */
export const createSubmission = (): Submission => {
  let pending = $state(false);
  let failure = $state(Option.none<FormFailure>());
  let succeeded = $state(false);
  // Guards against a second submit landing between the click and the state
  // update — `pending` disables the button, but a keyboard repeat can beat it.
  let busy = false;

  return {
    get pending() {
      return pending;
    },
    get failure() {
      return failure;
    },
    get succeeded() {
      return succeeded;
    },
    fail: (message, field) => {
      succeeded = false;
      failure = Option.some({ message, field: Option.some(field) });
    },
    run: async <T>(
      work: () => Promise<T>,
      fallback: string,
      onSuccess?: (result: T) => void,
      onError?: (error: unknown) => void,
    ): Promise<void> => {
      if (busy) return;
      busy = true;
      pending = true;
      failure = Option.none();
      succeeded = false;
      try {
        const result = await work();
        busy = false;
        pending = false;
        succeeded = true;
        onSuccess?.(result);
      } catch (cause) {
        busy = false;
        pending = false;
        failure = Option.some({
          message: messageOf(cause, fallback),
          field: Option.none(),
        });
        onError?.(cause);
      }
    },
  };
};
