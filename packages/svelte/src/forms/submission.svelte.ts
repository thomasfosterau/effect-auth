/**
 * The submit lifecycle every bundled form shares, as a rune-backed factory.
 *
 * A `.svelte.ts` module rather than a plain one so `$state` is available: the
 * returned object's getters are reactive in whichever component created it, and
 * one form (the email-OTP form) owns two of these at once, one per step.
 *
 * @module forms/submission
 */
import { messageOf, type FormFailure } from "./internal.ts";

/** How a submission should report itself. @internal */
export interface SubmitHandlers<T> {
  /** Message shown when the thrown value carries none. */
  readonly fallback: string;
  readonly onSuccess?: ((result: T) => void) | undefined;
  readonly onError?: ((error: unknown) => void) | undefined;
}

/** One form's submit lifecycle. @internal */
export interface Submission {
  /** `true` while a request is in flight. */
  readonly pending: boolean;
  /** The failure to render, or `null`. */
  readonly failure: FormFailure | null;
  /** `true` once a submit has resolved and nothing has been re-submitted. */
  readonly succeeded: boolean;
  /** Record a client-side validation failure against `field`. */
  readonly fail: (message: string, field: string) => void;
  /** Run `work`, tracking pending/error state and firing the callbacks. */
  readonly run: <T>(work: () => Promise<T>, handlers: SubmitHandlers<T>) => Promise<void>;
}

/** Own the submit/pending/error state of one form (or one step of one). @internal */
export const createSubmission = (): Submission => {
  let pending = $state(false);
  let failure = $state<FormFailure | null>(null);
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
      failure = { message, field };
    },
    run: async <T>(work: () => Promise<T>, handlers: SubmitHandlers<T>): Promise<void> => {
      if (busy) return;
      busy = true;
      pending = true;
      failure = null;
      succeeded = false;
      try {
        const result = await work();
        busy = false;
        pending = false;
        succeeded = true;
        handlers.onSuccess?.(result);
      } catch (cause) {
        busy = false;
        pending = false;
        failure = { message: messageOf(cause, handlers.fallback), field: null };
        handlers.onError?.(cause);
      }
    },
  };
};
