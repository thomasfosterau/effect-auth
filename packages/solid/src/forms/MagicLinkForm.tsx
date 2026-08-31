/**
 * Passwordless sign-in by emailed link.
 *
 * @module forms/MagicLinkForm
 */
import { createMemo, createSignal, createUniqueId } from "solid-js";
import type { JSX } from "solid-js";
import { createResolvedAuthClient } from "../AuthClientContext.jsx";
import {
  Field,
  FormMessages,
  SubmitButton,
  createSubmission,
  isInvalid,
  mergeLabels,
  resolveClasses,
} from "./internal.jsx";
import type { AuthFormBaseProps, StatusResponse } from "./internal.jsx";

/** Every visible string {@link MagicLinkForm} renders. */
export interface MagicLinkLabels extends Record<string, string> {
  readonly email: string;
  readonly submit: string;
  readonly submitPending: string;
  readonly success: string;
  readonly error: string;
}

const DEFAULT_LABELS: MagicLinkLabels = {
  email: "Email",
  submit: "Email me a sign-in link",
  submitPending: "Sending…",
  success: "Check your inbox for your sign-in link.",
  error: "Could not send the sign-in link. Please try again.",
};

/** Props for {@link MagicLinkForm}. */
export interface MagicLinkFormProps extends AuthFormBaseProps<StatusResponse> {
  readonly labels?: Partial<MagicLinkLabels> | undefined;
}

/**
 * Requests a magic link via `client.magicLink.send`.
 *
 * Redeeming the link is a page-load concern, not a form one: the landing route
 * calls `client.magicLink.verify({ token })` with the token from the URL.
 */
export const MagicLinkForm = (props: MagicLinkFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() => resolveClasses("magic-link", props.class, props.classes));
  const submission = createSubmission();
  const [email, setEmail] = createSignal("");
  const prefix = createUniqueId();

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    void submission.run(() => client().magicLink.send({ email: email() }), {
      fallback: labels().error,
      onSuccess: props.onSuccess,
      onError: props.onError,
    });
  };

  return (
    <form
      aria-busy={submission.pending() ? "true" : undefined}
      class={classes().form}
      onSubmit={handleSubmit}
    >
      <Field
        autocomplete="email"
        classes={classes()}
        disabled={submission.pending()}
        id={`${prefix}-email`}
        invalid={isInvalid(submission.failure(), "email")}
        label={labels().email}
        name="email"
        onValueChange={setEmail}
        type="email"
        value={email()}
      />
      <FormMessages
        classes={classes()}
        failure={submission.failure()}
        succeeded={submission.succeeded()}
        successMessage={labels().success}
      />
      <SubmitButton
        classes={classes()}
        label={labels().submit}
        pending={submission.pending()}
        pendingLabel={labels().submitPending}
      />
    </form>
  );
};
