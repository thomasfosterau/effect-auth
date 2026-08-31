/**
 * Step one of a password reset: ask for the email to send the link to.
 *
 * @module forms/PasswordResetRequestForm
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

/** Every visible string {@link PasswordResetRequestForm} renders. */
export interface PasswordResetRequestLabels extends Record<string, string> {
  readonly email: string;
  readonly submit: string;
  readonly submitPending: string;
  /** Rendered in a `role="status"` element once the request succeeds. */
  readonly success: string;
  readonly error: string;
}

const DEFAULT_LABELS: PasswordResetRequestLabels = {
  email: "Email",
  submit: "Send reset link",
  submitPending: "Sending…",
  success: "If that email has an account, a reset link is on its way.",
  error: "Could not send the reset link. Please try again.",
};

/** Props for {@link PasswordResetRequestForm}. */
export interface PasswordResetRequestFormProps extends AuthFormBaseProps<StatusResponse> {
  readonly labels?: Partial<PasswordResetRequestLabels> | undefined;
}

/**
 * Requests a password-reset email via `client.passwordResetRequest`.
 *
 * The success copy is deliberately non-committal: the server answers the same
 * way for a registered and an unregistered address, and the form should not
 * leak the difference.
 */
export const PasswordResetRequestForm = (props: PasswordResetRequestFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() =>
    resolveClasses("password-reset-request", props.class, props.classes),
  );
  const submission = createSubmission();
  const [email, setEmail] = createSignal("");
  const prefix = createUniqueId();

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    void submission.run(() => client().passwordResetRequest({ email: email() }), {
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
