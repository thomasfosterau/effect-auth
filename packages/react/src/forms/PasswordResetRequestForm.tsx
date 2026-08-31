/**
 * Step one of a password reset: ask for the email to send the link to.
 *
 * @module forms/PasswordResetRequestForm
 */
import { useId, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useResolvedAuthClient } from "../AuthClientContext.tsx";
import {
  Field,
  FormMessages,
  SubmitButton,
  isInvalid,
  mergeLabels,
  resolveClasses,
  useSubmission,
} from "./internal.tsx";
import type { AuthFormBaseProps, StatusResponse } from "./internal.tsx";

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
export const PasswordResetRequestForm = ({
  client: clientProp,
  onSuccess,
  onError,
  className,
  classes: classOverrides,
  labels: labelOverrides,
}: PasswordResetRequestFormProps): ReactNode => {
  const client = useResolvedAuthClient(clientProp);
  const labels = mergeLabels(DEFAULT_LABELS, labelOverrides);
  const classes = resolveClasses("password-reset-request", className, classOverrides);
  const submission = useSubmission();
  const [email, setEmail] = useState("");
  const prefix = useId();

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submission.run(() => client.passwordResetRequest({ email }), {
      fallback: labels.error,
      onSuccess,
      onError,
    });
  };

  return (
    <form
      aria-busy={submission.pending || undefined}
      className={classes.form}
      onSubmit={handleSubmit}
    >
      <Field
        autoComplete="email"
        classes={classes}
        disabled={submission.pending}
        id={`${prefix}-email`}
        invalid={isInvalid(submission.failure, "email")}
        label={labels.email}
        name="email"
        onValueChange={setEmail}
        type="email"
        value={email}
      />
      <FormMessages
        classes={classes}
        failure={submission.failure}
        succeeded={submission.succeeded}
        successMessage={labels.success}
      />
      <SubmitButton
        classes={classes}
        label={labels.submit}
        pending={submission.pending}
        pendingLabel={labels.submitPending}
      />
    </form>
  );
};
