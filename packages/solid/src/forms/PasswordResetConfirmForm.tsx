/**
 * Step two of a password reset: redeem the emailed token for a new password.
 *
 * @module forms/PasswordResetConfirmForm
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

/** Every visible string {@link PasswordResetConfirmForm} renders. */
export interface PasswordResetConfirmLabels extends Record<string, string> {
  readonly password: string;
  readonly confirmPassword: string;
  readonly submit: string;
  readonly submitPending: string;
  /** Client-side failure when the two password fields disagree. */
  readonly mismatch: string;
  readonly success: string;
  readonly error: string;
}

const DEFAULT_LABELS: PasswordResetConfirmLabels = {
  password: "New password",
  confirmPassword: "Confirm new password",
  submit: "Reset password",
  submitPending: "Resetting…",
  mismatch: "Those passwords do not match.",
  success: "Your password has been reset.",
  error: "Could not reset your password. The link may have expired.",
};

/** Props for {@link PasswordResetConfirmForm}. */
export interface PasswordResetConfirmFormProps extends AuthFormBaseProps<StatusResponse> {
  /** The single-use token from the reset email, usually a URL query parameter. */
  readonly token: string;
  readonly labels?: Partial<PasswordResetConfirmLabels> | undefined;
}

/**
 * Sets a new password against a reset token via `client.passwordResetConfirm`.
 *
 * The confirmation field is checked in the browser — a mismatch never reaches
 * the server, and marks only the confirmation input `aria-invalid`.
 *
 * ```tsx
 * <PasswordResetConfirmForm token={new URLSearchParams(location.search).get("token") ?? ""} />
 * ```
 */
export const PasswordResetConfirmForm = (props: PasswordResetConfirmFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() =>
    resolveClasses("password-reset-confirm", props.class, props.classes),
  );
  const submission = createSubmission();
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const prefix = createUniqueId();

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    if (newPassword() !== confirmation()) {
      submission.fail(labels().mismatch, "confirmPassword");
      return;
    }
    void submission.run(
      () => client().passwordResetConfirm({ token: props.token, newPassword: newPassword() }),
      {
        fallback: labels().error,
        onSuccess: props.onSuccess,
        onError: props.onError,
      },
    );
  };

  return (
    <form
      aria-busy={submission.pending() ? "true" : undefined}
      class={classes().form}
      onSubmit={handleSubmit}
    >
      <Field
        autocomplete="new-password"
        classes={classes()}
        disabled={submission.pending()}
        id={`${prefix}-password`}
        invalid={isInvalid(submission.failure(), "password")}
        label={labels().password}
        name="newPassword"
        onValueChange={setNewPassword}
        type="password"
        value={newPassword()}
      />
      <Field
        autocomplete="new-password"
        classes={classes()}
        disabled={submission.pending()}
        id={`${prefix}-confirm-password`}
        invalid={isInvalid(submission.failure(), "confirmPassword")}
        label={labels().confirmPassword}
        name="confirmPassword"
        onValueChange={setConfirmation}
        type="password"
        value={confirmation()}
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
