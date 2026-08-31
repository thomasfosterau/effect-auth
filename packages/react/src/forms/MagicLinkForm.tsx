/**
 * Passwordless sign-in by emailed link.
 *
 * @module forms/MagicLinkForm
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
export const MagicLinkForm = ({
  client: clientProp,
  onSuccess,
  onError,
  className,
  classes: classOverrides,
  labels: labelOverrides,
}: MagicLinkFormProps): ReactNode => {
  const client = useResolvedAuthClient(clientProp);
  const labels = mergeLabels(DEFAULT_LABELS, labelOverrides);
  const classes = resolveClasses("magic-link", className, classOverrides);
  const submission = useSubmission();
  const [email, setEmail] = useState("");
  const prefix = useId();

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submission.run(() => client.magicLink.send({ email }), {
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
