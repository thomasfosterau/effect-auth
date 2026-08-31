/**
 * Email + password registration, with an optional display-name field.
 *
 * @module forms/SignUpForm
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
import type { AuthFormBaseProps, AuthSuccess } from "./internal.tsx";

/** Every visible string {@link SignUpForm} renders. */
export interface SignUpLabels extends Record<string, string> {
  readonly email: string;
  readonly password: string;
  readonly name: string;
  readonly submit: string;
  readonly submitPending: string;
  readonly error: string;
}

const DEFAULT_LABELS: SignUpLabels = {
  email: "Email",
  password: "Password",
  name: "Name",
  submit: "Create account",
  submitPending: "Creating account…",
  error: "Sign-up failed. Please check your details and try again.",
};

/** Props for {@link SignUpForm}. */
export interface SignUpFormProps extends AuthFormBaseProps<AuthSuccess> {
  /**
   * Render the display-name field. On by default because the client's sign-up
   * payload carries an optional `name`; a blank name is omitted from the
   * request rather than sent as `""`.
   */
  readonly showName?: boolean | undefined;
  readonly labels?: Partial<SignUpLabels> | undefined;
}

/**
 * A registration form that owns its own submit, pending and error state.
 *
 * ```tsx
 * <SignUpForm showName={false} onSuccess={({ needsEmailVerification }) => ...} />
 * ```
 */
export const SignUpForm = ({
  showName = true,
  client: clientProp,
  onSuccess,
  onError,
  className,
  classes: classOverrides,
  labels: labelOverrides,
}: SignUpFormProps): ReactNode => {
  const client = useResolvedAuthClient(clientProp);
  const labels = mergeLabels(DEFAULT_LABELS, labelOverrides);
  const classes = resolveClasses("sign-up", className, classOverrides);
  const submission = useSubmission();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const prefix = useId();

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const trimmedName = name.trim();
    // `name` is optional on the wire; spread it in only when there is one.
    const payload =
      showName && trimmedName.length > 0
        ? { email, password, name: trimmedName }
        : { email, password };
    void submission.run(() => client.signUp(payload), {
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
      {showName ? (
        <Field
          autoComplete="name"
          classes={classes}
          disabled={submission.pending}
          id={`${prefix}-name`}
          invalid={isInvalid(submission.failure, "name")}
          label={labels.name}
          name="name"
          onValueChange={setName}
          required={false}
          type="text"
          value={name}
        />
      ) : null}
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
      <Field
        autoComplete="new-password"
        classes={classes}
        disabled={submission.pending}
        id={`${prefix}-password`}
        invalid={isInvalid(submission.failure, "password")}
        label={labels.password}
        name="password"
        onValueChange={setPassword}
        type="password"
        value={password}
      />
      <FormMessages classes={classes} failure={submission.failure} succeeded={false} />
      <SubmitButton
        classes={classes}
        label={labels.submit}
        pending={submission.pending}
        pendingLabel={labels.submitPending}
      />
    </form>
  );
};
