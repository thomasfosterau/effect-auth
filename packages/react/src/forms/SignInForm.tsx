/**
 * Email (or username) + password sign-in.
 *
 * @module forms/SignInForm
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

/** Every visible string {@link SignInForm} renders. */
export interface SignInLabels extends Record<string, string> {
  readonly email: string;
  readonly username: string;
  readonly password: string;
  readonly submit: string;
  readonly submitPending: string;
  /** Shown when the server's error carries no message of its own. */
  readonly error: string;
}

const DEFAULT_LABELS: SignInLabels = {
  email: "Email",
  username: "Username",
  password: "Password",
  submit: "Sign in",
  submitPending: "Signing in…",
  error: "Sign-in failed. Please check your details and try again.",
};

/** Props for {@link SignInForm}. */
export interface SignInFormProps extends AuthFormBaseProps<AuthSuccess> {
  /**
   * Which identifier to sign in with. `"email"` (the default) calls
   * `client.signIn`; `"username"` calls `client.signInUsername`, which the
   * server only answers when the username module is configured.
   */
  readonly variant?: "email" | "username" | undefined;
  readonly labels?: Partial<SignInLabels> | undefined;
}

/**
 * A sign-in form that owns its own submit, pending and error state.
 *
 * ```tsx
 * <SignInForm onSuccess={() => router.push("/app")} />
 * ```
 */
export const SignInForm = ({
  variant = "email",
  client: clientProp,
  onSuccess,
  onError,
  className,
  classes: classOverrides,
  labels: labelOverrides,
}: SignInFormProps): ReactNode => {
  const client = useResolvedAuthClient(clientProp);
  const labels = mergeLabels(DEFAULT_LABELS, labelOverrides);
  const classes = resolveClasses("sign-in", className, classOverrides);
  const submission = useSubmission();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const prefix = useId();

  const isUsername = variant === "username";

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submission.run(
      () =>
        isUsername
          ? client.signInUsername({ username: identifier, password })
          : client.signIn({ email: identifier, password }),
      { fallback: labels.error, onSuccess, onError },
    );
  };

  return (
    <form
      aria-busy={submission.pending || undefined}
      className={classes.form}
      data-variant={variant}
      onSubmit={handleSubmit}
    >
      <Field
        autoComplete={isUsername ? "username" : "email"}
        classes={classes}
        disabled={submission.pending}
        id={`${prefix}-identifier`}
        invalid={isInvalid(submission.failure, "identifier")}
        label={isUsername ? labels.username : labels.email}
        name={isUsername ? "username" : "email"}
        onValueChange={setIdentifier}
        type={isUsername ? "text" : "email"}
        value={identifier}
      />
      <Field
        autoComplete="current-password"
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
