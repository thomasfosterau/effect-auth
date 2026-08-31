/**
 * Email (or username) + password sign-in.
 *
 * @module forms/SignInForm
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
import type { AuthFormBaseProps, AuthSuccess } from "./internal.jsx";

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
 * <SignInForm onSuccess={() => navigate("/app")} />
 * ```
 */
export const SignInForm = (props: SignInFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() => resolveClasses("sign-in", props.class, props.classes));
  const submission = createSubmission();
  const [identifier, setIdentifier] = createSignal("");
  const [password, setPassword] = createSignal("");
  const prefix = createUniqueId();

  const isUsername = (): boolean => props.variant === "username";

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    void submission.run(
      () =>
        isUsername()
          ? client().signInUsername({ username: identifier(), password: password() })
          : client().signIn({ email: identifier(), password: password() }),
      { fallback: labels().error, onSuccess: props.onSuccess, onError: props.onError },
    );
  };

  return (
    <form
      aria-busy={submission.pending() ? "true" : undefined}
      class={classes().form}
      data-variant={props.variant ?? "email"}
      onSubmit={handleSubmit}
    >
      <Field
        autocomplete={isUsername() ? "username" : "email"}
        classes={classes()}
        disabled={submission.pending()}
        id={`${prefix}-identifier`}
        invalid={isInvalid(submission.failure(), "identifier")}
        label={isUsername() ? labels().username : labels().email}
        name={isUsername() ? "username" : "email"}
        onValueChange={setIdentifier}
        type={isUsername() ? "text" : "email"}
        value={identifier()}
      />
      <Field
        autocomplete="current-password"
        classes={classes()}
        disabled={submission.pending()}
        id={`${prefix}-password`}
        invalid={isInvalid(submission.failure(), "password")}
        label={labels().password}
        name="password"
        onValueChange={setPassword}
        type="password"
        value={password()}
      />
      <FormMessages classes={classes()} failure={submission.failure()} succeeded={false} />
      <SubmitButton
        classes={classes()}
        label={labels().submit}
        pending={submission.pending()}
        pendingLabel={labels().submitPending}
      />
    </form>
  );
};
