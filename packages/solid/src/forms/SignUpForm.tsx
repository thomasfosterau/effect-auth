/**
 * Email + password registration, with an optional display-name field.
 *
 * @module forms/SignUpForm
 */
import { Show, createMemo, createSignal, createUniqueId } from "solid-js";
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
 * <SignUpForm showName={false} onSuccess={(result) => console.log(result.user?.id)} />
 * ```
 */
export const SignUpForm = (props: SignUpFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() => resolveClasses("sign-up", props.class, props.classes));
  const submission = createSubmission();
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [name, setName] = createSignal("");
  const prefix = createUniqueId();

  const showName = (): boolean => props.showName !== false;

  const handleSubmit = (event: Event): void => {
    event.preventDefault();
    const trimmedName = name().trim();
    // `name` is optional on the wire; spread it in only when there is one.
    const payload =
      showName() && trimmedName.length > 0
        ? { email: email(), password: password(), name: trimmedName }
        : { email: email(), password: password() };
    void submission.run(() => client().signUp(payload), {
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
      <Show when={showName()}>
        <Field
          autocomplete="name"
          classes={classes()}
          disabled={submission.pending()}
          id={`${prefix}-name`}
          invalid={isInvalid(submission.failure(), "name")}
          label={labels().name}
          name="name"
          onValueChange={setName}
          required={false}
          type="text"
          value={name()}
        />
      </Show>
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
      <Field
        autocomplete="new-password"
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
