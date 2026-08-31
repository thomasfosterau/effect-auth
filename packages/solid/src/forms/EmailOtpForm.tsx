/**
 * Passwordless sign-in by emailed one-time code: request, then verify.
 *
 * @module forms/EmailOtpForm
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

/** Every visible string {@link EmailOtpForm} renders. */
export interface EmailOtpLabels extends Record<string, string> {
  readonly email: string;
  readonly code: string;
  readonly sendSubmit: string;
  readonly sendPending: string;
  readonly verifySubmit: string;
  readonly verifyPending: string;
  /** Shown above the code field once the code has been sent. */
  readonly sent: string;
  /** Button that returns to the email step. */
  readonly restart: string;
  readonly sendError: string;
  readonly verifyError: string;
}

const DEFAULT_LABELS: EmailOtpLabels = {
  email: "Email",
  code: "Sign-in code",
  sendSubmit: "Email me a code",
  sendPending: "Sending…",
  verifySubmit: "Sign in",
  verifyPending: "Verifying…",
  sent: "We emailed you a sign-in code.",
  restart: "Use a different email",
  sendError: "Could not send the code. Please try again.",
  verifyError: "That code was not accepted. Please try again.",
};

/** Props for {@link EmailOtpForm}. */
export interface EmailOtpFormProps extends AuthFormBaseProps<AuthSuccess> {
  readonly labels?: Partial<EmailOtpLabels> | undefined;
}

/**
 * Both halves of an email one-time-code sign-in in one component: it calls
 * `client.emailOtp.send({ email, purpose: "sign-in" })`, swaps itself for a
 * code field, then calls `client.emailOtp.signIn({ email, otp })`.
 *
 * `onSuccess` fires only for the second step — the step that yields a session.
 * The rendered `<form>` carries `data-step="request"` or `data-step="verify"`
 * so a stylesheet can tell the two apart.
 */
export const EmailOtpForm = (props: EmailOtpFormProps): JSX.Element => {
  const client = createResolvedAuthClient(() => props.client);
  const labels = createMemo(() => mergeLabels(DEFAULT_LABELS, props.labels));
  const classes = createMemo(() => resolveClasses("email-otp", props.class, props.classes));
  // A submission per step, so the request step's error does not linger over
  // the verify step (and vice versa).
  const request = createSubmission();
  const verify = createSubmission();
  const [email, setEmail] = createSignal("");
  const [otp, setOtp] = createSignal("");
  const [sent, setSent] = createSignal(false);
  const prefix = createUniqueId();

  const handleRequest = (event: Event): void => {
    event.preventDefault();
    void request.run(() => client().emailOtp.send({ email: email(), purpose: "sign-in" }), {
      fallback: labels().sendError,
      onSuccess: () => setSent(true),
      onError: props.onError,
    });
  };

  const handleVerify = (event: Event): void => {
    event.preventDefault();
    void verify.run(() => client().emailOtp.signIn({ email: email(), otp: otp() }), {
      fallback: labels().verifyError,
      onSuccess: props.onSuccess,
      onError: props.onError,
    });
  };

  return (
    <Show
      fallback={
        <form
          aria-busy={request.pending() ? "true" : undefined}
          class={classes().form}
          data-step="request"
          onSubmit={handleRequest}
        >
          <Field
            autocomplete="email"
            classes={classes()}
            disabled={request.pending()}
            id={`${prefix}-email`}
            invalid={isInvalid(request.failure(), "email")}
            label={labels().email}
            name="email"
            onValueChange={setEmail}
            type="email"
            value={email()}
          />
          <FormMessages classes={classes()} failure={request.failure()} succeeded={false} />
          <SubmitButton
            classes={classes()}
            label={labels().sendSubmit}
            pending={request.pending()}
            pendingLabel={labels().sendPending}
          />
        </form>
      }
      when={sent()}
    >
      <form
        aria-busy={verify.pending() ? "true" : undefined}
        class={classes().form}
        data-step="verify"
        onSubmit={handleVerify}
      >
        <p class={classes().status} role="status">
          {labels().sent}
        </p>
        <Field
          autocomplete="one-time-code"
          classes={classes()}
          disabled={verify.pending()}
          id={`${prefix}-otp`}
          inputmode="numeric"
          invalid={isInvalid(verify.failure(), "otp")}
          label={labels().code}
          name="otp"
          onValueChange={setOtp}
          type="text"
          value={otp()}
        />
        <FormMessages classes={classes()} failure={verify.failure()} succeeded={false} />
        <SubmitButton
          classes={classes()}
          label={labels().verifySubmit}
          pending={verify.pending()}
          pendingLabel={labels().verifyPending}
        />
        <button
          class={classes().restart}
          disabled={verify.pending()}
          onClick={() => {
            setSent(false);
            setOtp("");
          }}
          type="button"
        >
          {labels().restart}
        </button>
      </form>
    </Show>
  );
};
