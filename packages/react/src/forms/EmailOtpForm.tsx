/**
 * Passwordless sign-in by emailed one-time code: request, then verify.
 *
 * @module forms/EmailOtpForm
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
export const EmailOtpForm = ({
  client: clientProp,
  onSuccess,
  onError,
  className,
  classes: classOverrides,
  labels: labelOverrides,
}: EmailOtpFormProps): ReactNode => {
  const client = useResolvedAuthClient(clientProp);
  const labels = mergeLabels(DEFAULT_LABELS, labelOverrides);
  const classes = resolveClasses("email-otp", className, classOverrides);
  // A submission per step, so the request step's error does not linger over
  // the verify step (and vice versa).
  const request = useSubmission();
  const verify = useSubmission();
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [sent, setSent] = useState(false);
  const prefix = useId();

  const handleRequest = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void request.run(() => client.emailOtp.send({ email, purpose: "sign-in" }), {
      fallback: labels.sendError,
      onSuccess: () => setSent(true),
      onError,
    });
  };

  const handleVerify = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void verify.run(() => client.emailOtp.signIn({ email, otp }), {
      fallback: labels.verifyError,
      onSuccess,
      onError,
    });
  };

  if (!sent) {
    return (
      <form
        aria-busy={request.pending || undefined}
        className={classes.form}
        data-step="request"
        onSubmit={handleRequest}
      >
        <Field
          autoComplete="email"
          classes={classes}
          disabled={request.pending}
          id={`${prefix}-email`}
          invalid={isInvalid(request.failure, "email")}
          label={labels.email}
          name="email"
          onValueChange={setEmail}
          type="email"
          value={email}
        />
        <FormMessages classes={classes} failure={request.failure} succeeded={false} />
        <SubmitButton
          classes={classes}
          label={labels.sendSubmit}
          pending={request.pending}
          pendingLabel={labels.sendPending}
        />
      </form>
    );
  }

  return (
    <form
      aria-busy={verify.pending || undefined}
      className={classes.form}
      data-step="verify"
      onSubmit={handleVerify}
    >
      <p className={classes.status} role="status">
        {labels.sent}
      </p>
      <Field
        autoComplete="one-time-code"
        classes={classes}
        disabled={verify.pending}
        id={`${prefix}-otp`}
        inputMode="numeric"
        invalid={isInvalid(verify.failure, "otp")}
        label={labels.code}
        name="otp"
        onValueChange={setOtp}
        type="text"
        value={otp}
      />
      <FormMessages classes={classes} failure={verify.failure} succeeded={false} />
      <SubmitButton
        classes={classes}
        label={labels.verifySubmit}
        pending={verify.pending}
        pendingLabel={labels.verifyPending}
      />
      <button
        className={classes.restart}
        disabled={verify.pending}
        onClick={() => {
          setSent(false);
          setOtp("");
        }}
        type="button"
      >
        {labels.restart}
      </button>
    </form>
  );
};
