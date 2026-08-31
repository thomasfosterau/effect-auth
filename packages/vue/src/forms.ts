/**
 * The shared vocabulary of the form components: the payload types their events
 * carry, the per-element class overrides they accept, and the English strings
 * they render by default.
 *
 * Every component in `./components.ts` is a single-file component that owns its
 * own submit/loading/error state, ships zero CSS, and emits `success` / `error`
 * rather than navigating. Styling happens from the outside through the stable
 * `ea-*` class hooks, a `class` passthrough on the root `<form>`, or the
 * per-element `classes` prop; every visible string is overridable through the
 * `labels` prop, which is merged over the defaults exported here.
 *
 * @module forms
 */
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

/** What the client resolves an authentication call to. */
export type AuthSuccess = Awaited<ReturnType<AuthClient["signIn"]>>;

/** What the client resolves a "we sent you something" call to. */
export type StatusResponse = Awaited<ReturnType<AuthClient["passwordResetRequest"]>>;

/** The purposes an email OTP can be requested for. */
export type EmailOtpPurpose = Parameters<AuthClient["emailOtp"]["send"]>[0]["purpose"];

/**
 * Per-element class overrides. Each entry replaces the default `ea-*` classes
 * for that element; omitted entries keep the defaults. A `class` attribute set
 * on the component itself is merged onto the root `<form>` as usual.
 */
export interface AuthFormClasses {
  /** Root `<form>`. Defaults to `ea-form` plus a per-form modifier. */
  readonly form?: string;
  /** Wrapper around each label + input pair. Defaults to `ea-field`. */
  readonly field?: string;
  /** Each `<label>`. Defaults to `ea-label`. */
  readonly label?: string;
  /** Each `<input>`. Defaults to `ea-input`. */
  readonly input?: string;
  /** Submit `<button>`. Defaults to `ea-submit`. */
  readonly submit?: string;
  /** The `role="alert"` error element. Defaults to `ea-error`. */
  readonly error?: string;
}

/** Visible strings for `SignInForm`. */
export interface SignInFormLabels {
  readonly email: string;
  readonly username: string;
  readonly password: string;
  readonly submit: string;
  readonly pending: string;
  readonly error: string;
}

/** English defaults for `SignInForm`. */
export const signInFormLabels: SignInFormLabels = {
  email: "Email",
  username: "Username",
  password: "Password",
  submit: "Sign in",
  pending: "Signing in…",
  error: "Sign-in failed. Please check your details and try again.",
};

/** Visible strings for `SignUpForm`. */
export interface SignUpFormLabels {
  readonly name: string;
  readonly email: string;
  readonly password: string;
  readonly submit: string;
  readonly pending: string;
  readonly error: string;
}

/** English defaults for `SignUpForm`. */
export const signUpFormLabels: SignUpFormLabels = {
  name: "Name",
  email: "Email",
  password: "Password",
  submit: "Create account",
  pending: "Creating account…",
  error: "Sign-up failed. Please check your details and try again.",
};

/** Visible strings for `PasswordResetRequestForm`. */
export interface PasswordResetRequestFormLabels {
  readonly email: string;
  readonly submit: string;
  readonly pending: string;
  readonly error: string;
}

/** English defaults for `PasswordResetRequestForm`. */
export const passwordResetRequestFormLabels: PasswordResetRequestFormLabels = {
  email: "Email",
  submit: "Send reset link",
  pending: "Sending…",
  error: "Could not send the reset link. Please try again.",
};

/** Visible strings for `PasswordResetConfirmForm`. */
export interface PasswordResetConfirmFormLabels {
  readonly password: string;
  readonly confirm: string;
  readonly submit: string;
  readonly pending: string;
  readonly mismatch: string;
  readonly error: string;
}

/** English defaults for `PasswordResetConfirmForm`. */
export const passwordResetConfirmFormLabels: PasswordResetConfirmFormLabels = {
  password: "New password",
  confirm: "Confirm new password",
  submit: "Set new password",
  pending: "Saving…",
  mismatch: "The two passwords do not match.",
  error: "Could not reset the password. The link may have expired.",
};

/** Visible strings for `MagicLinkForm`. */
export interface MagicLinkFormLabels {
  readonly email: string;
  readonly submit: string;
  readonly pending: string;
  readonly error: string;
}

/** English defaults for `MagicLinkForm`. */
export const magicLinkFormLabels: MagicLinkFormLabels = {
  email: "Email",
  submit: "Send magic link",
  pending: "Sending…",
  error: "Could not send the magic link. Please try again.",
};

/** Visible strings for `EmailOtpForm`, which labels both of its steps. */
export interface EmailOtpFormLabels {
  readonly email: string;
  readonly code: string;
  readonly request: string;
  readonly requestPending: string;
  readonly verify: string;
  readonly verifyPending: string;
  readonly requestError: string;
  readonly verifyError: string;
}

/** English defaults for `EmailOtpForm`. */
export const emailOtpFormLabels: EmailOtpFormLabels = {
  email: "Email",
  code: "Verification code",
  request: "Send code",
  requestPending: "Sending…",
  verify: "Sign in",
  verifyPending: "Verifying…",
  requestError: "Could not send the code. Please try again.",
  verifyError: "That code was not accepted. Please try again.",
};
