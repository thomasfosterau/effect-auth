/**
 * The props and label sets of the six bundled form components, plus their
 * default copy.
 *
 * They live in a `.ts` module rather than beside each component because a
 * Svelte instance script cannot export types: keeping them here is what lets
 * `SignInFormProps`, `SignInLabels` and friends be part of the package's public
 * type surface.
 *
 * @module forms/props
 */
import type {
  AuthFormBaseProps,
  AuthSuccess,
  EmailOtpPurpose,
  StatusResponse,
} from "./internal.ts";

/** Every visible string `SignInForm` renders. */
export interface SignInLabels extends Record<string, string> {
  readonly email: string;
  readonly username: string;
  readonly password: string;
  readonly submit: string;
  readonly submitPending: string;
  /** Shown when the server's error carries no message of its own. */
  readonly error: string;
}

/** @internal */
export const SIGN_IN_LABELS: SignInLabels = {
  email: "Email",
  username: "Username",
  password: "Password",
  submit: "Sign in",
  submitPending: "Signing in…",
  error: "Sign-in failed. Please check your details and try again.",
};

/** Props for `SignInForm`. */
export interface SignInFormProps extends AuthFormBaseProps<AuthSuccess> {
  /**
   * Which identifier to sign in with. `"email"` (the default) calls
   * `client.signIn`; `"username"` calls `client.signInUsername`, which the
   * server only answers when the username module is configured.
   */
  readonly variant?: "email" | "username" | undefined;
  readonly labels?: Partial<SignInLabels> | undefined;
}

/** Every visible string `SignUpForm` renders. */
export interface SignUpLabels extends Record<string, string> {
  readonly email: string;
  readonly password: string;
  readonly name: string;
  readonly submit: string;
  readonly submitPending: string;
  readonly error: string;
}

/** @internal */
export const SIGN_UP_LABELS: SignUpLabels = {
  email: "Email",
  password: "Password",
  name: "Name",
  submit: "Create account",
  submitPending: "Creating account…",
  error: "Sign-up failed. Please check your details and try again.",
};

/** Props for `SignUpForm`. */
export interface SignUpFormProps extends AuthFormBaseProps<AuthSuccess> {
  /**
   * Render the display-name field. On by default because the client's sign-up
   * payload carries an optional `name`; a blank name is omitted from the
   * request rather than sent as `""`.
   */
  readonly showName?: boolean | undefined;
  readonly labels?: Partial<SignUpLabels> | undefined;
}

/** Every visible string `PasswordResetRequestForm` renders. */
export interface PasswordResetRequestLabels extends Record<string, string> {
  readonly email: string;
  readonly submit: string;
  readonly submitPending: string;
  /** Rendered in a `role="status"` element once the request succeeds. */
  readonly success: string;
  readonly error: string;
}

/** @internal */
export const PASSWORD_RESET_REQUEST_LABELS: PasswordResetRequestLabels = {
  email: "Email",
  submit: "Send reset link",
  submitPending: "Sending…",
  success: "If that email has an account, a reset link is on its way.",
  error: "Could not send the reset link. Please try again.",
};

/** Props for `PasswordResetRequestForm`. */
export interface PasswordResetRequestFormProps extends AuthFormBaseProps<StatusResponse> {
  readonly labels?: Partial<PasswordResetRequestLabels> | undefined;
}

/** Every visible string `PasswordResetConfirmForm` renders. */
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

/** @internal */
export const PASSWORD_RESET_CONFIRM_LABELS: PasswordResetConfirmLabels = {
  password: "New password",
  confirmPassword: "Confirm new password",
  submit: "Reset password",
  submitPending: "Resetting…",
  mismatch: "Those passwords do not match.",
  success: "Your password has been reset.",
  error: "Could not reset your password. The link may have expired.",
};

/** Props for `PasswordResetConfirmForm`. */
export interface PasswordResetConfirmFormProps extends AuthFormBaseProps<StatusResponse> {
  /** The single-use token from the reset email, usually a URL query parameter. */
  readonly token: string;
  readonly labels?: Partial<PasswordResetConfirmLabels> | undefined;
}

/** Every visible string `MagicLinkForm` renders. */
export interface MagicLinkLabels extends Record<string, string> {
  readonly email: string;
  readonly submit: string;
  readonly submitPending: string;
  readonly success: string;
  readonly error: string;
}

/** @internal */
export const MAGIC_LINK_LABELS: MagicLinkLabels = {
  email: "Email",
  submit: "Email me a sign-in link",
  submitPending: "Sending…",
  success: "Check your inbox for your sign-in link.",
  error: "Could not send the sign-in link. Please try again.",
};

/** Props for `MagicLinkForm`. */
export interface MagicLinkFormProps extends AuthFormBaseProps<StatusResponse> {
  readonly labels?: Partial<MagicLinkLabels> | undefined;
}

/** Every visible string `EmailOtpForm` renders. */
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

/** @internal */
export const EMAIL_OTP_LABELS: EmailOtpLabels = {
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

/** Props for `EmailOtpForm`. */
export interface EmailOtpFormProps extends AuthFormBaseProps<AuthSuccess> {
  /**
   * What the emailed code is for. Defaults to `"sign-in"`, the only purpose
   * whose verification issues a session.
   */
  readonly purpose?: EmailOtpPurpose | undefined;
  readonly labels?: Partial<EmailOtpLabels> | undefined;
}
