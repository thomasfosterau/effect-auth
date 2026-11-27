/**
 * Shared internals for the bundled form components: class-name resolution,
 * label merging and the shape of a rendered failure.
 *
 * The rune-backed submit state lives next door in `submission.svelte.ts`; only
 * the framework-free helpers are here so they can be unit tested without a
 * component around them.
 *
 * @module forms/internal
 */
import type { AuthClient } from "@thomasfosterau/effect-auth/client";
import * as Option from "effect/Option";

/**
 * The result an authenticating call resolves to. Derived from the client rather
 * than imported from `@thomasfosterau/effect-auth` so this package needs no
 * dependency on the server half just to name its own callback types.
 */
export type AuthSuccess = Awaited<ReturnType<AuthClient["signIn"]>>;

/**
 * The second-factor challenge a sign-in answers with (`202`) when the account
 * has multi-factor on: no session yet, only a token to redeem with
 * `client.multiFactor.continueChallenge`.
 */
export type SecondFactorChallenge = NonNullable<AuthSuccess["secondFactor"]>;

/**
 * The success handler of a session-yielding form: `onSecondFactor` for a
 * second-factor challenge, `onSuccess` otherwise, so a documented
 * `onSuccess={() => goto("/app")}` never navigates without a session.
 */
export const routeSignInResult =
  (
    onSuccess?: (result: AuthSuccess) => void,
    onSecondFactor?: (challenge: SecondFactorChallenge) => void,
  ) =>
  (result: AuthSuccess): void => {
    if (result.secondFactor !== undefined) onSecondFactor?.(result.secondFactor);
    else onSuccess?.(result);
  };

/** The `{ status }` acknowledgement a "we sent you something" call resolves to. */
export type StatusResponse = Awaited<ReturnType<AuthClient["passwordResetRequest"]>>;

/** The purposes an email OTP can be requested for. */
export type EmailOtpPurpose = Parameters<AuthClient["emailOtp"]["send"]>[0]["purpose"];

/**
 * Per-element class overrides. Each entry *replaces* the built-in `ea-*` class
 * for that element, so a design system can opt out of the defaults entirely
 * while keeping the markup.
 */
export interface AuthFormClasses {
  /** The `<form>` root. Replaces both `ea-form` and the per-form modifier. */
  readonly form?: string;
  /** The wrapper around one label + input pair. Default `ea-field`. */
  readonly field?: string;
  /** Every `<label>`. Default `ea-label`. */
  readonly label?: string;
  /** Every `<input>`. Default `ea-input`. */
  readonly input?: string;
  /** The submit `<button>`. Default `ea-submit`. */
  readonly submit?: string;
  /** The `role="alert"` error element. Default `ea-error`. */
  readonly error?: string;
  /** The `role="status"` success element. Default `ea-status`. */
  readonly status?: string;
  /** A secondary `type="button"` control, e.g. the OTP form's "start over". Default `ea-restart`. */
  readonly restart?: string;
}

/** {@link AuthFormClasses} with every slot filled in. @internal */
export interface ResolvedClasses {
  readonly form: string;
  readonly field: string;
  readonly label: string;
  readonly input: string;
  readonly submit: string;
  readonly error: string;
  readonly status: string;
  readonly restart: string;
}

/** Props every bundled form accepts. `TResult` is what `onSuccess` receives. */
export interface AuthFormBaseProps<TResult> {
  /** Client to use, overriding the one `setAuthClient` put in context. */
  readonly client?: AuthClient;
  /** Called with the client's result after a successful submit. */
  readonly onSuccess?: (result: TResult) => void;
  /** Called with the thrown value after a failed submit. */
  readonly onError?: (error: unknown) => void;
  /** Appended to the `<form>` root's class list. */
  readonly class?: string;
  /** Per-element class overrides. */
  readonly classes?: AuthFormClasses;
}

const joinClasses = (...parts: ReadonlyArray<string>): string =>
  parts.filter((part) => part.length > 0).join(" ");

/**
 * Resolve the class name for every element of a form.
 *
 * @param modifier - Per-form modifier, e.g. `"sign-in"` for `ea-sign-in`.
 * @internal
 */
export const resolveClasses = (
  modifier: string,
  className?: string,
  classes?: AuthFormClasses,
): ResolvedClasses => ({
  form: joinClasses(classes?.form ?? `ea-form ea-${modifier}`, className ?? ""),
  field: classes?.field ?? "ea-field",
  label: classes?.label ?? "ea-label",
  input: classes?.input ?? "ea-input",
  submit: classes?.submit ?? "ea-submit",
  error: classes?.error ?? "ea-error",
  status: classes?.status ?? "ea-status",
  restart: classes?.restart ?? "ea-restart",
});

/**
 * Overlay `overrides` onto `defaults`, ignoring keys explicitly set to
 * `undefined` so `labels={{ submit: maybeString }}` degrades to the default
 * rather than rendering an empty button.
 *
 * @internal
 */
export const mergeLabels = <T extends Record<string, string>>(
  defaults: T,
  overrides?: Partial<T>,
): T => {
  if (overrides === undefined) return defaults;
  const merged = { ...defaults };
  for (const key in overrides) {
    const value = overrides[key];
    if (Object.hasOwn(overrides, key) && value !== undefined) merged[key] = value;
  }
  return merged;
};

/** A rendered failure: the message, plus the field it is attributable to. */
export interface FormFailure {
  readonly message: string;
  /**
   * The field the failure belongs to, or `None` when it came from the server —
   * which reports "these credentials are wrong", not "this input is wrong".
   */
  readonly field: Option.Option<string>;
}

/** The message of a thrown value, or `fallback` when it has none. @internal */
export const messageOf = (cause: unknown, fallback: string): string =>
  cause instanceof Error && cause.message.length > 0 ? cause.message : fallback;

/**
 * Whether `field` should be marked `aria-invalid`: either the failure names it,
 * or the failure names no field at all and the whole submitted set is suspect.
 *
 * @internal
 */
export const isInvalid = (failure: Option.Option<FormFailure>, field: string): boolean =>
  Option.exists(failure, (found) =>
    Option.match(found.field, { onNone: () => true, onSome: (named) => named === field }),
  );

/**
 * The `captchaToken` member of a send's payload: present only when the form
 * was given a `captchaToken` prop and it has a token now.
 *
 * @internal
 */
export const captchaField = (
  read?: () => Option.Option<string>,
): { readonly captchaToken?: string } =>
  read === undefined
    ? {}
    : Option.match(read(), { onNone: () => ({}), onSome: (captchaToken) => ({ captchaToken }) });
