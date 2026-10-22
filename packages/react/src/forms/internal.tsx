/**
 * Shared internals for the bundled form components: class-name resolution,
 * label merging, submit/pending/error state and the field primitive.
 *
 * Nothing here is exported from the package root except the types the form
 * props reference ({@link AuthFormClasses}, {@link AuthFormBaseProps}).
 *
 * @module forms/internal
 */
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

/**
 * The result an authenticating call resolves to. Derived from the client rather
 * than imported from `@thomasfosterau/effect-auth` so this package needs no
 * dependency on the server half just to name its own callback types.
 */
export type AuthSuccess = Awaited<ReturnType<AuthClient["signIn"]>>;

/** The `{ status }` acknowledgement a "we sent you something" call resolves to. */
export type StatusResponse = Awaited<ReturnType<AuthClient["passwordResetRequest"]>>;

/**
 * Per-element class overrides. Each entry *replaces* the built-in `ea-*` class
 * for that element, so a design system can opt out of the defaults entirely
 * while keeping the markup.
 */
export interface AuthFormClasses {
  /** The `<form>` root. Replaces both `ea-form` and the per-form modifier. */
  readonly form?: string | undefined;
  /** The wrapper around one label + input pair. Default `ea-field`. */
  readonly field?: string | undefined;
  /** Every `<label>`. Default `ea-label`. */
  readonly label?: string | undefined;
  /** Every `<input>`. Default `ea-input`. */
  readonly input?: string | undefined;
  /** The submit `<button>`. Default `ea-submit`. */
  readonly submit?: string | undefined;
  /** The `role="alert"` error element. Default `ea-error`. */
  readonly error?: string | undefined;
  /** The `role="status"` success element. Default `ea-status`. */
  readonly status?: string | undefined;
  /** A secondary `type="button"` control, e.g. the OTP form's "start over". Default `ea-restart`. */
  readonly restart?: string | undefined;
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
  /** Client to use, overriding the one from `<AuthClientProvider>`. */
  readonly client?: AuthClient | undefined;
  /** Called with the client's result after a successful submit. */
  readonly onSuccess?: ((result: TResult) => void) | undefined;
  /** Called with the thrown value after a failed submit. */
  readonly onError?: ((error: unknown) => void) | undefined;
  /** Appended to the `<form>` root's class list. */
  readonly className?: string | undefined;
  /** Per-element class overrides. */
  readonly classes?: AuthFormClasses | undefined;
}

const joinClasses = (...parts: ReadonlyArray<string | undefined>): string =>
  parts.filter((part): part is string => part !== undefined && part.length > 0).join(" ");

/**
 * Resolve the class name for every element of a form.
 *
 * @param modifier - Per-form modifier, e.g. `"sign-in"` for `ea-sign-in`.
 * @internal
 */
export const resolveClasses = (
  modifier: string,
  className: string | undefined,
  classes: AuthFormClasses | undefined,
): ResolvedClasses => ({
  form: joinClasses(classes?.form ?? `ea-form ea-${modifier}`, className),
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
  overrides: Partial<T> | undefined,
): T => {
  if (overrides === undefined) return defaults;
  const merged = { ...defaults };
  // SAFETY: `overrides` is a `Partial<T>`, so its own keys are label keys of
  // `T`; whatever is copied is a defined `string`, which every key of `T` holds.
  for (const key of Object.keys(overrides) as Array<keyof T>) {
    const value = overrides[key];
    if (value !== undefined) merged[key] = value;
  }
  return merged;
};

/** A rendered failure: the message, plus the field it is attributable to. */
export interface FormFailure {
  readonly message: string;
  /**
   * The field the failure belongs to, or `null` when it came from the server —
   * which reports "these credentials are wrong", not "this input is wrong".
   */
  readonly field: string | null;
}

/** @internal */
export interface SubmitHandlers<T> {
  /** Message shown when the thrown value carries none. */
  readonly fallback: string;
  readonly onSuccess?: ((result: T) => void) | undefined;
  readonly onError?: ((error: unknown) => void) | undefined;
}

/** One form's submit lifecycle. @internal */
export interface Submission {
  readonly pending: boolean;
  readonly failure: FormFailure | null;
  /** `true` once a submit has resolved and nothing has been re-submitted. */
  readonly succeeded: boolean;
  /** Record a client-side validation failure against `field`. */
  readonly fail: (message: string, field: string) => void;
  /** Run `work`, tracking pending/error state and firing the callbacks. */
  readonly run: <T>(work: () => Promise<T>, handlers: SubmitHandlers<T>) => Promise<void>;
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
export const isInvalid = (failure: FormFailure | null, field: string): boolean =>
  failure !== null && (failure.field === null || failure.field === field);

/** Own the submit/pending/error state of one form (or one step of one). @internal */
export const useSubmission = (): Submission => {
  const [pending, setPending] = useState(false);
  const [failure, setFailure] = useState<FormFailure | null>(null);
  const [succeeded, setSucceeded] = useState(false);
  // Guards against a second submit landing between the click and the state
  // update, and against setting state on an unmounted form.
  const busy = useRef(false);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  return {
    pending,
    failure,
    succeeded,
    fail: (message, field) => {
      setSucceeded(false);
      setFailure({ message, field });
    },
    run: async <T,>(work: () => Promise<T>, handlers: SubmitHandlers<T>): Promise<void> => {
      if (busy.current) return;
      busy.current = true;
      setPending(true);
      setFailure(null);
      setSucceeded(false);
      try {
        const result = await work();
        busy.current = false;
        if (alive.current) {
          setPending(false);
          setSucceeded(true);
        }
        handlers.onSuccess?.(result);
      } catch (cause) {
        busy.current = false;
        if (alive.current) {
          setPending(false);
          setFailure({ message: messageOf(cause, handlers.fallback), field: null });
        }
        handlers.onError?.(cause);
      }
    },
  };
};

/** @internal */
export interface FieldProps {
  readonly id: string;
  readonly name: string;
  readonly type: "email" | "password" | "text";
  readonly autoComplete: string;
  readonly label: string;
  readonly value: string;
  readonly onValueChange: (value: string) => void;
  readonly invalid: boolean;
  readonly disabled: boolean;
  readonly classes: ResolvedClasses;
  readonly inputMode?: "numeric" | undefined;
  /** Defaults to `true`; pass `false` for genuinely optional inputs. */
  readonly required?: boolean | undefined;
}

/** One labelled input. @internal */
export const Field = ({
  id,
  name,
  type,
  autoComplete,
  label,
  value,
  onValueChange,
  invalid,
  disabled,
  classes,
  inputMode,
  required = true,
}: FieldProps): ReactNode => (
  <div className={classes.field}>
    <label className={classes.label} htmlFor={id}>
      {label}
    </label>
    <input
      aria-invalid={invalid || undefined}
      autoComplete={autoComplete}
      className={classes.input}
      disabled={disabled}
      id={id}
      inputMode={inputMode}
      name={name}
      onChange={(event) => onValueChange(event.target.value)}
      required={required}
      type={type}
      value={value}
    />
  </div>
);

/** @internal */
export interface FormMessagesProps {
  readonly failure: FormFailure | null;
  readonly succeeded: boolean;
  readonly successMessage?: string | undefined;
  readonly classes: ResolvedClasses;
}

/** The `role="alert"` failure and optional `role="status"` success elements. @internal */
export const FormMessages = ({
  failure,
  succeeded,
  successMessage,
  classes,
}: FormMessagesProps): ReactNode => (
  <>
    {failure === null ? null : (
      <p className={classes.error} role="alert">
        {failure.message}
      </p>
    )}
    {succeeded && successMessage !== undefined ? (
      <p className={classes.status} role="status">
        {successMessage}
      </p>
    ) : null}
  </>
);

/** @internal */
export interface SubmitButtonProps {
  readonly pending: boolean;
  readonly label: string;
  readonly pendingLabel: string;
  readonly classes: ResolvedClasses;
}

/** The submit button, disabled and relabelled while the form is pending. @internal */
export const SubmitButton = ({
  pending,
  label,
  pendingLabel,
  classes,
}: SubmitButtonProps): ReactNode => (
  <button className={classes.submit} disabled={pending} type="submit">
    {pending ? pendingLabel : label}
  </button>
);
