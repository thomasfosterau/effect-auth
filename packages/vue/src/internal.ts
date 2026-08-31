/**
 * Bits the form components share. Not part of the package's public surface —
 * `index.ts` does not re-export this module.
 *
 * @module internal
 */
import type { AuthFormClasses } from "./forms.ts";

/** Every `ea-*` class hook a form renders, after overrides are applied. */
export interface ResolvedClasses {
  readonly form: string;
  readonly field: string;
  readonly label: string;
  readonly input: string;
  readonly submit: string;
  readonly error: string;
}

/** Default `ea-*` classes for one form, with the `classes` prop layered over. */
export const resolveClasses = (
  modifier: string,
  overrides: AuthFormClasses | undefined,
): ResolvedClasses => ({
  form: overrides?.form ?? `ea-form ${modifier}`,
  field: overrides?.field ?? "ea-field",
  label: overrides?.label ?? "ea-label",
  input: overrides?.input ?? "ea-input",
  submit: overrides?.submit ?? "ea-submit",
  error: overrides?.error ?? "ea-error",
});

/** English defaults with the `labels` prop layered over. */
export const resolveLabels = <T extends object>(
  defaults: T,
  overrides: Partial<T> | undefined,
): T => ({
  ...defaults,
  ...overrides,
});

/** Prefer the server's own message, falling back to the component's label. */
export const errorText = (cause: unknown, fallback: string): string => {
  if (cause instanceof Error && cause.message.trim() !== "") return cause.message;
  if (typeof cause === "string" && cause.trim() !== "") return cause;
  return fallback;
};
