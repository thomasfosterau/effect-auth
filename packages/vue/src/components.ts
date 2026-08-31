/**
 * The package's single-file form components.
 *
 * Each resolves its client from `provide`/`inject` (see `./context.ts`), takes
 * an optional `client` prop that overrides that injection, owns its own
 * pending/error state, and emits `success` / `error` instead of navigating. See
 * `./forms.ts` for the label and class types they accept.
 *
 * @module components
 */
export { default as EmailOtpForm } from "./EmailOtpForm.vue";
export { default as MagicLinkForm } from "./MagicLinkForm.vue";
export { default as PasswordResetConfirmForm } from "./PasswordResetConfirmForm.vue";
export { default as PasswordResetRequestForm } from "./PasswordResetRequestForm.vue";
export { default as SignInForm } from "./SignInForm.vue";
export { default as SignUpForm } from "./SignUpForm.vue";
