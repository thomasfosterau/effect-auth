<!--
  Step two of a password reset: redeem the emailed token for a new password via
  `client.passwordResetConfirm`.

  The confirmation field is checked in the browser — a mismatch never reaches
  the server, and marks only the confirmation input `aria-invalid`.

  ```svelte
  <PasswordResetConfirmForm token={page.url.searchParams.get("token") ?? ""} />
  ```
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { PASSWORD_RESET_CONFIRM_LABELS, type PasswordResetConfirmFormProps } from "./props.ts";

  const {
    token,
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: PasswordResetConfirmFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  const submission = createSubmission();

  const labels = $derived(mergeLabels(PASSWORD_RESET_CONFIRM_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("password-reset-confirm", className, classOverrides));

  let newPassword = $state("");
  let confirmation = $state("");

  const handleSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (newPassword !== confirmation) {
      submission.fail(labels.mismatch, "confirmPassword");
      return;
    }
    void submission.run(() => client.passwordResetConfirm({ token, newPassword }), {
      fallback: labels.error,
      onSuccess,
      onError,
    });
  };
</script>

<form
  class={classes.form}
  aria-busy={submission.pending ? "true" : undefined}
  onsubmit={handleSubmit}
>
  <Field
    {classes}
    id="{uid}-password"
    name="newPassword"
    type="password"
    autocomplete="new-password"
    label={labels.password}
    value={newPassword}
    onValueChange={(next) => (newPassword = next)}
    invalid={isInvalid(submission.failure, "password")}
    disabled={submission.pending}
  />
  <Field
    {classes}
    id="{uid}-confirm-password"
    name="confirmPassword"
    type="password"
    autocomplete="new-password"
    label={labels.confirmPassword}
    value={confirmation}
    onValueChange={(next) => (confirmation = next)}
    invalid={isInvalid(submission.failure, "confirmPassword")}
    disabled={submission.pending}
  />
  <FormMessages
    {classes}
    failure={submission.failure}
    succeeded={submission.succeeded}
    successMessage={labels.success}
  />
  <SubmitButton
    {classes}
    pending={submission.pending}
    label={labels.submit}
    pendingLabel={labels.submitPending}
  />
</form>
