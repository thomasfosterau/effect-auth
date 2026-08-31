<!--
  Step one of a password reset: ask for the email to send the link to, via
  `client.passwordResetRequest`.

  The success copy is deliberately non-committal: the server answers the same
  way for a registered and an unregistered address, and the form should not leak
  the difference.
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { PASSWORD_RESET_REQUEST_LABELS, type PasswordResetRequestFormProps } from "./props.ts";

  const {
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: PasswordResetRequestFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  const submission = createSubmission();

  const labels = $derived(mergeLabels(PASSWORD_RESET_REQUEST_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("password-reset-request", className, classOverrides));

  let email = $state("");

  const handleSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void submission.run(() => client.passwordResetRequest({ email }), {
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
    id="{uid}-email"
    name="email"
    type="email"
    autocomplete="email"
    label={labels.email}
    value={email}
    onValueChange={(next) => (email = next)}
    invalid={isInvalid(submission.failure, "email")}
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
