<!--
  Email + password registration, with an optional display-name field.

  ```svelte
  <SignUpForm showName={false} onSuccess={({ needsEmailVerification }) => ...} />
  ```
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { SIGN_UP_LABELS, type SignUpFormProps } from "./props.ts";

  const {
    showName = true,
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: SignUpFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  const submission = createSubmission();

  const labels = $derived(mergeLabels(SIGN_UP_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("sign-up", className, classOverrides));

  let email = $state("");
  let password = $state("");
  let name = $state("");

  const handleSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    const trimmedName = name.trim();
    // `name` is optional on the wire; spread it in only when there is one.
    const payload =
      showName && trimmedName.length > 0 ? { email, password, name: trimmedName } : { email, password };
    void submission.run(() => client.signUp(payload), {
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
  {#if showName}
    <Field
      {classes}
      id="{uid}-name"
      name="name"
      type="text"
      autocomplete="name"
      label={labels.name}
      value={name}
      onValueChange={(next) => (name = next)}
      invalid={isInvalid(submission.failure, "name")}
      disabled={submission.pending}
      required={false}
    />
  {/if}
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
  <Field
    {classes}
    id="{uid}-password"
    name="password"
    type="password"
    autocomplete="new-password"
    label={labels.password}
    value={password}
    onValueChange={(next) => (password = next)}
    invalid={isInvalid(submission.failure, "password")}
    disabled={submission.pending}
  />
  <FormMessages {classes} failure={submission.failure} />
  <SubmitButton
    {classes}
    pending={submission.pending}
    label={labels.submit}
    pendingLabel={labels.submitPending}
  />
</form>
