<!--
  Email (or username) + password sign-in.

  ```svelte
  <SignInForm onSuccess={() => goto("/app")} />
  ```
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { SIGN_IN_LABELS, type SignInFormProps } from "./props.ts";

  const {
    variant = "email",
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: SignInFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  const submission = createSubmission();

  const labels = $derived(mergeLabels(SIGN_IN_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("sign-in", className, classOverrides));
  const isUsername = $derived(variant === "username");

  let identifier = $state("");
  let password = $state("");

  const handleSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void submission.run(
      () =>
        isUsername
          ? client.signInUsername({ username: identifier, password })
          : client.signIn({ email: identifier, password }),
      { fallback: labels.error, onSuccess, onError },
    );
  };
</script>

<form
  class={classes.form}
  data-variant={variant}
  aria-busy={submission.pending ? "true" : undefined}
  onsubmit={handleSubmit}
>
  <Field
    {classes}
    id="{uid}-identifier"
    name={isUsername ? "username" : "email"}
    type={isUsername ? "text" : "email"}
    autocomplete={isUsername ? "username" : "email"}
    label={isUsername ? labels.username : labels.email}
    value={identifier}
    onValueChange={(next) => (identifier = next)}
    invalid={isInvalid(submission.failure, "identifier")}
    disabled={submission.pending}
  />
  <Field
    {classes}
    id="{uid}-password"
    name="password"
    type="password"
    autocomplete="current-password"
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
