<!--
  Passwordless sign-in by emailed link: requests one via `client.magicLink.send`.

  Redeeming the link is a page-load concern, not a form one: the landing route
  calls `client.magicLink.verify({ token })` with the token from the URL.
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { MAGIC_LINK_LABELS, type MagicLinkFormProps } from "./props.ts";

  const {
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: MagicLinkFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  const submission = createSubmission();

  const labels = $derived(mergeLabels(MAGIC_LINK_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("magic-link", className, classOverrides));

  let email = $state("");

  const handleSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void submission.run(() => client.magicLink.send({ email }), {
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
