<!--
  Both halves of an email one-time-code sign-in in one component: it calls
  `client.emailOtp.send({ email, purpose })`, swaps itself for a code field, then
  calls `client.emailOtp.signIn({ email, otp })`.

  `onSuccess` fires only for the second step — the step that yields a session.
  The rendered `<form>` carries `data-step="request"` or `data-step="verify"` so
  a stylesheet can tell the two apart.
-->
<script lang="ts">
  import { resolveAuthClient } from "../context.ts";
  import Field from "./Field.svelte";
  import FormMessages from "./FormMessages.svelte";
  import SubmitButton from "./SubmitButton.svelte";
  import { isInvalid, mergeLabels, resolveClasses } from "./internal.ts";
  import { createSubmission } from "./submission.svelte.ts";
  import { EMAIL_OTP_LABELS, type EmailOtpFormProps } from "./props.ts";

  const {
    purpose = "sign-in",
    client: clientProp = undefined,
    onSuccess = undefined,
    onError = undefined,
    class: className = undefined,
    classes: classOverrides = undefined,
    labels: labelOverrides = undefined,
  }: EmailOtpFormProps = $props();

  const client = resolveAuthClient(() => clientProp);
  const uid = $props.id();
  // A submission per step, so the request step's error does not linger over the
  // verify step (and vice versa).
  const request = createSubmission();
  const verify = createSubmission();

  const labels = $derived(mergeLabels(EMAIL_OTP_LABELS, labelOverrides));
  const classes = $derived(resolveClasses("email-otp", className, classOverrides));

  let email = $state("");
  let otp = $state("");
  let sent = $state(false);

  const handleRequest = (event: SubmitEvent): void => {
    event.preventDefault();
    void request.run(() => client.emailOtp.send({ email, purpose }), {
      fallback: labels.sendError,
      onSuccess: () => {
        sent = true;
      },
      onError,
    });
  };

  const handleVerify = (event: SubmitEvent): void => {
    event.preventDefault();
    void verify.run(() => client.emailOtp.signIn({ email, otp }), {
      fallback: labels.verifyError,
      onSuccess,
      onError,
    });
  };

  const restart = (): void => {
    sent = false;
    otp = "";
  };
</script>

{#if sent}
  <form
    class={classes.form}
    data-step="verify"
    aria-busy={verify.pending ? "true" : undefined}
    onsubmit={handleVerify}
  >
    <p class={classes.status} role="status">{labels.sent}</p>
    <Field
      {classes}
      id="{uid}-otp"
      name="otp"
      type="text"
      autocomplete="one-time-code"
      inputmode="numeric"
      label={labels.code}
      value={otp}
      onValueChange={(next) => (otp = next)}
      invalid={isInvalid(verify.failure, "otp")}
      disabled={verify.pending}
    />
    <FormMessages {classes} failure={verify.failure} />
    <SubmitButton
      {classes}
      pending={verify.pending}
      label={labels.verifySubmit}
      pendingLabel={labels.verifyPending}
    />
    <button class={classes.restart} type="button" disabled={verify.pending} onclick={restart}>
      {labels.restart}
    </button>
  </form>
{:else}
  <form
    class={classes.form}
    data-step="request"
    aria-busy={request.pending ? "true" : undefined}
    onsubmit={handleRequest}
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
      invalid={isInvalid(request.failure, "email")}
      disabled={request.pending}
    />
    <FormMessages {classes} failure={request.failure} />
    <SubmitButton
      {classes}
      pending={request.pending}
      label={labels.sendSubmit}
      pendingLabel={labels.sendPending}
    />
  </form>
{/if}
