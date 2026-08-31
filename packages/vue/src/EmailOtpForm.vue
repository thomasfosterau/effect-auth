<script setup lang="ts">
/**
 * Both halves of an email one-time-passcode sign-in in one component: the email
 * step swaps itself for the code step once the code has been sent.
 *
 * Calls `client.emailOtp.send({ email, purpose })` and then
 * `client.emailOtp.signIn({ email, otp })`.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  emailOtpFormLabels,
  type AuthFormClasses,
  type AuthSuccess,
  type EmailOtpFormLabels,
  type EmailOtpPurpose,
} from "./forms.ts";

const props = withDefaults(
  defineProps<{
    /** Overrides the injected client. */
    client?: AuthClient;
    /** Per-element class overrides. */
    classes?: AuthFormClasses;
    /** Partial overrides for the English defaults. */
    labels?: Partial<EmailOtpFormLabels>;
    /** Why the code is being sent. Defaults to `"sign-in"`. */
    purpose?: EmailOtpPurpose;
  }>(),
  { purpose: "sign-in" },
);

const emit = defineEmits<{
  /**
   * The `AuthSuccess` from the verify step. The request step emits nothing on
   * success — it advances the form to the code field.
   */
  success: [result: AuthSuccess];
  /** The thrown cause from either step, normally an `AuthClientError`. */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(emailOtpFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-email-otp", props.classes));

const email = ref("");
const code = ref("");
const verifying = ref(false);
const pending = ref(false);
const message = ref<string | null>(null);
const failed = ref(false);

const onSubmit = async (): Promise<void> => {
  if (pending.value) return;
  const isVerifyStep = verifying.value;
  pending.value = true;
  message.value = null;
  failed.value = false;
  try {
    if (isVerifyStep) {
      const result = await client.emailOtp.signIn({ email: email.value, otp: code.value });
      emit("success", result);
    } else {
      await client.emailOtp.send({ email: email.value, purpose: props.purpose });
      verifying.value = true;
    }
  } catch (cause) {
    failed.value = true;
    message.value = errorText(
      cause,
      isVerifyStep ? text.value.verifyError : text.value.requestError,
    );
    emit("error", cause);
  } finally {
    pending.value = false;
  }
};
</script>

<template>
  <form :class="classes.form" :aria-busy="pending ? 'true' : 'false'" @submit.prevent="onSubmit">
    <div v-if="verifying" :class="classes.field">
      <label :class="classes.label" :for="`${uid}-code`">{{ text.code }}</label>
      <input
        :id="`${uid}-code`"
        v-model="code"
        :class="classes.input"
        name="otp"
        type="text"
        autocomplete="one-time-code"
        inputmode="numeric"
        :aria-invalid="failed ? 'true' : undefined"
        required
      />
    </div>
    <div v-else :class="classes.field">
      <label :class="classes.label" :for="`${uid}-email`">{{ text.email }}</label>
      <input
        :id="`${uid}-email`"
        v-model="email"
        :class="classes.input"
        name="email"
        type="email"
        autocomplete="email"
        :aria-invalid="failed ? 'true' : undefined"
        required
      />
    </div>
    <p v-if="message !== null" :class="classes.error" role="alert">{{ message }}</p>
    <button :class="classes.submit" type="submit" :disabled="pending">
      <template v-if="verifying">{{ pending ? text.verifyPending : text.verify }}</template>
      <template v-else>{{ pending ? text.requestPending : text.request }}</template>
    </button>
  </form>
</template>
