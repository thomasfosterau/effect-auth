<script setup lang="ts">
/**
 * Step one of a password reset: the email address to send the reset link to.
 *
 * Calls `client.passwordResetRequest({ email })`. The server answers the same
 * way whether or not the address exists, so the form never reveals whether an
 * account is registered.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  passwordResetRequestFormLabels,
  type AuthFormClasses,
  type PasswordResetRequestFormLabels,
  type StatusResponse,
} from "./forms.ts";

const props = defineProps<{
  /** Overrides the injected client. */
  client?: AuthClient;
  /** Per-element class overrides. */
  classes?: AuthFormClasses;
  /** Partial overrides for the English defaults. */
  labels?: Partial<PasswordResetRequestFormLabels>;
}>();

const emit = defineEmits<{
  /** The `StatusResponse` the client resolved. */
  success: [result: StatusResponse];
  /** The thrown cause, normally an `AuthClientError`. */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(passwordResetRequestFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-password-reset-request", props.classes));

const email = ref("");
const pending = ref(false);
const message = ref<string | null>(null);
const failed = ref(false);

const onSubmit = async (): Promise<void> => {
  if (pending.value) return;
  pending.value = true;
  message.value = null;
  failed.value = false;
  try {
    const result = await client.passwordResetRequest({ email: email.value });
    emit("success", result);
  } catch (cause) {
    failed.value = true;
    message.value = errorText(cause, text.value.error);
    emit("error", cause);
  } finally {
    pending.value = false;
  }
};
</script>

<template>
  <form :class="classes.form" :aria-busy="pending ? 'true' : 'false'" @submit.prevent="onSubmit">
    <div :class="classes.field">
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
      {{ pending ? text.pending : text.submit }}
    </button>
  </form>
</template>
