<script setup lang="ts">
/**
 * Step two of a password reset: the new password, typed twice. The two entries
 * are compared client-side before anything is sent, so a mismatch never costs a
 * round trip.
 *
 * Calls `client.passwordResetConfirm({ token, newPassword })`.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  passwordResetConfirmFormLabels,
  type AuthFormClasses,
  type PasswordResetConfirmFormLabels,
  type StatusResponse,
} from "./forms.ts";

const props = defineProps<{
  /** The reset token from the emailed link. */
  token: string;
  /** Overrides the injected client. */
  client?: AuthClient;
  /** Per-element class overrides. */
  classes?: AuthFormClasses;
  /** Partial overrides for the English defaults. */
  labels?: Partial<PasswordResetConfirmFormLabels>;
}>();

const emit = defineEmits<{
  /** The `StatusResponse` the client resolved. */
  success: [result: StatusResponse];
  /**
   * The thrown cause: an `AuthClientError` from the server, or an `Error`
   * carrying the mismatch label when the two passwords differ.
   */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(passwordResetConfirmFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-password-reset-confirm", props.classes));

const password = ref("");
const confirmation = ref("");
const pending = ref(false);
const message = ref<string | null>(null);
const failed = ref(false);
const mismatched = ref(false);

const onSubmit = async (): Promise<void> => {
  if (pending.value) return;
  message.value = null;
  failed.value = false;
  mismatched.value = false;

  if (password.value !== confirmation.value) {
    mismatched.value = true;
    message.value = text.value.mismatch;
    emit("error", new Error(text.value.mismatch));
    return;
  }

  pending.value = true;
  try {
    const result = await client.passwordResetConfirm({
      token: props.token,
      newPassword: password.value,
    });
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
      <label :class="classes.label" :for="`${uid}-password`">{{ text.password }}</label>
      <input
        :id="`${uid}-password`"
        v-model="password"
        :class="classes.input"
        name="newPassword"
        type="password"
        autocomplete="new-password"
        :aria-invalid="failed ? 'true' : undefined"
        required
      />
    </div>
    <div :class="classes.field">
      <label :class="classes.label" :for="`${uid}-confirm`">{{ text.confirm }}</label>
      <input
        :id="`${uid}-confirm`"
        v-model="confirmation"
        :class="classes.input"
        name="confirmPassword"
        type="password"
        autocomplete="new-password"
        :aria-invalid="failed || mismatched ? 'true' : undefined"
        required
      />
    </div>
    <p v-if="message !== null" :class="classes.error" role="alert">{{ message }}</p>
    <button :class="classes.submit" type="submit" :disabled="pending">
      {{ pending ? text.pending : text.submit }}
    </button>
  </form>
</template>
