<script setup lang="ts">
/**
 * Request a sign-in link by email.
 *
 * Calls `client.magicLink.send({ email })`. Redeeming the emailed token stays
 * the app's job — call `client.magicLink.verify({ token })` on the landing
 * route.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  magicLinkFormLabels,
  type AuthFormClasses,
  type MagicLinkFormLabels,
  type StatusResponse,
} from "./forms.ts";

const props = defineProps<{
  /** Overrides the injected client. */
  client?: AuthClient;
  /** Per-element class overrides. */
  classes?: AuthFormClasses;
  /** Partial overrides for the English defaults. */
  labels?: Partial<MagicLinkFormLabels>;
}>();

const emit = defineEmits<{
  /** The `StatusResponse` the client resolved. */
  success: [result: StatusResponse];
  /**
   * The thrown cause, normally an `AuthClientError` — a 404 means the server
   * has no magic-link plugin configured.
   */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(magicLinkFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-magic-link", props.classes));

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
    const result = await client.magicLink.send({ email: email.value });
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
