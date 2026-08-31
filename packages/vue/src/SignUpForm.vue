<script setup lang="ts">
/**
 * Email + password sign-up, with an optional name field (`showName`) — the
 * client's `signUp` payload takes an optional `name`, which is left out of the
 * request when the field is blank.
 *
 * Calls `client.signUp({ email, password, name? })`.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  signUpFormLabels,
  type AuthFormClasses,
  type AuthSuccess,
  type SignUpFormLabels,
} from "./forms.ts";

const props = withDefaults(
  defineProps<{
    /** Overrides the injected client. */
    client?: AuthClient;
    /** Per-element class overrides. */
    classes?: AuthFormClasses;
    /** Partial overrides for the English defaults. */
    labels?: Partial<SignUpFormLabels>;
    /** Render the optional name field. Defaults to `false`. */
    showName?: boolean;
  }>(),
  { showName: false },
);

const emit = defineEmits<{
  /**
   * The `AuthSuccess` the client resolved. Its `needsEmailVerification` flag
   * says whether a session was created or a verification email was sent.
   */
  success: [result: AuthSuccess];
  /** The thrown cause, normally an `AuthClientError`. */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(signUpFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-sign-up", props.classes));

const name = ref("");
const email = ref("");
const password = ref("");
const pending = ref(false);
const message = ref<string | null>(null);
const failed = ref(false);

const onSubmit = async (): Promise<void> => {
  if (pending.value) return;
  pending.value = true;
  message.value = null;
  failed.value = false;
  const trimmed = name.value.trim();
  try {
    const result = await client.signUp({
      email: email.value,
      password: password.value,
      ...(props.showName && trimmed !== "" ? { name: trimmed } : {}),
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
    <div v-if="showName" :class="classes.field">
      <label :class="classes.label" :for="`${uid}-name`">{{ text.name }}</label>
      <input
        :id="`${uid}-name`"
        v-model="name"
        :class="classes.input"
        name="name"
        type="text"
        autocomplete="name"
      />
    </div>
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
    <div :class="classes.field">
      <label :class="classes.label" :for="`${uid}-password`">{{ text.password }}</label>
      <input
        :id="`${uid}-password`"
        v-model="password"
        :class="classes.input"
        name="password"
        type="password"
        autocomplete="new-password"
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
