<script setup lang="ts">
/**
 * Email + password sign-in, or username + password when `variant="username"`.
 *
 * Calls `client.signIn({ email, password })` — or
 * `client.signInUsername({ username, password })` for the username variant.
 */
import { computed, ref, useId } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./context.ts";
import { errorText, resolveClasses, resolveLabels } from "./internal.ts";
import {
  signInFormLabels,
  type AuthFormClasses,
  type AuthSuccess,
  type SignInFormLabels,
} from "./forms.ts";

const props = withDefaults(
  defineProps<{
    /** Overrides the injected client. Useful in tests and multi-tenant apps. */
    client?: AuthClient;
    /** Per-element class overrides. */
    classes?: AuthFormClasses;
    /** Partial overrides for the English defaults. */
    labels?: Partial<SignInFormLabels>;
    /** `"email"` (default) or `"username"`. */
    variant?: "email" | "username";
  }>(),
  { variant: "email" },
);

const emit = defineEmits<{
  /**
   * The `AuthSuccess` the client resolved. It may carry a pending second-factor
   * challenge rather than a session — continue it with `client.secondFactor`.
   */
  success: [result: AuthSuccess];
  /** The thrown cause, normally an `AuthClientError`. */
  error: [cause: unknown];
}>();

const client = useAuthClient(props.client);
const uid = useId();

const text = computed(() => resolveLabels(signInFormLabels, props.labels));
const classes = computed(() => resolveClasses("ea-sign-in", props.classes));
const isUsername = computed(() => props.variant === "username");

const identifier = ref("");
const password = ref("");
const pending = ref(false);
const message = ref<string | null>(null);
const failed = ref(false);

const onSubmit = async (): Promise<void> => {
  if (pending.value) return;
  pending.value = true;
  message.value = null;
  failed.value = false;
  try {
    const result = isUsername.value
      ? await client.signInUsername({ username: identifier.value, password: password.value })
      : await client.signIn({ email: identifier.value, password: password.value });
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
      <label :class="classes.label" :for="`${uid}-identifier`">
        {{ isUsername ? text.username : text.email }}
      </label>
      <input
        :id="`${uid}-identifier`"
        v-model="identifier"
        :class="classes.input"
        :name="isUsername ? 'username' : 'email'"
        :type="isUsername ? 'text' : 'email'"
        :autocomplete="isUsername ? 'username' : 'email'"
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
        autocomplete="current-password"
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
