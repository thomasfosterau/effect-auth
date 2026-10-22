# @thomasfosterau/effect-auth-vue

Vue bindings for [`@thomasfosterau/effect-auth-client`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/client): composables over the client's observable session store, plus headless single-file form components for the flows every app has to build anyway.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-vue @thomasfosterau/effect-auth-client effect
```

`vue` (>= 3) is a peer dependency.

## Composables

```vue
<script setup>
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { useSession, useListSessions } from "@thomasfosterau/effect-auth-vue";

const client = createAuthClient({ baseUrl: "/api/auth" });
const session = useSession(client);
const { data: sessions, refetch } = useListSessions(client);
</script>

<template>
  <span v-if="session.data">
    {{ session.data.user.email }} — {{ sessions?.length ?? 0 }} active sessions
    <button @click="refetch">Refresh</button>
  </span>
</template>
```

Both composables release their subscription with the current effect scope. Called outside one (plain scripts, tests) they warn and hand back a `dispose()` to call yourself.

## Form components

Install the client once at the app root and every form below finds it by injection.

```ts
import { createApp } from "vue";
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { authClientPlugin } from "@thomasfosterau/effect-auth-vue";
import App from "./App.vue";

createApp(App)
  .use(authClientPlugin, { client: createAuthClient({ baseUrl: "/api/auth" }) })
  .mount("#app");
```

`provideAuthClient(client)` inside a parent component's `setup()` does the same thing for one subtree, and `useAuthClient()` returns the client anywhere below either of them. A component that can find no client throws on mount with a message naming all three ways to supply one.

| Component                  | Client method                                                 | `success` payload |
| -------------------------- | ------------------------------------------------------------- | ----------------- |
| `SignInForm`               | `signIn` — or `signInUsername` with `variant="username"`      | `AuthSuccess`     |
| `SignUpForm`               | `signUp` — sends `name` too when `showName` is set and filled | `AuthSuccess`     |
| `PasswordResetRequestForm` | `passwordResetRequest`                                        | `StatusResponse`  |
| `PasswordResetConfirmForm` | `passwordResetConfirm`, with the `token` prop                 | `StatusResponse`  |
| `MagicLinkForm`            | `magicLink.send`                                              | `StatusResponse`  |
| `EmailOtpForm`             | `emailOtp.send`, then `emailOtp.signIn`                       | `AuthSuccess`     |

Every component owns its own pending and error state, disables its submit button while a request is in flight, and emits `success` with whatever the client resolved or `error` with whatever it threw (normally an `AuthClientError` carrying the server's `status` and message).

None of them navigate — where to go next is the app's decision, so make it in the `success` handler.

```vue
<script setup lang="ts">
import { useRouter } from "vue-router";
import { SignInForm, type AuthSuccess } from "@thomasfosterau/effect-auth-vue";

const router = useRouter();
const onSuccess = (result: AuthSuccess) => {
  if (result.secondFactor) return router.push("/sign-in/verify");
  return router.push("/");
};
</script>

<template>
  <SignInForm class="sign-in" @success="onSuccess" @error="(cause) => console.warn(cause)" />
</template>
```

`EmailOtpForm` is both halves of a one-time-passcode sign-in in one component: it renders the email field, and once the code has been sent it swaps itself for the code field. Only the second step emits `success`.

`PasswordResetConfirmForm` compares its two password fields before it calls the client, so a typo emits `error` with a plain `Error` and never costs a round trip.

### Styling

The markup is semantic and carries no styles at all — just stable class hooks you write CSS against.

```css
.ea-form {
  display: grid;
  gap: 1rem;
  max-width: 22rem;
}
.ea-field {
  display: grid;
  gap: 0.25rem;
}
.ea-label {
  font-size: 0.875rem;
  font-weight: 600;
}
.ea-input {
  padding: 0.5rem;
  border: 1px solid #cbd5e1;
  border-radius: 0.375rem;
}
.ea-input[aria-invalid="true"] {
  border-color: #dc2626;
}
.ea-error {
  margin: 0;
  color: #dc2626;
  font-size: 0.875rem;
}
.ea-submit {
  padding: 0.5rem 1rem;
  border-radius: 0.375rem;
}
.ea-form[aria-busy="true"] .ea-submit {
  opacity: 0.6;
  cursor: progress;
}
.ea-sign-in .ea-submit {
  background: #1d4ed8;
  color: white;
}
```

Each form's root also carries a modifier — `ea-sign-in`, `ea-sign-up`, `ea-password-reset-request`, `ea-password-reset-confirm`, `ea-magic-link`, `ea-email-otp` — so one stylesheet can treat them differently.

A `class` on the component merges onto the root `<form>` as usual, and the `classes` prop replaces individual hooks when you would rather bring your own names.

```vue
<SignUpForm
  show-name
  :classes="{ form: 'card stack', input: 'input input-bordered', submit: 'btn btn-primary' }"
/>
```

### Text

Every visible string has an English default and is overridable per component through `labels`, which is merged over the defaults, so partial overrides are fine.

```vue
<SignInForm :labels="{ email: 'Courriel', password: 'Mot de passe', submit: 'Se connecter' }" />
```

The exported defaults (`signInFormLabels`, `signUpFormLabels`, …) and their types (`SignInFormLabels`, …) are there to build translations against.

When the server sends a message with a failure, that message is what the `role="alert"` element shows; the `error` label is only the fallback.

## Accessibility

Each form is a real `<form>` with labels wired to inputs by `for`/`id`, correct `type` and `autocomplete` on every input (`email`, `current-password`, `new-password`, `one-time-code`, `username`), `aria-busy` on the form while a request is in flight, `aria-invalid` on the fields a failure implicates, and the error message in a `role="alert"` element.

See [the client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) for the rest of the client API.

## API

- `useSession(client): UseSessionResult` — a shallow ref over `SessionState` with `dispose`.
- `useListSessions(client): ListSessionsRefs` — refs `data`, `isPending`, `error`, plus `refetch` and `dispose`.
- `authClientPlugin` (`AuthClientPluginOptions`: `{ client }`), `provideAuthClient(client)`, `useAuthClient(override?)`, `authClientKey`.
- Components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`.
- Default labels and their types: `signInFormLabels`, `signUpFormLabels`, `passwordResetRequestFormLabels`, `passwordResetConfirmFormLabels`, `magicLinkFormLabels`, `emailOtpFormLabels` (`SignInFormLabels`, …).
- Shared types: `AuthFormClasses`, `AuthSuccess`, `StatusResponse`, `EmailOtpPurpose`.

## License

MIT
