# @thomasfosterau/effect-auth-svelte

Svelte bindings for [`@thomasfosterau/effect-auth-client`](https://github.com/thomasfosterau/effect-auth/tree/main/packages/client): readable stores over the client's observable session store, plus unstyled form components for the usual authentication screens.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-svelte @thomasfosterau/effect-auth-client
```

`svelte` (>= 5.20) is a peer dependency. The components are authored with runes, and the package is built with `svelte-package`, so it resolves through the `svelte` export condition like any other Svelte component library.

## Usage

```svelte
<script lang="ts">
  import { createAuthClient } from "@thomasfosterau/effect-auth-client";
  import { sessionStore, listSessionsStore } from "@thomasfosterau/effect-auth-svelte";

  const client = createAuthClient({ baseUrl: "/api/auth" });
  const session = sessionStore(client);
  const sessions = listSessionsStore(client);
</script>

{#if $session.isPending}
  Loading…
{:else if $session.data}
  Signed in as {$session.data.user.email} — {$sessions.data?.length ?? 0} active sessions
  <button onclick={sessions.refetch}>Refresh</button>
{/if}
```

The stores implement Svelte's readable-store contract directly, so the `$store` syntax works without importing anything from `svelte/store`.

Subscribing to `sessionStore` triggers the initial `/session` fetch; every auth mutation on the client refreshes it.

See [the client guide](https://github.com/thomasfosterau/effect-auth/blob/main/docs/guides/client.md) for the rest of the client API.

## Forms

The package ships the six forms almost every app needs, so a login screen is a component rather than a morning's work.

| Component                  | Client call                                                   | `onSuccess` receives |
| -------------------------- | ------------------------------------------------------------- | -------------------- |
| `SignInForm`               | `signIn` — or `signInUsername` with `variant="username"`      | `AuthSuccess`        |
| `SignUpForm`               | `signUp` — `name` included unless `showName={false}` or blank | `AuthSuccess`        |
| `PasswordResetRequestForm` | `passwordResetRequest`                                        | `StatusResponse`     |
| `PasswordResetConfirmForm` | `passwordResetConfirm` — takes the emailed `token` as a prop  | `StatusResponse`     |
| `MagicLinkForm`            | `magicLink.send`                                              | `StatusResponse`     |
| `EmailOtpForm`             | `emailOtp.send`, then `emailOtp.signIn` on the second step    | `AuthSuccess`        |

Each form owns its own submit, pending and error state, and calls `onSuccess(result)` / `onError(error)` instead of navigating or reloading — where to go next is your router's business, not the form's.

### Context setup

Put the client in context once, high in the tree, and every form below finds it.

```svelte
<!-- src/routes/+layout.svelte -->
<script lang="ts">
  import { createAuthClient } from "@thomasfosterau/effect-auth-client";
  import { setAuthClient } from "@thomasfosterau/effect-auth-svelte";

  const { children } = $props();

  setAuthClient(createAuthClient({ baseUrl: "/api/auth" }));
</script>

{@render children()}
```

```svelte
<!-- src/routes/login/+page.svelte -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import { SignInForm } from "@thomasfosterau/effect-auth-svelte";
</script>

<SignInForm
  labels={{ email: "Work email", submit: "Continue" }}
  onSuccess={() => goto("/app")}
  onError={(error) => reportToSentry(error)}
/>
```

`getAuthClient()` returns the same client for your own components, and throws a pointed error when nothing above has called `setAuthClient`.

A `client` prop overrides context on any single form, which is what tests and Storybook stories want:

```svelte
<SignInForm client={stubClient} />
```

### The rest of the set

`SignUpForm` collects a name unless you turn it off, and omits a blank one from the request rather than sending `""`.

```svelte
<SignUpForm showName={false} onSuccess={({ needsEmailVerification }) => goto(needsEmailVerification ? "/check-your-email" : "/app")} />
```

The two password-reset forms are the two halves of the flow; the second takes the token out of the URL and checks the confirmation field in the browser, so a mismatch never reaches the server.

```svelte
<PasswordResetRequestForm />

<PasswordResetConfirmForm token={page.url.searchParams.get("token") ?? ""} onSuccess={() => goto("/login")} />
```

`MagicLinkForm` asks the server to email a link; redeeming it is a page-load concern, so the landing route calls `client.magicLink.verify({ token })` itself.

`EmailOtpForm` is both halves of a one-time-code sign-in in one component: it emails a code, swaps itself for a code field, and signs in. `onSuccess` fires only for the second step — the step that yields a session — and the rendered `<form>` carries `data-step="request"` or `data-step="verify"` so a stylesheet can tell them apart.

```svelte
<EmailOtpForm onSuccess={() => goto("/app")} />
```

### Styling

Nothing ships any CSS. The markup is semantic (`<form>`, `<label for>`, inputs with the right `type` and `autocomplete`, `role="alert"` errors, `aria-invalid` on failed fields, `aria-busy` on the form while pending) and every element carries a stable `ea-*` class for a stylesheet to grab:

```css
.ea-form {
  display: grid;
  gap: 0.75rem;
  max-width: 20rem;
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
  border: 1px solid #cbd5e1;
  border-radius: 0.375rem;
  padding: 0.5rem;
}
.ea-input[aria-invalid="true"] {
  border-color: #dc2626;
}
.ea-error {
  color: #dc2626;
  font-size: 0.875rem;
}
.ea-submit[disabled] {
  opacity: 0.6;
}
```

The classes are `ea-form` plus a per-form modifier (`ea-sign-in`, `ea-sign-up`, `ea-password-reset-request`, `ea-password-reset-confirm`, `ea-magic-link`, `ea-email-otp`), then `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error`, `ea-status` and `ea-restart`.

If you would rather not write global CSS, `class` appends to the form root and `classes` replaces individual defaults — enough to drop the forms straight into Tailwind or a CSS-modules setup:

```svelte
<SignInForm
  class="rounded-xl border p-6"
  classes={{ input: "w-full rounded border px-3 py-2", submit: "btn btn-primary" }}
/>
```

### Text and i18n

Every visible string is overridable through `labels`, including the button's pending text and the fallback shown when a server error carries no message of its own. Server messages are rendered verbatim when there are any, so your API's copy wins.

```svelte
<SignUpForm labels={{ name: "Nom", email: "Courriel", submit: "Créer un compte" }} />
```

## License

MIT
