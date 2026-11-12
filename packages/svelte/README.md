# @thomasfosterau/effect-auth-svelte

Svelte bindings for [`@thomasfosterau/effect-auth/client`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth#browser-client-client), the browser client subpath of the core: readable stores over its session Atoms ([`/client/atoms`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth#the-session-atoms-clientatoms), `effect/reactivity`), plus unstyled form components for the usual authentication screens.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-svelte @thomasfosterau/effect-auth effect
```

`svelte` (>= 5.20) and `effect` (>= 4.1, for the Atom types) are peer dependencies. The components are authored with runes, and the package is built with `svelte-package`, so it resolves through the `svelte` export condition like any other Svelte component library.

## Usage

```ts
// src/lib/auth.ts — one client, one set of session Atoms, and the page's one registry.
import { createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";
import { AtomRegistry } from "effect/reactivity";

export const client = createAuthClient({ baseUrl: "/api/auth" });
export const auth = makeSessionAtoms(client, { refresh: { onFocus: true } });
export const registry = AtomRegistry.make();
```

```svelte
<script lang="ts">
  import { sessionStore, listSessionsStore } from "@thomasfosterau/effect-auth-svelte";
  import { auth, registry } from "$lib/auth";

  const session = sessionStore(registry, auth);
  const sessions = listSessionsStore(registry, auth);
</script>

{#if $session.isPending}
  Loading…
{:else if $session.data}
  Signed in as {$session.data.user.email} — {$sessions.data?.length ?? 0} active sessions
  <button onclick={sessions.refetch}>Refresh</button>
{/if}
```

The stores implement Svelte's readable-store contract directly, so the `$store` syntax works without importing anything from `svelte/store`. They hold no state: `atomStore(registry, atom)` turns any Atom into a readable store (mounted while subscribed), and `sessionStore` / `listSessionsStore` are it over `auth.state` and `auth.sessionsState`. Pass the registry the rest of your page uses, and auth and your other Atoms share one graph:

```ts
import { Atom } from "effect/reactivity";
import { atomStore } from "@thomasfosterau/effect-auth-svelte";

// Recomputes on sign-in and sign-out, with no invalidation of its own.
const greeting = atomStore(
  registry,
  Atom.make((get) => `Hello, ${get(auth.data)?.user.email ?? "guest"}`),
);
```

Subscribing to `sessionStore` starts the initial `GET /sessions/current` read; every session-changing call on the client refetches it while it is subscribed, and resolves once it has. The session list refetches when the session changes, and on `sessions.refetch()`.

See [the client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) for the rest of the client API.

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
  import { createAuthClient } from "@thomasfosterau/effect-auth/client";
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

Both send forms take an optional `captchaToken` getter, read when the form submits. Pass it when the server's `CaptchaPlugin` guards code and link sends (its `"sendCode"` endpoint, on by default): render the captcha widget beside the form and return its current token.

```svelte
<MagicLinkForm captchaToken={() => turnstileToken} />
```

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

## API

- `atomStore(registry, atom): Readable<A>`, `sessionStore(registry, atoms): Readable<SessionState>` and `listSessionsStore(registry, atoms): ListSessionsStore` (`ListSessionsState` plus `refetch`); `Readable` is the readable-store contract they implement, `atoms` the `SessionAtoms` from `makeSessionAtoms`.
- `setAuthClient(client)`, `getAuthClient()`, `authClientKey` (the context key).
- Forms: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`, with their `*FormProps` and `*Labels` types.
- Shared form types: `AuthFormBaseProps`, `AuthFormClasses`, `AuthSuccess`, `StatusResponse`, `EmailOtpPurpose`, `FormFailure`.

## License

MIT
