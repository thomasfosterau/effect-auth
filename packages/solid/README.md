# @thomasfosterau/effect-auth-solid

Solid bindings for [`@thomasfosterau/effect-auth-client`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/client): reactive primitives over the client's observable session store, plus unstyled form components for the usual authentication screens.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-solid @thomasfosterau/effect-auth-client effect
```

`solid-js` (>= 1.9.17) is a peer dependency.

The package ships a `solid` export condition pointing at un-compiled JSX, so a Solid-aware bundler (`vite-plugin-solid`, SolidStart) compiles the components with your own app; bundlers without that condition fall back to a pre-compiled ESM build.

## Provider setup

Create the client once and put it in context; every binding and form component below resolves it from there.

```tsx
import { render } from "solid-js/web";
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { AuthClientProvider } from "@thomasfosterau/effect-auth-solid";

const client = createAuthClient({ baseUrl: "/api/auth" });

render(
  () => (
    <AuthClientProvider client={client}>
      <App />
    </AuthClientProvider>
  ),
  document.getElementById("root")!,
);
```

`useSession()` reads that client and returns an accessor over its session store — subscribing triggers the initial `GET /sessions/current` read, every auth mutation on the client refreshes it, and the subscription is released with the owning component.

```tsx
import { Show } from "solid-js";
import { useSession } from "@thomasfosterau/effect-auth-solid";

function Navbar() {
  const session = useSession();
  return (
    <Show fallback={<a href="/login">Sign in</a>} when={session().data}>
      {(data) => <b>{data().user.email}</b>}
    </Show>
  );
}
```

`createSession(client)` is the same primitive with the client passed explicitly, and `useListSessions()` / `createListSessions(client)` fetch the signed-in user's active sessions.

## Form components

`SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm` and `EmailOtpForm` each own their submit, pending and error state, and report the outcome through `onSuccess` / `onError` rather than navigating.

```tsx
import { useNavigate } from "@solidjs/router";
import { SignInForm } from "@thomasfosterau/effect-auth-solid";

function Login() {
  const navigate = useNavigate();
  return (
    <SignInForm
      labels={{ submit: "Log in" }}
      onError={(cause) => console.error(cause)}
      onSuccess={() => navigate("/app")}
    />
  );
}
```

Every visible string is overridable through `labels`, a `client` prop overrides the one from context, `variant="username"` switches `SignInForm` to `client.signInUsername`, and `EmailOtpForm` walks both steps of an emailed code in one component.

## Styling

The components ship no CSS. Each element carries a stable class — `ea-form` plus a per-form modifier (`ea-sign-in`, `ea-sign-up`, `ea-password-reset-request`, `ea-password-reset-confirm`, `ea-magic-link`, `ea-email-otp`), then `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error`, `ea-status` and `ea-restart` — so a stylesheet can dress them from the outside.

```css
.ea-form {
  display: grid;
  gap: 0.75rem;
  max-width: 22rem;
}

.ea-field {
  display: grid;
  gap: 0.25rem;
}

.ea-input[aria-invalid="true"] {
  border-color: crimson;
}

.ea-submit:disabled {
  opacity: 0.6;
}

.ea-error {
  color: crimson;
}
```

A `class` prop is appended to the root `<form>`, and the `classes` prop replaces individual defaults (`classes={{ submit: "btn btn-primary" }}`) when a design system would rather not see the `ea-*` names at all.

See [the client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) for the rest of the client API.

## API

- `createSession(client)` / `useSession()` — a `SessionAccessor` (an accessor over `SessionState` with `dispose`).
- `createListSessions(client)` / `useListSessions()` — `ListSessionsResult`: accessors `data`, `isPending`, `error`, plus `refetch` and `dispose`.
- `AuthClientProvider` (`AuthClientProviderProps`), `AuthClientContext`, `useAuthClient()`.
- Forms: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`, each with its `*FormProps` and `*Labels` types.
- Shared form types: `AuthFormBaseProps`, `AuthFormClasses`, `AuthSuccess`, `StatusResponse`.

## License

MIT
