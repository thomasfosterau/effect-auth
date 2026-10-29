# @thomasfosterau/effect-auth-react

React bindings for [`@thomasfosterau/effect-auth-client`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/client): hooks over the client's observable session store, plus unstyled form components for the usual authentication screens.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-react @thomasfosterau/effect-auth-client effect
```

`react` (>= 18) is a peer dependency.

## Usage

```tsx
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { useSession, useListSessions } from "@thomasfosterau/effect-auth-react";

const client = createAuthClient({ baseUrl: "/api/auth" });

function Navbar() {
  const { data, isPending } = useSession(client);
  if (isPending) return <Spinner />;
  return data ? <b>{data.user.email}</b> : <a href="/login">Sign in</a>;
}

function Devices() {
  const { data, error, refetch } = useListSessions(client);
  if (error) return <p>{error.message}</p>;
  return <button onClick={refetch}>{data?.length ?? 0} active sessions</button>;
}
```

`useSession` reads the client's session store through `useSyncExternalStore`, so the first mounted hook triggers the initial `GET /sessions/current` read and every auth mutation on the client refreshes it.

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

### Provider setup

Wrap the tree once and the forms find the client themselves; a `client` prop still overrides it per instance, which is handy in tests and in Storybook.

```tsx
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { AuthClientProvider, SignInForm } from "@thomasfosterau/effect-auth-react";

const client = createAuthClient({ baseUrl: "/api/auth" });

createRoot(document.getElementById("root")!).render(
  <AuthClientProvider client={client}>
    <App />
  </AuthClientProvider>,
);

function Login() {
  const navigate = useNavigate();
  return (
    <SignInForm
      labels={{ email: "Work email", submit: "Continue" }}
      onError={(error) => reportToSentry(error)}
      onSuccess={() => navigate("/app")}
    />
  );
}
```

`useAuthClient()` returns the same client for your own components, and throws a pointed error when there is no provider above it.

### Styling

Nothing ships any CSS. The markup is semantic (`<form>`, `<label htmlFor>`, inputs with the right `type` and `autocomplete`, `role="alert"` errors, `aria-invalid` on failed fields, `aria-busy` on the form while pending) and every element carries a stable `ea-*` class for a stylesheet to grab:

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

The classes are `ea-form` plus a per-form modifier (`ea-sign-in`, `ea-sign-up`, `ea-password-reset-request`, `ea-password-reset-confirm`, `ea-magic-link`, `ea-email-otp`), then `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error` and `ea-status`.

If you would rather not write global CSS, `className` appends to the form root and `classes` replaces individual defaults — enough to drop the forms straight into Tailwind or a CSS-modules setup:

```tsx
<SignInForm
  className="rounded-xl border p-6"
  classes={{ input: "w-full rounded border px-3 py-2", submit: "btn btn-primary" }}
/>
```

### Text and i18n

Every visible string is overridable through `labels`, including the button's pending text and the fallback shown when a server error carries no message of its own. Server messages are rendered verbatim when there are any, so your API's copy wins.

```tsx
<SignUpForm labels={{ name: "Nom", email: "Courriel", submit: "Créer un compte" }} />
```

## API

- `useSession(client): SessionState` — the client's session store through `useSyncExternalStore`.
- `useListSessions(client): ListSessionsState` — `{ data, isPending, error, refetch }` over `client.listSessions()`.
- `AuthClientProvider` (`AuthClientProviderProps`: `client`, `children`), `useAuthClient()`.
- Forms: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`, each with its `*FormProps` and `*Labels` types.
- Shared form types: `AuthFormBaseProps`, `AuthFormClasses`, `AuthSuccess`, `StatusResponse`.

## License

MIT
