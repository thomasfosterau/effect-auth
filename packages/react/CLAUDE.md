# @thomasfosterau/effect-auth-react

React bindings over `@thomasfosterau/effect-auth-client`: `useSession` / `useListSessions`, `AuthClientProvider` / `useAuthClient`, and six unstyled form components.

## Boundary

Archetype **Framework binding** (`.fallowrc.json` zone `bindings`, which may import only `client`). Peer: `react` (`catalog:peers`, `>=18`) and nothing else. Depends on `@thomasfosterau/effect-auth-client`, imported as types only (the client is passed in or read from context). Imports nothing from `effect` or from core.

## Invariants

- **Thin over the client**: no fetching of its own, no session cache, no endpoint knowledge beyond the client's methods. `useSession` is `useSyncExternalStore` over `client.session` (the client's `get` is the server snapshot too).
- **Parity with the other bindings** (DESIGN.md D8): the same capability set as `-svelte`, `-solid` and `-vue` (session, session list, provider/context, the six forms with the same `ea-*` classes, labels and outcomes). A feature added here is added to all four.
- **Forms never navigate or reload**: they own submit, pending and error state and report through `onSuccess(result)` / `onError(error)`. `EmailOtpForm` reports success only for the step that yields a session.
- **No CSS ships.** Markup is semantic (`<label htmlFor>`, correct `type` / `autocomplete`, `role="alert"` errors, `aria-invalid`, `aria-busy`) and carries stable `ea-*` classes; `className` appends, `classes` replaces individual defaults. Class names and default label text are public API.
- **Server messages render verbatim**; the `error` label is only the fallback.
- `useAuthClient()` throws a pointed error without a provider; a form's `client` prop overrides context.

## Terms

- **Form outcome** — `AuthSuccess` (sign-in, sign-up, email OTP) or `StatusResponse` (reset request/confirm, magic link), the client's own result types re-exported.
