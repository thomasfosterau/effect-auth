# @thomasfosterau/effect-auth-svelte

Svelte bindings for [`@thomasfosterau/effect-auth/client`](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client-reference.md), the browser client subpath of the core: readable stores over its session Atoms ([`/client/atoms`](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client-reference.md#the-session-atoms-clientatoms), `effect/reactivity`), plus unstyled form components for the usual authentication screens.

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

## Entry points

- `atomStore(registry, atom): Readable<A>`, `sessionStore(registry, atoms): Readable<SessionState>` and `listSessionsStore(registry, atoms): ListSessionsStore` (`ListSessionsState` plus `refetch`); `Readable` is the readable-store contract they implement, `atoms` the `SessionAtoms` from `makeSessionAtoms`.
- `setAuthClient(client)`, `getAuthClient()`, `authClientKey` (the context key).
- Forms: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`, with their `*FormProps` and `*Labels` types.
- Shared form types: `AuthFormBaseProps`, `AuthFormClasses`, `AuthSuccess`, `StatusResponse`, `EmailOtpPurpose`, `FormFailure`.

## Guides

- [Svelte bindings](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/svelte.md): the stores in detail, the form components, their context, styling and text.
- [The browser client](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md).

## License

MIT
