# @effect-auth/client

Framework client libraries for [effect-auth](https://github.com/thomasfosterau/effect-auth): a small, dependency-free vanilla client over the auth HTTP contract, plus React, Svelte, and Vue bindings.

## Vanilla

```ts
import { createAuthClient } from "@effect-auth/client";

const client = createAuthClient({ baseUrl: "/api/auth" });

await client.signUp({ email, password });
await client.signIn({ email, password });
const session = await client.getSession(); // null when signed out
await client.signOut();

// Optional feature namespaces (404 AuthClientError when not enabled server-side):
await client.magicLink.send({ email });
await client.emailOtp.signIn({ email, otp });
await client.twoFactor.verifyTotp({ token, code });
```

Every client owns an observable **session store** — `{ data, isPending, error }` — that is fetched lazily on first subscription and refreshed automatically after every session-changing call (`signIn`, `signUp`, `signOut`, magic-link/OTP/two-factor redemption, `updateUser`, ...):

```ts
client.session.subscribe(() => render(client.session.get()));
await client.session.refetch(); // manual refresh
```

Errors are `AuthClientError` instances carrying the HTTP `status` and the server's `message`.

## React

```tsx
import { useSession, useListSessions } from "@effect-auth/client/react";

function Navbar() {
  const { data, isPending } = useSession(client);
  if (isPending) return <Spinner />;
  return data ? <b>{data.user.email}</b> : <a href="/login">Sign in</a>;
}
```

`useSession` subscribes via `useSyncExternalStore`; `useListSessions` fetches the active session list and exposes `refetch`.

## Svelte

```svelte
<script>
  import { sessionStore } from "@effect-auth/client/svelte";
  const session = sessionStore(client);
</script>

{#if $session.data}Signed in as {$session.data.user.email}{/if}
```

`sessionStore` implements the readable-store contract directly — no `svelte` runtime import.

## Vue

```vue
<script setup>
import { useSession } from "@effect-auth/client/vue";
const session = useSession(client);
</script>

<template>
  <span v-if="session.data">{{ session.data.user.email }}</span>
</template>
```

## Types

Wire types (`UserView`, `SessionWithUserView`, `AuthSuccess`, ...) are re-exported type-only from `@effect-auth/client/types`, so client code shares the server contract's shapes without importing any server code.

## Bundle size

The core client is plain `fetch` + an ~80-line observable — it does **not** pull the Effect runtime or the `effect-auth` server package into your bundle (only type-only imports, which erase at compile time). The vanilla entry is ~2 kB min+gzip; each framework adapter adds well under 1 kB on top of the framework you already ship. If you want the full Effect-native experience instead (typed errors as `Effect`s, schema-validated responses), use `effect-auth`'s `Http.makeAuthClient`, which derives an `HttpApiClient` from the same contract.

## Testing

The package's own tests run the real `effect-auth` web handler in-process with a cookie-jar `fetch` (see `src/testing/fixture.ts`) — the same technique works for your app's integration tests.
