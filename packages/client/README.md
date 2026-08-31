# @thomasfosterau/effect-auth-client

The browser half of [effect-auth](https://github.com/thomasfosterau/effect-auth): a small, dependency-free client over the auth HTTP contract (plain `fetch`, no Effect runtime in the bundle) with an observable session store. Only the wire _types_ come from `@thomasfosterau/effect-auth`, and those erase at compile time — nothing server-side reaches the browser bundle.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-client
```

## Usage

```ts
import { createAuthClient, AuthClientError } from "@thomasfosterau/effect-auth-client";

const client = createAuthClient({ baseUrl: "/api/auth" });

// Typed methods mirroring the contract's endpoint names.
const { user } = await client.signIn({ email, password });

// An observable session store the framework bindings subscribe to.
const unsubscribe = client.session.subscribe(() => render(client.session.get()));

try {
  await client.signIn({ email, password: "wrong" });
} catch (error) {
  if (error instanceof AuthClientError && error.status === 401) showBadCredentials();
}
```

## Framework bindings

Each framework has its own package built on this client:

| Framework | Package                              |
| --------- | ------------------------------------ |
| React     | `@thomasfosterau/effect-auth-react`  |
| Svelte    | `@thomasfosterau/effect-auth-svelte` |
| Vue       | `@thomasfosterau/effect-auth-vue`    |

See [the client guide](https://github.com/thomasfosterau/effect-auth/blob/main/docs/guides/client.md) for the full endpoint coverage, background-refresh options and the plugin API.

## License

MIT
