# @thomasfosterau/effect-auth-sveltekit

The server side of [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) in a SvelteKit app:

- `handle`: the `handle` hook. It resolves the session once, before any `load`, puts it on `event.locals.auth` (the session named by its stored id, the token's digest: no credential, so `locals.auth` is safe to return from a `load`), and forces `Cache-Control: private, no-store` on pages rendered for a signed-in viewer.
- `credentialAction`: the form action for sign-in, sign-up and the other credential flows. It relays the auth handler's `Set-Cookie`, redirects only to a validated target, returns a `pending` result when no session was issued yet (a second factor, or email verification), and reports wrong credentials, throttling and service faults as distinct failures.
- `credentialForm` and `credentialCommand`: the same credential flows as SvelteKit remote functions (`form()` and `command()` from `$app/server`).

The package is typed against the parts of SvelteKit's `RequestEvent` it uses, and takes `redirect` and `fail` from you, so it does not depend on `@sveltejs/kit`.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-sveltekit @thomasfosterau/effect-auth effect
```

## Usage

```ts
// src/hooks.server.ts
import { sequence } from "@sveltejs/kit/hooks";
import { Effect } from "effect";
import * as Http from "@thomasfosterau/effect-auth/http";
import { handle as auth } from "@thomasfosterau/effect-auth-sveltekit/Handle";

const authHook = auth({
  cookies: { name: "app_session" },
  // The session read for this request: here, the auth Worker over a service binding.
  // `read` answers the session and its `Set-Cookie` lines, which the hook replays.
  lookup: (request, event) =>
    remoteSession.read(request, { clientAddress: event.getClientAddress() }),
  // Anonymous is the lower-privilege outcome for this app, so degrade to it.
  failure: { mode: "open", onDegraded: (cause) => Effect.logError("auth degraded", cause) },
});

export const handle = sequence(authHook /* , your other hooks */);
```

```ts
// src/app.d.ts
declare global {
  namespace App {
    interface Locals {
      auth: import("@thomasfosterau/effect-auth-sveltekit").LocalsAuth;
    }
  }
}
export {};
```

## Entry points

- `handle(options): (input) => Promise<Response>`, with `HandleOptions` (`cookies?`, `lookup`, `failure`), `LocalsAuth`, `FailurePolicy`, `HandleEvent`, `HandleInput` and `PRIVATE_CACHE_CONTROL`.
- `credentialAction(kit, options): (event) => Promise<Failure | CredentialPending<Fields>>`, with `CredentialActionOptions`, `CredentialFailure`, `CredentialFailureKind`, `CredentialPending`, `Kit`, `ActionEvent` and `CookieOptions`.
- `credentialForm(kit, options): (input) => Promise<CredentialPending<Fields> | CredentialFailure<Fields>>` and `credentialCommand(kit, options): (input) => Promise<CredentialResult<Fields>>`, with `RemoteFormKit`, `RemoteKit` and `CredentialRequestOptions<Input, Fields>` (`CredentialActionOptions` is its `FormData` case).
- `submitCredential(event, input, options): Promise<CredentialResult<Fields>>`, the shared core: `CredentialSignedIn`, `CredentialPending` or `CredentialRejected`.
- `parseSetCookie(header): Option<{ name, value, options }>`.
- `safeRedirect(target, fallback)` itself lives in the core (`@thomasfosterau/effect-auth`).

## Guide

The [SvelteKit guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/sveltekit.md) walks through the hook, the credential form actions and the remote functions.

## License

MIT
