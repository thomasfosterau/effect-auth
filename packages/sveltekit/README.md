# @thomasfosterau/effect-auth-sveltekit

The server side of [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) in a SvelteKit app:

- `handle`: the `handle` hook. It resolves the session once, before any `load`, puts it on `event.locals.auth`, and forces `Cache-Control: private, no-store` on pages rendered for a signed-in viewer.
- `credentialAction`: the form action for sign-in, sign-up and the other credential flows. It relays the auth handler's `Set-Cookie`, redirects only to a validated target, and reports wrong credentials, throttling and service faults as distinct failures.

The package is typed against the parts of SvelteKit's `RequestEvent` it uses, and takes `redirect` and `fail` from you, so it does not depend on `@sveltejs/kit`.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-sveltekit @thomasfosterau/effect-auth effect
```

## The hook

```ts
// src/hooks.server.ts
import { sequence } from "@sveltejs/kit/hooks";
import { Effect } from "effect";
import * as Http from "@thomasfosterau/effect-auth/http";
import { handle as auth } from "@thomasfosterau/effect-auth-sveltekit";

const authHook = auth({
  cookies: { name: "app_session" },
  // The session read for this request: here, the auth Worker over a service binding.
  lookup: (request) => remoteSession.resolve(request),
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

Put the hook first in `sequence`. The later hooks and every `load` then see `event.locals.auth`. Expose the user once from the root layout (`+layout.server.ts` returns `{ user: locals.auth.session?.user ?? null }`), and let pages read it from `page.data` rather than each fetching the session.

`failure` is required: `{ mode: "closed" }` fails the request on a lookup fault, and `{ mode: "open", onDegraded }` continues as anonymous. Read `SessionResolution.resolveFailOpen` for when each is safe.

## Credential form actions

```ts
// src/routes/login/+page.server.ts
import { fail, redirect } from "@sveltejs/kit";
import { credentialAction } from "@thomasfosterau/effect-auth-sveltekit";

export const actions = {
  default: (event) =>
    credentialAction(
      { redirect, fail },
      {
        fetch: (request) => event.platform!.env.AUTH.fetch(request),
        endpoint: "https://auth.internal/api/auth/sessions",
        // Sign in with a password credential: a JSON:API `sessions` document.
        body: (form) => ({
          data: {
            type: "sessions",
            attributes: {
              credential: {
                method: "password",
                email: String(form.get("email") ?? ""),
                password: String(form.get("password") ?? ""),
              },
            },
          },
        }),
        fields: (form) => ({ email: String(form.get("email") ?? "") }),
        fallback: "/",
      },
    )(event),
};
```

On success the action relays every `Set-Cookie` onto `event.cookies` and redirects (303) to `?redirect=` when that is a same-origin path, or to `fallback` otherwise. On failure it returns `fail(status, { kind, message, retryAfterSeconds, fields })`:

| Handler answered                 | `kind`                                                       | `fail` status |
| -------------------------------- | ------------------------------------------------------------ | ------------- |
| `400`, `401`                     | `invalid`                                                    | 400           |
| `429`                            | `rate-limited` (with `retryAfterSeconds` from `Retry-After`) | 429           |
| anything else, or the call threw | `unavailable`                                                | 503           |

The action forwards the browser's `Origin`, `User-Agent`, `X-Forwarded-For` and `CF-Connecting-IP`, so the handler's CSRF check and rate limits see the real client. The browser's origin must be in the auth handler's `trustedOrigins`.

## API

- `handle(options): (input) => Promise<Response>`, with `HandleOptions` (`cookies?`, `lookup`, `failure`), `LocalsAuth`, `FailurePolicy`, `HandleEvent`, `HandleInput` and `PRIVATE_CACHE_CONTROL`.
- `credentialAction(kit, options): (event) => Promise<Failure>`, with `CredentialActionOptions`, `CredentialFailure`, `CredentialFailureKind`, `Kit`, `ActionEvent` and `CookieOptions`.
- `parseSetCookie(header): Option<{ name, value, options }>`.
- `safeRedirect(target, fallback)` itself lives in the core (`@thomasfosterau/effect-auth`).

## License

MIT
