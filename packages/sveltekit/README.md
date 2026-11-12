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

On success (a `201`, or any other 2xx but `202`) the action relays every `Set-Cookie` onto `event.cookies` and redirects (303) to `?redirect=` when that is a same-origin path, or to `fallback` otherwise.

A `202` means the handler took the credential but issued no session, so the action does not redirect. It returns `{ kind: "pending", secondFactor, needsEmailVerification, fields }` as the action's data (`form` on the page):

- `secondFactor: { token, expiresAt }` when a second factor is pending: show the code step, and redeem the challenge with `POST /second-factor-challenges/verifications`, citing `token`;
- `secondFactor: null` with `needsEmailVerification: true` when the address must be verified first (a sign-up under `antiEnumeration` always answers this way): show a check-your-inbox step.

A `202` whose body is not the handler's pending document counts as `unavailable`. On failure it returns `fail(status, { kind, message, retryAfterSeconds, fields })`:

| Handler answered                 | `kind`                                                       | `fail` status |
| -------------------------------- | ------------------------------------------------------------ | ------------- |
| `400`, `401`                     | `invalid`                                                    | 400           |
| `429`                            | `rate-limited` (with `retryAfterSeconds` from `Retry-After`) | 429           |
| anything else, or the call threw | `unavailable`                                                | 503           |

The action forwards the browser's `Origin`, `User-Agent`, `X-Forwarded-For` and `CF-Connecting-IP`, so the handler's CSRF check and rate limits see the real client. The browser's origin must be in the auth handler's `trustedOrigins`.

## Remote functions

`credentialForm` and `credentialCommand` give a remote function the same submission as `credentialAction`, through the shared `submitCredential`. They take `getRequestEvent` from `$app/server`, and `credentialForm` also takes `redirect`:

```ts
// src/routes/login/sign-in.remote.ts
import { getRequestEvent, form } from "$app/server";
import { redirect } from "@sveltejs/kit";
import { credentialForm } from "@thomasfosterau/effect-auth-sveltekit";

export const signIn = form(
  credentialForm(
    { getRequestEvent, redirect },
    {
      fetch: (request) => getRequestEvent().platform!.env.AUTH.fetch(request),
      endpoint: "https://auth.internal/api/auth/sessions",
      body: (form: FormData) => ({
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
      // A remote call's event is not the page's: read the target from the form.
      target: (form) => String(form.get("redirect") ?? ""),
      fallback: "/",
    },
  ),
);
```

- **`credentialForm`** sets the session cookie and redirects (303) to the validated target. Otherwise it returns `form.result`: the `pending` step as above, or the failure `{ kind, message, retryAfterSeconds, fields }`, whose `kind` tells `invalid` (`400`/`401`) from `rate-limited` (`429`) and `unavailable`.
- **`credentialCommand`** can't redirect, because a command cannot. It answers `{ kind: "signed-in", location }` with the cookie already set (navigate with `goto(result.location)`), the `pending` step, or `{ kind: "failed", status, failure }`.

`Input` is whatever the remote function hands its handler: `FormData`, or the validated object of a schema'd `form` or `command`. By default the target is the event URL's `?redirect=`, which for a remote call is the remote endpoint's URL, not the page's. So pass `target` to read it from the input.

## API

- `handle(options): (input) => Promise<Response>`, with `HandleOptions` (`cookies?`, `lookup`, `failure`), `LocalsAuth`, `FailurePolicy`, `HandleEvent`, `HandleInput` and `PRIVATE_CACHE_CONTROL`.
- `credentialAction(kit, options): (event) => Promise<Failure | CredentialPending<Fields>>`, with `CredentialActionOptions`, `CredentialFailure`, `CredentialFailureKind`, `CredentialPending`, `Kit`, `ActionEvent` and `CookieOptions`.
- `credentialForm(kit, options): (input) => Promise<CredentialPending<Fields> | CredentialFailure<Fields>>` and `credentialCommand(kit, options): (input) => Promise<CredentialResult<Fields>>`, with `RemoteFormKit`, `RemoteKit` and `CredentialRequestOptions<Input, Fields>` (`CredentialActionOptions` is its `FormData` case).
- `submitCredential(event, input, options): Promise<CredentialResult<Fields>>`, the shared core: `CredentialSignedIn`, `CredentialPending` or `CredentialRejected`.
- `parseSetCookie(header): Option<{ name, value, options }>`.
- `safeRedirect(target, fallback)` itself lives in the core (`@thomasfosterau/effect-auth`).

## License

MIT
