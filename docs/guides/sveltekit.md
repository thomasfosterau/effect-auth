# effect-auth in a SvelteKit app

This guide covers the server side of a SvelteKit app on effect-auth. The browser side (the typed
client and the Svelte components) is in [client.md](client.md). Where the auth handler runs (in the
app's own Worker, or as a separate service behind a binding) is covered in
[split-auth-service.md](split-auth-service.md).

`@thomasfosterau/effect-auth-sveltekit` ([README](../../packages/sveltekit/README.md),
[ADR-0021](../adr/0021-sveltekit-server-adapter.md)) provides two things: the `handle` hook and the
credential form action.

## 1. Resolve the session once, in `handle`

```ts
// src/hooks.server.ts
import { sequence } from "@sveltejs/kit/hooks";
import { Effect } from "effect";
import { handle as auth } from "@thomasfosterau/effect-auth-sveltekit";

export const handle = sequence(
  auth({
    cookies: { name: "app_session" }, // the same naming the auth handler uses
    lookup: (request) => lookupSession(request), // in-process SessionService, or Http.RemoteSession
    failure: { mode: "open", onDegraded: (cause) => Effect.logError("auth degraded", cause) },
  }),
  // ...your other hooks, which now see event.locals.auth
);
```

- **The cookieless skip is built in.** A request with no session cookie, bearer token or API key
  never calls `lookup`, and its outcome is `skipped`. For a split service, this is the largest
  read-path saving there is.
- **The failure direction is your decision.** `failure` has no default. `open` is safe only when
  anonymous is the lower-privilege outcome (public reads, with every write gated on the resolved
  viewer). Otherwise use `closed`.
- **A lookup's `Set-Cookie` reaches the browser.** `Http.RemoteSession`'s `read` answers the
  session with the `Set-Cookie` lines the auth service sent (a refreshed cache cookie, or the
  clearing of a stale one). Return it from `lookup` as it is and the hook appends them to the
  response, except for an API-key or bearer caller, which never receives a cookie.
- **The client address is SvelteKit's.** Pass `event.getClientAddress()` on with
  `remoteSession.read(request, { clientAddress: event.getClientAddress() })`, and the credential
  actions send it by default. Both send it in one header (`x-forwarded-for` unless you name
  another) and drop the browser's own `x-forwarded-for` and `cf-connecting-ip`; configure the auth
  handler to trust that one header (`trustedProxy: ClientIP.trustedHeader("x-forwarded-for")`).
- **Cache-control comes after authentication.** The hook sets `Cache-Control: private, no-store`
  on any page rendered for a signed-in viewer, after rendering, whatever the route set. Don't put
  a cache-control hook before it in `sequence`: it would run before the viewer is known, and a page
  rendered for an admin could be stored in a shared cache.

## 2. Expose the user once, from the root layout

```ts
// src/routes/+layout.server.ts
export const load = ({ locals }) => ({ user: locals.auth.session?.user ?? null });
```

Pages and components read the user from `page.data.user`. Don't fetch the session per component
or per `load`. That costs a round trip each time, and two reads in one render can disagree.

A route that needs a signed-in user checks `locals.auth.session` in its own `load` or action, and
redirects to sign-in with `?redirect=` set to the current path.

## 3. Sign in and sign up with form actions

`credentialAction` turns a form POST into a call to the auth handler (see the
[below](#credential-form-actions)). It does three things a
hand-written action tends to get wrong:

- It relays `Set-Cookie` through `event.cookies`. SvelteKit drops the headers on a thrown
  redirect, so a relay that only copies headers loses the session cookie.
- It redirects through `safeRedirect`, so `/login?redirect=https://evil.example` lands on the
  fallback instead of a phishing page.
- It reports a `429` as `rate-limited`, with `retryAfterSeconds`, distinct from wrong credentials.
  Show it: a throttled sign-in that renders nothing looks like a broken form.

## 4. `safeRedirect` outside forms

`safeRedirect(target, fallback)` is in the core (`@thomasfosterau/effect-auth`), not this package.
Use it wherever a client-supplied "next" value is followed: OAuth and SSO callbacks, the OIDC
provider's post-sign-in return, and sign-out. It accepts only a same-origin path, and falls back
for everything else, including `//host`, `/\host`, schemes, and control characters.

## The hook in detail

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
