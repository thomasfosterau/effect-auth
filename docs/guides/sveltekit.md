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
[README](../../packages/sveltekit/README.md#credential-form-actions)). It does three things a
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
