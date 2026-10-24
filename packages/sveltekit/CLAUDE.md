# @thomasfosterau/effect-auth-sveltekit

The server side of effect-auth in a SvelteKit app ([ADR-0021](../../docs/adr/0021-sveltekit-server-adapter.md)): the `handle` hook (`Handle.ts`) and the credential form action (`Actions.ts`).

## Boundary

Archetype **Server binding** (`.fallowrc.json` zone `server-bindings`, which may import `core` and `ladder`). It depends on `@thomasfosterau/effect-auth` and peers `effect` (`catalog:peers`). It does **not** depend on `@sveltejs/kit`. Both entry points are typed against the parts of SvelteKit's `RequestEvent` they use (`HandleEvent`, `ActionEvent`), and the form action takes kit's `redirect` and `fail` as arguments (`Kit`). So a kit major-version bump is a structural check in the consumer's type-check, not a peer range here.

## Invariants

- **Authenticate, render, then set the cache headers.** `handle` resolves the session and sets `event.locals.auth` before calling `resolve`, and only afterwards forces `Cache-Control: private, no-store` on a response rendered for a signed-in viewer. It copies the response first, because a fetched or redirect `Response` has immutable headers.
- **Resolution is the core's.** The cookieless skip, the fail-open and fail-closed directions and the outcome metric come from `SessionResolution`. The hook never derives an outcome itself, and `failure` has no default.
- **The redirect target is always `safeRedirect`'s answer** (core `Redirect.ts`). It is never the raw query parameter.
- **`Set-Cookie` is relayed through `event.cookies.set`**, attribute for attribute. Absent `HttpOnly` and `Secure` are passed as `false`, because SvelteKit would otherwise default them to `true`.
- **Failures are distinguishable.** `400` and `401` map to `invalid`, `429` to `rate-limited` (with `Retry-After` seconds), and anything else, including the call throwing, to `unavailable`. Each kind has its own `fail` status. The password is never echoed back: `fields` is the caller's choice.

## Terms

- **Lookup**: the app's own session read for one request (in-process `SessionService`, or `Http.RemoteSession` over a binding).
- **Credential action**: a form action that POSTs a credential to the auth handler and redirects on success: sign-in, sign-up, and the passwordless flows.
