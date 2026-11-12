# @thomasfosterau/effect-auth-sveltekit

The server side of effect-auth in a SvelteKit app ([ADR-0021](../../docs/adr/0021-sveltekit-server-adapter.md)): the `handle` hook (`Handle.ts`) and the credential helpers (`Actions.ts`): the form action and the remote-function handlers, over one `submitCredential`.

## Boundary

Archetype **Server binding** (`.fallowrc.json` zone `server-bindings`, which may import `core` and `ladder`). It depends on `@thomasfosterau/effect-auth` and peers `effect` (`catalog:peers`). It does **not** depend on `@sveltejs/kit`. Both entry points are typed against the parts of SvelteKit's `RequestEvent` they use (`HandleEvent`, `ActionEvent`), and the form action takes kit's `redirect` and `fail` as arguments (`Kit`), the remote-function handlers `getRequestEvent` and `redirect` (`RemoteKit`, `RemoteFormKit`). So a kit major-version bump is a structural check in the consumer's type-check, not a peer range here.

## Invariants

- **Authenticate, render, then set the cache headers.** `handle` resolves the session and sets `event.locals.auth` before calling `resolve`, and only afterwards forces `Cache-Control: private, no-store` on a response rendered for a signed-in viewer. It copies the response first, because a fetched or redirect `Response` has immutable headers.
- **Resolution is the core's.** The cookieless skip, the fail-open and fail-closed directions and the outcome metric come from `SessionResolution`. The hook never derives an outcome itself, and `failure` has no default.
- **`locals.auth` carries no credential.** The session on it is named by its stored id (the token's digest, #581), so a `load` that returns it serializes nothing replayable into the page; the token reaches the browser only through the relayed `HttpOnly` cookie. `index.test.ts` pins it against the real handler.
- **The redirect target is always `safeRedirect`'s answer** (core `Redirect.ts`). It is never the raw query parameter.
- **`Set-Cookie` is relayed through `event.cookies.set`**, attribute for attribute. Absent `HttpOnly` and `Secure` are passed as `false`, because SvelteKit would otherwise default them to `true`.
- **One submission, three envelopes.** `submitCredential` does the POST, the cookie relay and the failure mapping, and answers a `CredentialResult`; `credentialAction` (`redirect` / `fail`), `credentialForm` (`redirect` / returned result) and `credentialCommand` (the whole result, since a command cannot redirect) only translate it. Behaviour belongs in `submitCredential`.
- **A `202` never redirects.** It issued no session, so the action returns a `pending` result (the second-factor challenge, or `needsEmailVerification`) for the form's next step; only another 2xx relays cookies and redirects.
- **Failures are distinguishable.** `400` and `401` map to `invalid`, `429` to `rate-limited` (with `Retry-After` seconds), and anything else, including the call throwing, to `unavailable`. Each kind has its own `fail` status. The password is never echoed back: `fields` is the caller's choice.

## Terms

- **Lookup**: the app's own session read for one request (in-process `SessionService`, or `Http.RemoteSession` over a binding).
- **Credential action**: a form action (or remote `form()` / `command()`) that POSTs a credential to the auth handler and redirects on success: sign-in, sign-up, and the passwordless flows.
