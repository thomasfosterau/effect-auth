---
"@thomasfosterau/effect-auth-sveltekit": minor
---

New package (#200, ADR-0021): the server side of effect-auth in a SvelteKit app. `handle(options)` is the `handle` hook. It resolves the session before `load` through `SessionResolution`, with the cookieless skip and an explicit fail-open or fail-closed choice, sets `event.locals.auth`, and forces `Cache-Control: private, no-store` on pages rendered for a signed-in viewer, after authentication. `credentialAction(kit, options)` is the form action for the credential flows. It relays the auth handler's `Set-Cookie` through `event.cookies`, redirects (303) only to a `safeRedirect`-validated target, and reports `400`/`401`, `429` (with `Retry-After`) and service faults as distinct failures. It is typed structurally against SvelteKit's `RequestEvent`, so it does not depend on `@sveltejs/kit`.
