---
"@thomasfosterau/effect-auth-sveltekit": minor
---

Credential helpers for SvelteKit remote functions (#487). `credentialForm` builds a remote `form()` handler: it sets the session cookie and redirects to the `safeRedirect`-validated target, or returns the pending step or a failure whose `kind` tells `invalid` (`400`/`401`) from `rate-limited` (`429`) and `unavailable`. `credentialCommand` builds a remote `command()` handler that answers the whole result, with the target as `location`, since a command cannot redirect. Both take `getRequestEvent` (and `redirect`) from the app, so the package still has no `@sveltejs/kit` dependency. `credentialAction` now wraps the same `submitCredential`, which is exported. `CredentialRequestOptions<Input, Fields>` generalizes `CredentialActionOptions` (now its `FormData` case), with a new `target` option for reading the post-sign-in target from the input.
