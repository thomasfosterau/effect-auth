---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-svelte": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
"@thomasfosterau/effect-auth-alchemy-postgres": minor
---

Framework packages, form components, and adapter reworks.

- The Svelte binding moved out of the client into its own package, `@thomasfosterau/effect-auth-svelte`, authored as Svelte 5 runes `.svelte` components, with six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
- `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
- `@thomasfosterau/effect-auth-alchemy-cloudflare` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth/sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
