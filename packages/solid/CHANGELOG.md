# @thomasfosterau/effect-auth-solid

## 0.2.0

### Minor Changes

- cc67083: Framework packages, form components, and adapter reworks.
  
  - Framework bindings moved out of the client into their own packages — `@thomasfosterau/effect-auth-react`, `-svelte`, `-vue`, and the new `-solid` — each with idiomatic authoring (React JSX, Svelte 5 runes `.svelte` components, Vue SFCs, Solid JSX with a `"solid"` export condition) and the same six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth-sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- c54e5d1: Raise the `solid-js` peer floor from `>=1.8` to `>=1.9.17` (#308).
  
  solid-js 1.9.15 and earlier declare `seroval` and `seroval-plugins` `~1.5.4`, inside the range covered by GHSA-p6vx-979v-rg4c and GHSA-jp82-f5mq-hwhp. A consumer on one of those releases resolves that seroval in its own dependency tree, which no override in this workspace can change. solid-js 1.9.16 moved to `seroval ~1.6.8`; the floor is set at 1.9.17, the release this workspace now builds against. No API changes.

### Patch Changes

- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- 5ab875a: The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
- Updated dependencies [ca3abfb]
- Updated dependencies [7f5206e]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [dcffe28]
- Updated dependencies [8d904a6]
- Updated dependencies [cc67083]
- Updated dependencies [78dac5f]
- Updated dependencies [02df078]
- Updated dependencies [624a9b5]
- Updated dependencies [ef58828]
- Updated dependencies [d2d8163]
- Updated dependencies [5ab875a]
- Updated dependencies [a517a32]
  - @thomasfosterau/effect-auth-client@0.2.0
