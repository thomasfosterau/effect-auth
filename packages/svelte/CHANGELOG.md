# @thomasfosterau/effect-auth-svelte

## 0.1.1

### Patch Changes

- 3c140a6: Ship `CHANGELOG.md` in the published tarball, so the release notes can be read from `node_modules` (#545).
- e52a95d: Pay down oxlint adoption allowances (#503): `AuthDatabase.delete` drops its unused type parameter, and the core's message catalog, header detection and client session refresh are rewritten without behaviour changes for valid inputs.
- Updated dependencies [55637b0]
- Updated dependencies [3c140a6]
- Updated dependencies [1cacf66]
- Updated dependencies [e52a95d]
- Updated dependencies [7f12561]
- Updated dependencies [47534bb]
- Updated dependencies [4c48eb4]
  - @thomasfosterau/effect-auth@0.2.0

## 0.1.0

### Minor Changes

- cc67083: Framework packages, form components, and adapter reworks.
  
  - The Svelte binding moved out of the client into its own package, `@thomasfosterau/effect-auth-svelte`, authored as Svelte 5 runes `.svelte` components, with six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy-cloudflare` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth/sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- ce56aeb: **Breaking (HTTP):** sign-in, sign-up and the flows that prove an address are JSON:API resources (#205). They take `application/vnd.api+json` documents and answer JSON:API documents and error documents.
  
  | Before                                                                                                                                                  | Now                                                                                                                                                                                       |
  | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `POST /sign-in`, `/sign-in/username`, `/sign-in/email-otp`, `/sign-in/phone-otp`, `/sign-in/anonymous`, `/sign-in/google-one-tap`, `/magic-link/verify` | `POST /sessions`, its write-only `credential` attribute tagged by `method` (`password`, `username`, `email-otp`, `phone-otp`, `anonymous`, `google-one-tap` with `idToken`, `magic-link`) |
  | `POST /multi-factor/verify-totp`, `/multi-factor/verify-backup-code`                                                                                    | `POST /second-factor-challenges/verifications` (`method`: `totp` / `backup-code`; the challenge as a relationship)                                                                        |
  | `POST /sign-up`                                                                                                                                         | `POST /users`                                                                                                                                                                             |
  | `POST /email-otp/send`, `/phone-otp/send`, `/magic-link/send`                                                                                           | `POST /otp-challenges` (`channel`: `email` / `phone` / `magic-link`)                                                                                                                      |
  | `POST /email-verification/send` · `/email-verification/verify`                                                                                          | `POST /email-verifications` · `POST /email-verifications/redemptions` (the token)                                                                                                         |
  | `POST /password-reset/request` · `/password-reset/reset`                                                                                                | `POST /password-resets` · `POST /password-resets/redemptions` (the token)                                                                                                                 |
  | `GET /sign-in/google-one-tap/nonce`                                                                                                                     | `POST /google-one-tap-nonces` (the nonce is the resource's id)                                                                                                                            |
  
  - A sign-in or sign-up that issues a session answers `201` with the `sessions` resource, its user in `included` and `meta.needsEmailVerification`. One that issues none answers `202`: with the `second-factor-challenges` resource to redeem, or with only `meta.needsEmailVerification` when the address must be verified first. The second-factor answer no longer carries the user.
  - Under `antiEnumeration`, `POST /users` answers a fresh address and a held one with the same `202` and no user at all, so neither answer names an id (#195, #414).
  - The sends (`otp-challenges`, `email-verifications`, `password-resets`) answer `202` with no body; a password reset answers `204`; an email verification answers `201` with the session when it signs the user in, else `204`.
  - The default IP rate-limit rules follow the paths: `POST /sessions` (every sign-in method, now including magic-link verification), `POST /users`, `POST /otp-challenges`, `POST /password-resets` and the second-factor verifications.
  - No secret travels in a URL: the reset, verification and second-factor challenge tokens are sent in the request body, so access logs, `Referer` headers and rate-limit keys never carry them.
  - A rate-limit rule whose `path` is a regex now counts every path it matches in one bucket per client address (it was one bucket per path), so a caller cannot reset its count by varying the path.
  - effect-auth/client: the sign-in, sign-up and verification methods keep their arguments and resolve with the new `AuthResult`, whose `user` is present only when a session was issued. `continueChallenge` takes an `AuthResult`. The Svelte binding's form `AuthSuccess` type follows it.
  - effect-auth-sveltekit: `credentialAction` sends its body as `application/vnd.api+json` by default (`contentType` overrides it), so an action for `POST /sessions` posts a `sessions` document.
- c1b0737: The binding now depends on `@thomasfosterau/effect-auth` for its `/client` subpath instead of on `@thomasfosterau/effect-auth-client`, which merged into the core. Install `@thomasfosterau/effect-auth` and import `createAuthClient` from `@thomasfosterau/effect-auth/client`.

### Patch Changes

- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- 5ab875a: The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
- fed9d0c: Doc comments name `@thomasfosterau/effect-auth-svelte` as the one framework binding: the React, Vue and Solid bindings were removed before their first release. No API change.
- Updated dependencies [84c9180]
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [ca3abfb]
- Updated dependencies [7f5206e]
- Updated dependencies [29d011c]
- Updated dependencies [afd57ae]
- Updated dependencies [20cde53]
- Updated dependencies [c1b0737]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [aa7b6e6]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [51edf74]
- Updated dependencies [dcffe28]
- Updated dependencies [0def0c5]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [42d0f03]
- Updated dependencies [b165354]
- Updated dependencies [cc67083]
- Updated dependencies [fa438cf]
- Updated dependencies [5ab2078]
- Updated dependencies [9ff7ded]
- Updated dependencies [78dac5f]
- Updated dependencies [78dac5f]
- Updated dependencies [41ce19d]
- Updated dependencies [b1fbf57]
- Updated dependencies [ce56aeb]
- Updated dependencies [e03530e]
- Updated dependencies [4c70cd2]
- Updated dependencies [c1ba5f6]
- Updated dependencies [02df078]
- Updated dependencies [4e6293b]
- Updated dependencies [2484af6]
- Updated dependencies [6bee50c]
- Updated dependencies [90d7a79]
- Updated dependencies [d767491]
- Updated dependencies [7f5206e]
- Updated dependencies [e6c3a64]
- Updated dependencies [39654ad]
- Updated dependencies [f4f6606]
- Updated dependencies [624a9b5]
- Updated dependencies [373bb87]
- Updated dependencies [ec17f5d]
- Updated dependencies [8e5fc41]
- Updated dependencies [504ae0d]
- Updated dependencies [c99689b]
- Updated dependencies [1d47091]
- Updated dependencies [3de5d6a]
- Updated dependencies [a108a36]
- Updated dependencies [624f356]
- Updated dependencies [ef58828]
- Updated dependencies [00aa6e9]
- Updated dependencies [8213f5b]
- Updated dependencies [d2d8163]
- Updated dependencies [856d6fe]
- Updated dependencies [8235dad]
- Updated dependencies [5a48055]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
- Updated dependencies [5ab875a]
- Updated dependencies [f5bf843]
- Updated dependencies [8fce539]
- Updated dependencies [a517a32]
- Updated dependencies [5e1d6ce]
- Updated dependencies [311e9cb]
- Updated dependencies [a81a752]
- Updated dependencies [50a4084]
- Updated dependencies [36788a7]
- Updated dependencies [68e339a]
- Updated dependencies [2ba63b6]
- Updated dependencies [408285d]
- Updated dependencies [a3131b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [fed9d0c]
- Updated dependencies [03a3219]
- Updated dependencies [ca3abfb]
- Updated dependencies [9ff7ded]
- Updated dependencies [cbeda0d]
- Updated dependencies [8f78034]
- Updated dependencies [f7bafc0]
- Updated dependencies [c092987]
- Updated dependencies [ef0207d]
- Updated dependencies [bfa558e]
- Updated dependencies [3875062]
- Updated dependencies [1031ed5]
- Updated dependencies [5ab2078]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.1.0
