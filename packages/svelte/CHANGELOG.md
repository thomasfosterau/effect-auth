# @thomasfosterau/effect-auth-svelte

## 0.3.0

### Minor Changes

- d3afdec: `CaptchaPlugin` checks what a token was minted for, not only `success: true`: new options `expectedHostname` (one or several), `expectedAction` (one, or one per endpoint) and `minScore` (0 to 1), and `recaptchaVersion: 2 | 3`. reCAPTCHA v3 answers `success: true` for every genuine token, bots included, so `recaptchaVersion: 3` without `minScore` makes the layer build die with the new `CaptchaConfigError`, and a token carrying a `score` that no `minScore` judges is refused. The siteverify answer is decoded with `Schema`, and the client address goes along as `remoteip` when the request has one.
  
  `PasswordResetService.requestPasswordReset(email, options?)` fires `beforeSendCode` (`method: "password-reset"`, the new `SendCodeMethod`) with `options.captchaToken`, before the address is looked up, so `CaptchaPlugin`'s `"sendCode"` endpoint now guards password-reset requests too. `POST /password-resets` takes an optional `captchaToken` attribute and answers `400` when the captcha refuses, and the client's `passwordResetRequest` takes `captchaToken`. With the default endpoints, a client that sends no token on a password-reset request is now refused: pass one, or leave `"sendCode"` out of `endpoints`.
  
  `PasswordResetRequestForm` takes the `captchaToken` getter `MagicLinkForm` and `EmailOtpForm` take, and sends its token with the request.
- 67435fc: **Breaking:** the browser client, the session Atoms, the ladder and the Svelte binding answer "nothing" with `Option`.
  
  - `./client`: `getSession()` resolves `Option<SessionWithUserView>` (`None` on a `401`). `AuthClientOptions` and the send payloads spell their optional members `readonly x?: T`. The client now imports `effect/Option` at runtime, its only Effect module.
  - `./client/atoms`: `SessionResult` is an `AsyncResult<Option<SessionWithUserView>, AuthClientError>`; `data` and `error` (on the Atoms and on `SessionState` / `SessionListState`) are `Option`s. The cross-tab message carries no `data` key when signed out.
  - `./ladder`: `hasAtLeast` takes the holder as `Option<RungHolder>` (`Option.none()` is anonymous). The module imports `effect/Option`, and nothing else.
  - `effect-auth-svelte`: `$session.data` and `$sessions.data` are `Option`s, so templates unwrap them (`Option.isSome($session.data)`). `effect` is now a runtime peer (`effect/Option`). A form's `captchaToken` prop returns `Option<string>`, and its optional props are `readonly x?: T`.
- 8feb236: `SignInForm` and `EmailOtpForm` no longer call `onSuccess` when the server answers with a second-factor challenge (`202`), so `onSuccess={() => goto("/app")}` never navigates without a session. The challenge goes to the new `onSecondFactor` prop; the `SecondFactorChallenge` type is exported.

### Patch Changes

- cbbacba: Shorten each package README to what the package is, how to install it, one example, its entry points and links. The detail moved, unchanged, to guides under `docs/guides/` in the repository: getting started, authorization, sign-in methods, abuse protection, the HTTP API, storage, the browser client reference, SAML, testing, Drizzle, Svelte, SvelteKit, Alchemy and Argon2id.
- 5e2f119: Shorten the module doc comments to a few lines each. Consumer detail they held now sits on the export it describes: the `SamlVerifier` checks, what a `defineSchema` table must satisfy, and runnable examples on `Guard.requireSystem`, `OwnedAccess.make`, `Delivery`, `TrustedDevice`, `Messages`, `OrganizationEntities` and `RateLimitPersistence`.
- Updated dependencies [6c618f1]
- Updated dependencies [511357b]
- Updated dependencies [8c41d26]
- Updated dependencies [839deb6]
- Updated dependencies [d3afdec]
- Updated dependencies [aeaa5f0]
- Updated dependencies [afa3c31]
- Updated dependencies [70c2c8e]
- Updated dependencies [4c8b37c]
- Updated dependencies [9a79494]
- Updated dependencies [03f4aff]
- Updated dependencies [b5c935d]
- Updated dependencies [c9e519b]
- Updated dependencies [9b2c5ce]
- Updated dependencies [65bc383]
- Updated dependencies [f546e14]
- Updated dependencies [4189a4f]
- Updated dependencies [6ed0d73]
- Updated dependencies [7dd6f0d]
- Updated dependencies [390d0eb]
- Updated dependencies [5158442]
- Updated dependencies [bc22d09]
- Updated dependencies [c9e09af]
- Updated dependencies [934eebe]
- Updated dependencies [666cb31]
- Updated dependencies [342aa55]
- Updated dependencies [e0c9f41]
- Updated dependencies [c7998b9]
- Updated dependencies [8feb236]
- Updated dependencies [e9c5876]
- Updated dependencies [aa4e451]
- Updated dependencies [605f0fa]
- Updated dependencies [2d7dc18]
- Updated dependencies [692c5b6]
- Updated dependencies [bdda509]
- Updated dependencies [4da18de]
- Updated dependencies [c7f3e0b]
- Updated dependencies [9f9c278]
- Updated dependencies [9213fe2]
- Updated dependencies [8b47bd6]
- Updated dependencies [6fbfa58]
- Updated dependencies [67435fc]
- Updated dependencies [93a21c7]
- Updated dependencies [3aaae40]
- Updated dependencies [4db7b04]
- Updated dependencies [acf056e]
- Updated dependencies [c1e3933]
- Updated dependencies [2cbe703]
- Updated dependencies [4481724]
- Updated dependencies [e5e6c5c]
- Updated dependencies [87ce3d0]
- Updated dependencies [8c6a234]
- Updated dependencies [36828f4]
- Updated dependencies [9bb8e23]
- Updated dependencies [898eb41]
- Updated dependencies [8024bd1]
- Updated dependencies [c269ca8]
- Updated dependencies [7b2a431]
- Updated dependencies [e803edb]
- Updated dependencies [5854245]
- Updated dependencies [e5e7a09]
- Updated dependencies [d95f411]
- Updated dependencies [ce726c4]
- Updated dependencies [cbbacba]
- Updated dependencies [1bb5c77]
- Updated dependencies [05adb89]
- Updated dependencies [afa3c31]
- Updated dependencies [5e2f119]
- Updated dependencies [4148b2a]
- Updated dependencies [d863f61]
- Updated dependencies [e089e8c]
  - @thomasfosterau/effect-auth@0.9.0

## 0.2.5

### Patch Changes

- Updated dependencies [f3e1da7]
- Updated dependencies [7635b1e]
- Updated dependencies [3fa7b9a]
- Updated dependencies [7d4de4b]
  - @thomasfosterau/effect-auth@0.8.0

## 0.2.4

### Patch Changes

- Updated dependencies [db2a726]
- Updated dependencies [93a9153]
  - @thomasfosterau/effect-auth@0.7.0

## 0.2.3

### Patch Changes

- Updated dependencies [c5bf0f2]
- Updated dependencies [1704b6b]
- Updated dependencies [1a1bb2d]
- Updated dependencies [d8c7881]
- Updated dependencies [93c2ff0]
- Updated dependencies [167ef03]
- Updated dependencies [fa1eacb]
- Updated dependencies [a25f872]
  - @thomasfosterau/effect-auth@0.6.0

## 0.2.2

### Patch Changes

- Updated dependencies [efad4fb]
- Updated dependencies [c0f9b73]
- Updated dependencies [ca639d5]
- Updated dependencies [1f75f76]
- Updated dependencies [6f37516]
- Updated dependencies [05f7c10]
- Updated dependencies [90e1793]
  - @thomasfosterau/effect-auth@0.5.0

## 0.2.1

### Patch Changes

- Updated dependencies [2a2252c]
- Updated dependencies [6b7ffa8]
  - @thomasfosterau/effect-auth@0.4.0

## 0.2.0

### Minor Changes

- 7f3ab3d: The client session is now an `effect/reactivity` Atom graph (#206). **Breaking.**
  
  `@thomasfosterau/effect-auth`: the new `./client/atoms` subpath's `makeSessionAtoms(client, options?)` exposes the session read (`result`, an `AsyncResult`), its derived states (`state`, `data`, `isSignedIn`, `isPending`, `error`) and the signed-in user's session list (`sessions`, `sessionsState`) as Atoms, read through the application's own `AtomRegistry`. The semantics of the old store carry over: the read is lazy and starts pending, a `401` is `data: null`, a transient failure keeps the last session and sets `error`, a superseded refetch never lands, and session-changing calls refetch only while the session is observed, now resolving once that refetch has settled. A session change reaches every Atom that reads the session through the graph. `./client` itself still imports nothing at runtime: it drops its session store and instead announces session-changing calls through `client.onSessionChange(listener)` and `client.invalidateSession()`.
  
  `@thomasfosterau/effect-auth-svelte`: the stores are now adapters over those Atoms. `atomStore(registry, atom)` turns any Atom into a readable store; `sessionStore` and `listSessionsStore` take `(registry, atoms)`. `effect` is a new peer dependency, used for its types only. The form components are unchanged.
  
  Migration:
  
  - `client.session.subscribe(listener)` / `client.session.get()` → `const auth = makeSessionAtoms(client)` once, then `registry.subscribe(auth.state, listener, { immediate: true })` / `registry.get(auth.state)`. `SessionState` keeps its `{ data, isPending, error }` shape and moves to `./client/atoms`.
  - `client.session.refetch()` → `registry.refresh(auth.result)`, or `await client.invalidateSession()` to wait for it.
  - `createAuthClient({ refresh })` → `makeSessionAtoms(client, { refresh })`; `RefreshOptions` moves to `./client/atoms`.
  - `AuthClientPluginContext.session` is gone; `mutating` notifies the session observers instead.
  - Svelte: `sessionStore(client)` → `sessionStore(registry, auth)`, `listSessionsStore(client)` → `listSessionsStore(registry, auth)`. The session list now follows the session (empty, with no request, while signed out) and keeps its last data through a failed read.
  
  Server-side hydration of the session Atoms is not part of this release.
- 32ebf2d: `MagicLinkForm` and `EmailOtpForm` take a `captchaToken` getter (`SendCaptchaProps`), read when the form submits and sent with the code or link request (#698). Released together with the core's captcha on sends (#678), which `CaptchaPlugin` turns on by default: pass `captchaToken={() => widgetToken}` when the server's `CaptchaPlugin` guards sends.

### Patch Changes

- 9b63f86: **Security hardening (#631):** every adapter now depends on `@thomasfosterau/effect-auth` through a caret range (`^0.x.y`) instead of an exact pin. A consumer who upgrades the core within a minor (say, for a security patch) gets one copy of it, and no adapter keeps running a nested, unpatched core of its own. Under 0.x a caret range covers one minor, so the adapters are released with every core minor.
  
  **effect-auth-drizzle (#635):** the `drizzle-orm` peer range is bounded to the tested lines, `>=0.44.0 <0.46.0 || >=1.0.0-rc.5 <2`, and a new drizzle minor joins it once CI has run against it. The unused optional `@types/pg` peer is dropped.
- Updated dependencies [8d7fe03]
- Updated dependencies [c80f91c]
- Updated dependencies [fd32f3f]
- Updated dependencies [eafa773]
- Updated dependencies [701eebc]
- Updated dependencies [fe036f1]
- Updated dependencies [de98263]
- Updated dependencies [3829977]
- Updated dependencies [4037bcf]
- Updated dependencies [9598882]
- Updated dependencies [dd8715a]
- Updated dependencies [ea7f4ea]
- Updated dependencies [325f231]
- Updated dependencies [4649a7b]
- Updated dependencies [d66403e]
- Updated dependencies [f49ee5d]
- Updated dependencies [cf1e3c9]
- Updated dependencies [7a651a3]
- Updated dependencies [cc2bac6]
- Updated dependencies [1e7d8f4]
- Updated dependencies [8b65156]
- Updated dependencies [2096e2a]
- Updated dependencies [efba66d]
- Updated dependencies [7d9579e]
- Updated dependencies [4037bcf]
- Updated dependencies [e2ff7f7]
- Updated dependencies [6d33e11]
- Updated dependencies [b386606]
- Updated dependencies [32ebf2d]
- Updated dependencies [a2624ea]
- Updated dependencies [211f399]
- Updated dependencies [93685f4]
- Updated dependencies [f43b53d]
- Updated dependencies [7f3ab3d]
- Updated dependencies [68faced]
- Updated dependencies [b96f201]
- Updated dependencies [c50edb9]
- Updated dependencies [63e45ac]
- Updated dependencies [e57ea3c]
- Updated dependencies [e1770e3]
- Updated dependencies [88cd0a1]
  - @thomasfosterau/effect-auth@0.3.0

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
