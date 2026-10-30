# @thomasfosterau/effect-auth-client

## 0.2.0

### Minor Changes

- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).
- cc67083: Framework packages, form components, and adapter reworks.
  
  - Framework bindings moved out of the client into their own packages — `@thomasfosterau/effect-auth-react`, `-svelte`, `-vue`, and the new `-solid` — each with idiomatic authoring (React JSX, Svelte 5 runes `.svelte` components, Vue SFCs, Solid JSX with a `"solid"` export condition) and the same six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth-sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- 41ce19d: **Breaking (HTTP):** account management is JSON:API resources (#205). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.
  
  | Before                                         | Now                                                                                                                         |
  | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
  | `POST /change-password`                        | `PATCH /users/me/password` (a `user-passwords` document, id `me`): `204`                                                    |
  | `POST /change-email` · `/change-email/confirm` | `POST /email-changes` (`202`) · `POST /email-changes/redemptions` (the token, `204`)                                        |
  | `POST /delete-user` · `/delete-user/confirm`   | `POST /account-deletions` (`202`) · `POST /account-deletions/redemptions` (the token; `204`, the session cookies cleared)   |
  | `POST /multi-factor/enable`                    | `POST /multi-factor-enrollments`: `201`, the unverified enrolment with `meta.secret`, `meta.totpUri` and `meta.backupCodes` |
  | `POST /multi-factor/confirm`                   | `PATCH /multi-factor-enrollments/current` with the `code`: `200`, `verified: true`                                          |
  | `POST /multi-factor/disable`                   | `DELETE /multi-factor-enrollments/current` with the password in `meta`: `204`                                               |
  | `POST /multi-factor/regenerate-backup-codes`   | `POST /backup-code-sets`: `201`, the codes in `meta.backupCodes`                                                            |
  
  - The confirmation tokens travel in the request body, never in a URL.
  - effect-auth-client: `changePassword`, `changeEmail`, `deleteUser` and `multiFactor` keep their arguments and results and call the new endpoints.
- b1fbf57: **Breaking (HTTP):** the included HTTP API starts speaking JSON:API (#205). The session, identifier and own-profile endpoints are now JSON:API resources, answering `application/vnd.api+json` documents and JSON:API error documents:
  
  | Before                              | Now                                                  |
  | ----------------------------------- | ---------------------------------------------------- |
  | `GET /session`                      | `GET /sessions/current?include=user`                 |
  | `POST /sign-out`                    | `DELETE /sessions/current`                           |
  | `GET /sessions`                     | `GET /sessions` (a collection document)              |
  | `DELETE /sessions/:sessionId`       | `DELETE /sessions/:id`, `id` the listed (hashed) id  |
  | `POST /sessions/revoke-others`      | `DELETE /sessions?filter[current]=false`             |
  | `GET /identifiers`                  | `GET /identifiers` (the identifier's type is `kind`) |
  | `DELETE /identifiers/:identifierId` | `DELETE /identifiers/:id`                            |
  | `PATCH /user`                       | `PATCH /users/me` (a JSON:API update document)       |
  
  - A session is now revoked by the id `GET /sessions` lists (the hash of its token). Before, the endpoint took the raw token, so a listed session other than your own could not be revoked. `SessionService` gains `revokeSessionById(userId, storedSessionId)` for it.
  - A foreign or unknown session or identifier answers `404` (was `400`); removing an account's last identifier answers `403` (was `400`).
  - `PATCH /users/me` accepts only `name` and `image`; a write to the `attributes` bag is refused (`400`, #193).
  - `@thomasfosterau/effect-jsonapi` is an optional peer of effect-auth, needed only by the `./http` subpath. New in `./http`: `Http.Resources` (the resource declarations), `Http.JsonApiErrors` (the error documents), `Http.groupLayers` (every group plus the JSON:API middleware, for serving `AuthApi` from your own `HttpApiBuilder`; compose it in place of `authGroupLayer` + `scimGroupLayer`) and `Http.RemoteSession.fromSessionDocument`.
  - `RemoteSession` reads `GET /sessions/current?include=user`, so an app and its auth service must be on the same release.
  
  effect-auth-client keeps its method signatures and maps the documents onto the same view types. `revokeSession(id)` now takes the id `listSessions()` reports, and an error's `message` is read from a JSON:API error document's `detail`.
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
  - effect-auth-client: the sign-in, sign-up and verification methods keep their arguments and resolve with the new `AuthResult`, whose `user` is present only when a session was issued. `continueChallenge` takes an `AuthResult`. The framework bindings' form `AuthSuccess` type follows it.
  - effect-auth-sveltekit: `credentialAction` sends its body as `application/vnd.api+json` by default (`contentType` overrides it), so an action for `POST /sessions` posts a `sessions` document.
- 624a9b5: Organizations: member deactivation, verified domains, JIT provisioning, invitation resend, and a per-organization default role.
  
  - **Member status.** `Member.status` (`"active" | "inactive"`, absent means active) with
    `deactivateMember` / `reactivateMember` (`member:update`, `POST
    /organization/:organizationId/members/:userId/{deactivate,reactivate}`). An inactive member keeps
    its row, its team memberships and its role — parked in `previousRole` while the row is demoted to
    the organization's default role — and is treated as a non-member by every permission check,
    including the `OrganizationEntities` policy projection. Only an owner may deactivate an owner, and
    the last _active_ owner may not be deactivated or demoted. **Deliberate deviation from WorkOS:**
    application sessions are _not_ revoked, because a session is app-scoped while a membership is
    organization-scoped — signing a user out of every tenant because one deactivated them is the wrong
    default for a multi-tenant app. The new `onMemberDeactivated` config hook is where an app that
    wants WorkOS's behavior calls `invalidateUserSessions`.
  - **Organization domains.** New `OrganizationDomain` record and `OrganizationDomainStore` contract
    (43 store contracts now; `memoryOrganizationDomainStore` included), plus list/add/remove/verify
    endpoints under `/organization/:organizationId/domains`. Domains are globally unique — pending
    claims included, so verification order can never decide which tenant wins — writes need the new
    `domain:manage` permission (granted to `owner` and `admin` in `defaultOrganizationRoles`), and any
    member may list. DNS verification adds no dependency: implement the new `DomainVerifier` contract
    over your own resolver, or claim domains with the `"manual"` strategy and attest them through the
    verify endpoint. The DNS TXT token is generated server-side.
  - **JIT provisioning on SSO sign-in.** Opt-in per organization via `Organization.jitProvisioning`
    (default `false` — silent domain absorption is a consent surprise). After the shared SSO
    provisioning tail resolves the user, a verified email whose domain is a _verified_ claim of a
    JIT-enabled organization adds an active membership with that organization's default role. Failures
    are logged and swallowed: membership is fail-open, authentication never is.
  - **`resendInvitation`.** Same row and id, `expiresAt` pushed out by the configured TTL, delivery
    callback fired again; gated on `invitation:create` like inviting, and refused for unknown,
    accepted, rejected or canceled invitations. `POST /invitations/:invitationId/resend`.
  - **Per-organization default role.** `Organization.defaultRole` (default `"member"`), settable only
    by owners (`role:manage`, `PUT /organization/:organizationId/default-role`) and validated against
    the organization's role set. Used wherever a member is added without an explicit role: `addMember`
    (its `role` argument and the `AddMemberPayload` field are now optional), JIT provisioning, the SCIM
    provisioning path, and SSO first-login provisioning — the `ScimConfig.defaultRole` /
    `SsoConfig.defaultRole` options still win when set.
  
  The client gains `organization.{deactivateMember,reactivateMember,setDefaultRole,resendInvitation,listDomains,addDomain,verifyDomain,removeDomain}`;
  `OrganizationView` now carries `defaultRole` and `jitProvisioning`, and `MemberView` carries `status`
  and `previousRole`.
- ef58828: Publish testing fixture as a public entry point at `@thomasfosterau/effect-auth-client/testing`. The fixture provides a fully functional in-memory effect-auth server and cookie-jar fetch for end-to-end testing. This unblocks consumers who previously had to hand-roll their own test harness (see #180).
  
  Also adds `effect` to peerDependencies (range `>=4.0.0-rc.112`) since fixture.ts imports Effect's `Layer` and `Effect` utilities.

### Patch Changes

- ca3abfb: The `./testing` in-memory server's `createUser` seams resolve to core's `CreateUserResult`, `{ user, created: true }`, since each call inserts a new user (#406). No change to the fixture's own API.
- 7f5206e: The `./testing` in-memory server's feature set (`features: true`) includes an in-memory `RateLimiter`, because the core requires one for device authorization (`Http.make` throws `RateLimiterConfigError` without it, #389). Device approve and deny on the fixture are therefore rate limited as in production: 5 attempts per user code per 15 minutes, then `429`. No API change.
- 61847b0: Every exported symbol has a doc-comment summary that shows in editor hovers: the core's service classes (with the stores each one requires), configs and results, the `Condition` and `Policy` scope constructors, the `Observability` record helpers, the HTTP list views and error schemas, the SQL stores and their layers, drizzle's row types and every `databaseLayer` overload, and `AuthClientOptions`. `hashToken` carries its own doc comment, and the client module overview opens with its summary rather than a tag line.
  
  Doc comments on `SessionResolution.resolveFailOpen` and `resolveAtEdgeFailOpen` (`http/RemoteSession.ts`) point at `docs/ARCHITECTURE.md` for the fail-open precondition.
- 89802ec: Built and tested against Effect `4.0.0`. The `effect` peer floor is unchanged (`>=4.0.0-rc.118`), so consumers still on `4.0.0-rc.118` keep working; `@effect/*` companions such as `@effect/sql-pg` should match whichever `effect` you install.
- dcffe28: Internal refactor for the Effect lint presets, with these observable edges:
  
  - `SessionService.createSession` / `setSessionAttributes`, `UserService.updateUserAttributes`, the `Username` sign-up and sign-in inputs and `ScimUserStore.create` take `Types.Attributes` (the readonly form of `Record<string, unknown>`); existing callers still type-check.
  - OAuth userinfo, OIDC discovery, JWKS and id_token segments that are not JSON objects now fail with `OAuthProviderError`, and a malformed JWKS document fails with `JwtError("Failed to fetch JWKS")`, instead of a defect or a confusing later error.
  - A CAPTCHA verification body of `null` now counts as a failed verification (`CaptchaError`) instead of a defect.
  - The sql stores decode their JSON columns with Schema, so a malformed stored value fails with the same `AuthError` instead of passing through unchecked; `readRbacPolicies` (drizzle) may return policies in a different order (decisions are unchanged).
  - Several thrown plain `Error`s (invalid header names, reserved principal types, malformed permissions, OTP URI and COSE key errors, session-cache config) are now tagged error classes with the same message; they are still `Error` instances.
  - resend and twilio wrap a failed non-2xx body read in a private tagged defect; saml reads non-object attribute bags as empty.
  - Effect handlers that became `Effect.fn` (auth middleware schemes, `requireScim`, JWT key rotation, decoy hashing) now emit a tracing span.
- 78dac5f: Widen the optional option fields to `?: T | undefined` so callers under `exactOptionalPropertyTypes` can forward their own optional values: `AuthClientOptions` (`fetch`, `headers`, `refresh`) and `RefreshOptions` (`intervalMs`, `onFocus`, `crossTab`) in the client, and the `render` / `baseUrl` / `fetch` fields of `ResendEmailSenderConfig` and `TwilioSmsSenderConfig`.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- d2d8163: `RateLimiter.consumeToken` now decides from the count `RateLimitStore.increment` returns instead of a count it read before incrementing, so concurrent requests at the limit no longer all pass, and concurrent first requests in a window no longer overwrite each other's count (#455). It also checks a block before the window, so a `blockDurationMs` longer than `windowMs` is no longer lifted when the window expires.
  
  **Breaking: the `RateLimitStore.increment` contract is now stated and relied on.** It must start a new window (count 1, `resetAt` `ttl` seconds away) when the key has no entry or its window has expired, and return the new count atomically. effect-auth-sql's store and the `KeyValueStore`-backed store already do. A custom store whose `increment` only bumps an existing entry (relying on `consumeToken` to `set` a new window) must be updated, or `consumeToken` never refuses. The client's in-memory testing fixture is updated to match.
  
  **Breaking: `RateLimitError.retryAfter` is now an `effect/Duration`** instead of a bare number, which was seconds from `RateLimiter.make()` but milliseconds from `rateLimiterPersistenceLayer`. Both now report the same `Duration`. Read it with `Duration.toMillis` / `Duration.toSeconds`. The HTTP IP rate limit (`ipRateLimit`) sends it as a `Retry-After` header in whole seconds, rounded up, and keeps the 429 body's `retryAfter` as the same whole seconds.
- 5ab875a: The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
- a517a32: **Security — verifying an address no longer hands the verifier an account whose password someone else chose (#425).** The first time `AuthLifecycleService.verifyEmail` verifies an address (`POST /email-verification/verify`), it clears the account's password and revokes all of its sessions before marking the address verified. Until then no one had proven they own the address, so an attacker could sign up with a victim's address and a password they know, and the victim's later verification (from the attacker's sign-up email, a re-send, or the victim's own recovered sign-up) left the attacker able to sign in. The verifier now sets a password afterwards, with `EmailPasswordService.setPassword` from the session the verification issues (with `autoSignInAfterVerification`, the default) or through a password reset. Verifying an address already verified changes neither.
  
  This applies to every first verification, the account's real owner included: after verifying, a user who signed up with a password has none until they set one, and any session they held before verifying is signed out.
  
  **Breaking — `EmailPasswordStore` gains a required `clearPasswordHash(userId)`**, which removes the user's password so `getPasswordHash` returns `null` (a no-op when there is none). `EmailPasswordService` gains `clearPassword(userId)` over it. effect-auth-sql's `EmailPasswordStore` implements it (`password_hash = NULL`); the effect-auth-client `./testing` server implements it in memory.
  
  **The recovered sign-up acts on the address the `beforeSignUp` hooks returned (#426).** With `antiEnumeration` off, a sign-up for an address held unverified looks the holder up by the address `EmailPasswordService.signUp` found taken, not the raw submitted one, and answers with that address as its `identifier`. `EmailInUseError` carries that address as an optional `email` (never sent over HTTP); `AccountManagementService`'s change-email sets it too.
- 50a4084: **Breaking:** the package root no longer re-exports the HTTP tier as the `Http` namespace (#205). Importing `@thomasfosterau/effect-auth` for the headless core (sessions, users, stores, the authorization kernel) no longer pulls `effect/http-api` into your module graph; `ModuleGraph.test.ts` now asserts that.
  
  The HTTP tier is unchanged and lives on the `./http` subpath. Migrate by importing it from there:
  
  ```ts
  // before
  import * as Auth from "@thomasfosterau/effect-auth";
  const { handler } = Auth.Http.make({ services });
  
  // after
  import * as Http from "@thomasfosterau/effect-auth/http";
  const { handler } = Http.make({ services });
  ```
  
  `import { Http } from "@thomasfosterau/effect-auth"` becomes `import * as Http from "@thomasfosterau/effect-auth/http"`, and `import type { Http }` becomes `import type * as Http from "@thomasfosterau/effect-auth/http"`. Every name keeps its identity: `Http.ClientAddressConfigError`, `Http.ServicesBuildPendingError` and the rest are the same classes the root exports flat.
  
  `effect-auth-client` now imports its wire types from `@thomasfosterau/effect-auth/http`; its own API is unchanged.
- Updated dependencies [84c9180]
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [29d011c]
- Updated dependencies [afd57ae]
- Updated dependencies [20cde53]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [aa7b6e6]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [dcffe28]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [42d0f03]
- Updated dependencies [b165354]
- Updated dependencies [fa438cf]
- Updated dependencies [5ab2078]
- Updated dependencies [9ff7ded]
- Updated dependencies [41ce19d]
- Updated dependencies [b1fbf57]
- Updated dependencies [ce56aeb]
- Updated dependencies [e03530e]
- Updated dependencies [4c70cd2]
- Updated dependencies [c1ba5f6]
- Updated dependencies [02df078]
- Updated dependencies [2484af6]
- Updated dependencies [6bee50c]
- Updated dependencies [90d7a79]
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
- Updated dependencies [624f356]
- Updated dependencies [00aa6e9]
- Updated dependencies [d2d8163]
- Updated dependencies [8235dad]
- Updated dependencies [5a48055]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
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
- Updated dependencies [a3131b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [03a3219]
- Updated dependencies [f7bafc0]
- Updated dependencies [c092987]
- Updated dependencies [ef0207d]
- Updated dependencies [bfa558e]
- Updated dependencies [3875062]
- Updated dependencies [1031ed5]
- Updated dependencies [5ab2078]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.2.0
