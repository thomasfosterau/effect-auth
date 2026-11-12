# @thomasfosterau/effect-auth

## 0.5.0

### Minor Changes

- efad4fb: Resolve an API key over the HTTP tier and across a service binding (#730).
  
  - **New endpoint, `GET /api-keys/current`.** It is JSON:API and mounted with the `api-keys` group; without an `ApiKeyService` it answers `404`.
    - It reads the key from an API-key header, never from the URL: `cookie.apiKeyHeaders` on `Http.make`, default `x-api-key`.
    - It verifies the key with `ApiKeyService.verifyWithRateLimit` and no required permissions.
    - It answers the `api-keys` resource, never its hash or plaintext, with its `user` in `included` and `Cache-Control: no-store`.
    - The key wins over any cookie or bearer token on the request.
    - An unknown, disabled, expired or exhausted key gets one identical `401`, and the reason is logged server-side only.
    - Only a real key over its own `rateLimit` gets `429` with `Retry-After`.
  - **Each resolution consumes one use of the key**: `remaining` decrements and `lastUsedAt` moves. A non-consuming check is #645.
  - **New default rate-limit rule.** `defaultEndpointRules` gains one for the endpoint: 300 requests a minute per client address, then a 5-minute block.
    - It counts every request before the key is read, refused and resolved ones alike.
    - A request it refuses spends no use of the key.
    - Override it with a rule ahead of `...defaultEndpointRules`; the first match wins.
  - **Behaviour change in `RemoteSession`.** `resolveAtEdge` and `resolveAtEdgeFailOpen` now resolve a request that carries an API key through `GET /api-keys/current`, to `{ session: None, user, apiKey, credentialClass: "machine" }`.
    - The cookie is not forwarded on that call.
    - A request carrying a key **and** a session cookie or bearer token used to resolve through the cookie or token. It now resolves the key.
    - If the auth service has no `ApiKeyService`, that call answers `404`. `resolveAtEdge` then fails closed with a `RemoteSessionError` (`status: 404`), and `resolveAtEdgeFailOpen` degrades to anonymous. Neither falls back to the cookie.
    - A key over its own per-key limit reaches the edge as a `RemoteSessionError` with `status: 429`: `resolveAtEdge` fails with it, and `resolveAtEdgeFailOpen` degrades to anonymous.
    - New API: `RemoteSessionResult.user` / `apiKey`, a `RemoteApiKey` type, `RemoteSessionClient.readApiKey` and `fromApiKeyDocument`.
  - **Fix in `ApiKeyService.verifyWithRateLimit`.** It now runs the enabled, expiry, remaining-uses and permission checks before it consumes the key's per-key rate-limit token.
    - A disabled, expired, exhausted or under-permitted key is refused with that reason even when it is over its limit. It used to be refused as `Rate limit exceeded`, which told a revoked-but-real key apart from an unknown one.
    - A refused attempt no longer spends a token from the key's bucket.
  - **A banned or SCIM-deactivated owner's key is refused (#755, in part).** `ApiKeyService.verify` and `verifyWithRateLimit` answer `Invalid API key` (`reason: "invalid"`) for a key whose owner is currently banned (`isBanned`: `banned`, an unlapsed `banExpires`) or SCIM-deactivated (`isScimDeactivated`), as they already did for an owner that no longer exists (#601).
    - It is decided at lookup, before the per-key limit and before a use is spent. So such a key gets the unknown-key `401` from `GET /api-keys/current` whether or not it is over its limit, and a refused call spends neither a use nor a bucket token.
    - `isBanned`, `isScimDeactivated` and `SCIM_DEACTIVATED_ATTRIBUTE` now live in a new internal `UserStanding.ts` and are re-exported, unchanged, from `Admin.ts`, `Scim.ts` and the root.
  - **Type narrowing in `ApiKeyService.verifyWithRateLimit`.** It now declares `R = never` instead of `RateLimitStore`, as every service method does; it never read the store from its context.
    - Callers keep compiling.
    - It breaks only a hand-written `ApiKeyService` implementation whose `verifyWithRateLimit` requires `RateLimitStore`.
  - **Smaller additions:**
    - `ApiKeyVerifyResult` gains `reason` (`ApiKeyRefusal`) and, for `rate-limited`, `retryAfter`.
    - `SessionResolution.ResolveWithOptions` gains an optional `resolved` predicate.
    - `./client/testing`'s `makeServerFixture` gains `apiKeys`, `layer`, `cookie` and `rateLimitStore` options, and returns `apiKeyRecords`.
    - `Http.ResolvedCookieConfig` (exported, marked internal) gains a required `apiKeyHeaders` field. `resolveCookieConfig` fills it in; only a hand-built value of the type needs it added.
- c0f9b73: Bounded purges for a cron with a CPU budget (#729). `@thomasfosterau/effect-auth/sql` adds `purgeExpiredWith({ limit })`: `purgeExpired` with each table's `DELETE` capped at `limit` rows (magic links, email OTPs and rate-limit rows alike), reporting the counts so a caller can loop until they are `0`. `RateLimitStore.purgeExpired(tables, { limit })` in `@thomasfosterau/effect-auth-drizzle` caps its `DELETE` the same way on PostgreSQL, SQLite and MySQL (through a derived table, which MySQL accepts inside `IN`) and still returns nothing. Omitting `limit` keeps the unbounded purge; a `limit` that is not a positive integer fails with `AuthError`.
- ca639d5: Deleting a user now deletes everything the account holds (#601). `AccountManagementService.confirmAccountDeletion`, `AdminService.removeUser`, `AnonymousService.linkAccount` and `UserService.deleteUser` run one purge: every user-keyed credential and token store present where the service's layer is built deletes that user's rows (OAuth links and their provider tokens, passkeys, API keys, the TOTP enrolment and backup codes, trusted devices, OIDC-provider tokens and consents, pending password resets, email verifications and account-management tokens), the unspent magic links and email / phone one-time codes sent to the user's addresses are deleted (keyed by address, they would otherwise sign their holder into the next account to claim it), then the sessions are revoked, then the identifiers are deleted (`removeUser` used to leave them, so the address stayed claimed; it can now sign up again), and the user row goes last, so a failure leaves the user rather than rows naming a missing one. No foreign keys are added; wrap the call in your stores' transaction (`sql.withTransaction` on `./sql`) to make it atomic. `ApiKeyService.verify` and `verifyWithRateLimit` now answer `Invalid API key` for a key whose owner no longer exists.
  
  Breaking for bring-your-own stores and for layer wiring:
  
  - `ApiKeyStore`, `OAuthAccountStore`, `MultiFactor.CredentialStore` and `OidcConsentStore` gain a required `deleteByUserId(userId)`, which deletes that user's rows only (a no-op for a user with none). `MultiFactorStore.delete(userId)` is its per-user delete, unchanged.
  - **`ApiKeyService` now requires `UserStore`** in its layer's context (it reads the key's owner on every verify). `Testing.apiKeyServiceLayer` takes `users` (seed the owners of the keys a test verifies) and provides `UserStore`.
  - **`UserService.deleteUser` now deletes the whole account**, through the new `AccountDeletion` service: provide `accountDeletionLayer` (it needs `UserServiceStore`, `IdentifierStore` and `SessionService`, and clears whichever credential stores are in its context) where `UserService` is built. Without it, `deleteUser` fails with `AuthError` and deletes nothing; it no longer deletes the user row alone.
  - `./sql`: `UserServiceStore.delete` also deletes the user's `auth_user_roles` rows, in one transaction; the API key, OAuth account and passkey stores implement `deleteByUserId`.
  - `./testing`: `memoryStores` also provides `UserServiceStore`, `CredentialStore` and `AccountManagementStore` (`memoryUserServiceStore`, `memoryCredentialStore`, `memoryAccountManagementStore`), and new conformance suites check every per-user delete: `oauthAccountStoreConformance`, `credentialStoreConformance`, `multiFactorStoreConformance`, `trustedDeviceStoreConformance`, `oidcTokenStoreConformance`, `oidcConsentStoreConformance`, `emailVerificationStoreConformance`, `passwordResetStoreConformance`, `accountManagementStoreConformance`, and a case in `apiKeyStoreConformance`.
  
  `@thomasfosterau/effect-auth-drizzle`: `ApiKeyStore` implements `deleteByUserId` (one `DELETE`), as the core contract now requires.
- 6f37516: `redeemOneTimeTokenForSession` now refuses a token whose subject `UserStore` no longer finds (a deleted user), with the same `OneTimeTokenError` as an unknown token, instead of minting a session for it; it therefore requires `UserStore` (which `SessionService.layer` already needs). The "Deleting a user" README section now lists one-time tokens and by-email organization invitations among the records left to expire, and says what happens to a store missing from the deleting layer's context and to a deletion that fails after the identifiers are gone (#601).

### Patch Changes

- 1f75f76: Every response carrying `Set-Cookie` is now sent with `Cache-Control: no-store` (#628), whether `Http.make` serves it or `Http.RemoteSession.relayResponse` / `withSetCookie` relays it: sign-in, sign-up, sign-out and the other cookie-clearing answers, and the `GET /sessions/current` that refreshes the session-data cache cookie. An existing `Cache-Control` with `no-store` is kept; one without it keeps its directives and gets `no-store` appended. The responses that hand a credential over without a cookie are `no-store` too: `GET /sessions/:id`, `POST /tokens`, `POST /api-keys`, `POST /oauth-clients`, `POST /multi-factor-enrollments`, `POST /backup-code-sets`, `POST /device/token`, `POST /oauth2/token`, `GET /oauth2/userinfo` and `POST /register`.
- 05f7c10: `Http.RemoteSession`: a first sign-in through `relay` now signs the browser in (#619). `relayResponse` (and `relay`, which applies it) used to pass `Set-Cookie` on only when the inbound request already carried a session or cache cookie, so a browser signing in for the first time got a `201` with its session cookie stripped and the new session orphaned. `Set-Cookie` is now relayed to every caller without a machine credential: a request with no credential at all, or with a session cookie only. It is still stripped when the inbound request carries an API key or an `Authorization: Bearer` token, alone or beside a session cookie, since such a caller authenticates with that key or token and a cookie would only plant session state in whatever jar its HTTP client keeps; a bearer client gets its token through `bearerMode`'s `set-auth-token` header. A request carrying a session cookie and a bearer token, which previously received `Set-Cookie`, no longer does.
- 90e1793: The core's crypto now runs on Cloudflare Workers (#748). Workers apps gain working JWTs and OIDC: ES256, `JwtService`'s default, failed to sign and verify on every compatibility date (workerd's `node:crypto` rejects a `KeyObject` beside `dsaEncoding` with `ERR_INVALID_ARG_TYPE`), which broke `JwtService`, the OIDC provider's `id_token`s, ES256 `id_token` verification in `OAuthService` and `appleClientSecret`; `signJws` and `verifyJws` now pass the PEM or the JWK instead, and sign and verify exactly as before on Node (the same tokens, the same refusals). `generateJwsKeyPair`, and so `JwtService`'s first key, failed from compatibility date 2025-12-03, where workerd's JWK export carries absent members as `undefined`; those are dropped. Apps on a compatibility date before 2024-09-23 also gain the default PBKDF2 and scrypt password hashers, AES-256-GCM (`aes256GcmCipher`, the session cookie cache) and the WebAuthn signature checks, which read the `Buffer` global that `nodejs_compat` sets only from that date and now import it from `node:buffer`. The README's new Runtimes section states the supported floor: `nodejs_compat` and a compatibility date of 2023-01-01 or later, tested inside a real workerd.

## 0.4.0

### Minor Changes

- 2a2252c: The optional peer `@thomasfosterau/effect-jsonapi` moves to `^0.22.0` (was `^0.21.0`), so an application on effect-jsonapi 0.22 no longer gets a peer mismatch (#723). It is still needed only by `./http` (and `./client/testing` through it); `./http` now requires 0.22, so an application on 0.21 upgrades effect-jsonapi with this release. effect-jsonapi 0.22 itself requires `effect ^4.1.0`, the floor effect-auth already declares.
  
  What a consumer of the HTTP API sees:
  
  - A `400` the JSON:API tier answers for a request it could not decode (a malformed query or body, answered by effect-jsonapi's `SchemaErrors` middleware) no longer repeats its `detail` in `meta`: the error object is `{ status: "400", code: "bad_request", title: "Bad Request", detail: "Request query failed validation" }`, without `meta: { detail: … }`. Read `errors[].detail`, which was already there.
  - Every other effect-auth error body is unchanged: the JSON:API errors keep `detail` and `meta: { message, code? }`, and the `406` / `415` content-negotiation errors keep the codes `not_acceptable` / `unsupported_media_type` they already carried.
- 6b7ffa8: **Security hardening (#718):** a record looked up by its id no longer reveals that it exists before the permission check. Before, an unknown id answered differently from another tenant's record, so a caller holding a foreign id could confirm it was real, and a stranger could learn whether an invitation was still pending.
  
  - `PATCH` / `DELETE /organization-members/:id`, `GET /organization-members/:id/teams`, `DELETE /organization-domains/:id`, `POST /organization-domains/:id/verifications`, `PATCH` / `DELETE /organization-roles/:id` and `DELETE /team-members/:id` answer an unknown id with the same `403` and body as another tenant's record and a member without the permission: `Missing permission '<permission>' in this organization` (`member:update`, `member:delete`, `domain:manage`, `role:manage`, `team:manage-members`), or `You are not a member of this organization` for a membership's teams, which any member may read. An unknown id no longer answers `404`. The operator's `DELETE /admin/organization-domains/:id` still answers an unknown id `404`, after the admin check.
  - The team operations (`updateTeam`, `deleteTeam`, `addTeamMember`, `removeTeamMember`, and so `PATCH` / `DELETE /teams/:id` and `POST /teams/:id/members`) refuse an unknown team with the `Missing permission` error a stranger gets, and `listTeamMembers` (`GET /teams/:id/members`) with the `You are not a member` one, instead of `Team not found`.
  - `cancelInvitation` and `resendInvitation` (`PATCH /invitations/:id` to `canceled`, `POST /invitations/:id/deliveries`) check `invitation:cancel` / `invitation:create` first: an unknown id, a stranger and a member without the permission get the same `Missing permission` error and `403`, whatever the invitation's status, instead of `Invitation not found` or `Invitation is no longer pending`. A permitted member still gets `Invitation is no longer pending` for one that is not.
  
  No public signature changes; the `404` and the `not found` messages these routes documented do.

## 0.3.0

### Minor Changes

- 8d7fe03: **Security fix (#678):** an account lock no longer blocks magic-link and one-time-code recovery, the captcha now guards the code and link sends, unknown challenges and tokens count against the per-IP limit, passkey sign-in and `EmailOtpService.check` run the `beforeAuthenticate` gate, and an admin impersonation no longer clears the target's lockout.
  
  - **Lock scope.** `AccountLockoutPlugin` exempts the possession proofs (email OTP, phone OTP, magic link; `isPossessionMethod`) from its account lock: it neither refuses them nor counts them. Before, anyone who knew a handle could lock its owner out of passwordless recovery for `lockoutDurationMs`. Their guesses stay bounded by the per-code `maxAttempts`, the per-address failure backoff (#590), 256-bit magic-link tokens and the rate limits. A session one of them issues clears the lock, as any session the user earns does.
  - **Captcha on sends.** A new hook point, `beforeSendCode` (`SendCodeAttempt`: `{ method, purpose, address, captchaToken? }`), runs at the start of `EmailOtpService.send`, `PhoneOtpService.send` and `MagicLinkService.send`, before the address is looked up. Each send takes `SendCodeOptions` (`{ captchaToken? }`) as a new last argument; `POST /otp-challenges` takes a `captchaToken` attribute on every channel and answers `400` when the captcha refuses; the client's `magicLink.send`, `emailOtp.send` and `phoneOtp.send` take `captchaToken`. `CaptchaPlugin` has a new `"sendCode"` endpoint, which guards that hook.
  - **Unkeyed attempts.** An unknown or expired second-factor challenge (TOTP, backup code, OTP second factor), magic-link token or passkey challenge, and an unknown passkey credential, now fire `beforeAuthenticate` with no `identifier` before failing, so `IPRateLimitPlugin` counts them. The per-account plugins let such an attempt through.
  - **Coverage.** `EmailOtpService.check` (every purpose, method `"email-otp"`) and `WebAuthnService.verifyAuthentication` (new method `"passkey"`, keyed on the credential's user, before the signature is checked) fire `beforeAuthenticate`.
  - **Impersonation.** `AccountLockoutPlugin` leaves the counts standing when `AdminService.impersonateUser` issues a session; a new `isImpersonationSession(session)` names such a session (`attributes.impersonatedBy`).
  
  **Breaking:**
  
  - `CaptchaPlugin`'s default `endpoints` is now `["signUp", "signIn", "sendCode"]`: with the defaults, every code and link send needs a `captchaToken` that verifies. Pass `endpoints: ["signUp", "signIn"]` to keep the sends unguarded.
  - `AuthenticateAttempt.identifier` is optional (absent for an unkeyed attempt), and `authenticationSubject` returns `string | undefined`. A custom `beforeAuthenticate` plugin that reads either must handle the unkeyed case.
  - `AuthenticationMethod` adds `"passkey"`. A plugin that matches on the method exhaustively must handle it.
  - `WebAuthnService.layer` / `make` require `Hooks` (provide `Hooks.Default` for no plugins), and `verifyAuthentication` can fail with a `HookError`.
  - `EmailOtpService.check` and the three sends can fail with a `HookError`, and a hand-written `Hooks` implementation needs `beforeSendCode`.
  - `AccountLockoutPlugin` no longer locks out or counts email OTP, phone OTP and magic-link attempts.
- c80f91c: **Security fix (#592):** username, email OTP, phone OTP, magic-link and second-factor sign-ins now run the lockout, captcha and rate-limit plugins, and account lockout clears only when a session is issued. Before, only email-and-password sign-in fired `beforeSignIn`, the hook those plugins guarded, so `UsernameService.signIn` (and `POST /sessions` with `method: "username"`) could guess a password with no lockout, per-account limit, per-IP limit or captcha; and a correct password that earned only a second-factor challenge reset the lockout counter, so an attacker holding the password could guess TOTP codes without ever being locked out.
  
  A new hook point, `beforeAuthenticate`, runs in every credential-verifying flow (email and password, username, email OTP, phone OTP, magic link, and the TOTP, backup-code and OTP second factors), after the handle is resolved to a user and before the credential is checked or a code, link or challenge is spent. Its input is `AuthenticateAttempt`: `{ method, identifier: { type, value }, userId?, captchaToken? }`. `authenticationSubject(attempt)` gives the per-account key: `user:<id>` for a resolved handle, else `<type>:<value>`. `beforeSignIn` stays, for rewriting an email-and-password sign-in's input.
  
  **Breaking:**
  
  - `AccountLockoutPlugin`, `CaptchaPlugin`, `RateLimitPlugin` and `IPRateLimitPlugin` hook `beforeAuthenticate` instead of `beforeSignIn`. A test or a custom flow that drove them through `hooks.beforeSignIn` must call `hooks.beforeAuthenticate`.
  - `AccountLockoutPlugin` keys its counters on the account (`lockout:user:<id>`, or `lockout:<type>:<value>` for a handle no account holds) instead of the email (`lockout:<email>`), so counts stored under the old keys are ignored and lapse. It clears them in `afterCreateSession` (any session issued for the user) instead of `afterSignIn`, and no longer on a sign-in that returned only a second-factor challenge. A lock now refuses every method of the account, a magic link and a one-time code included. A new per-user second-factor count (`lockout:second-factor:user:<id>`, `maxSecondFactorAttempts`, default 5) runs across challenges and refuses second-factor redemption with `AccountLockedError` while locked.
  - `RateLimitPlugin` keys its bucket on `signin:<subject>` instead of `signin:<email>`, and draws second-factor redemptions from `second-factor:<subject>` under `RateLimitPresets.totpVerification`.
  - `IPRateLimitPlugin`'s `signin` bucket now counts every first-factor method, and second-factor redemptions draw on a new `second-factor` bucket (`secondFactor` option, default `RateLimitPresets.totpVerification`). Without a client address, these flows are refused with `RateLimitError` too.
  - `CaptchaPlugin`'s `"signIn"` endpoint also guards username sign-in, which now needs a token: `UsernameSignInInput.captchaToken`, the `captchaToken` attribute on the `username` sign-in credential and `UsernameSignInPayload`, and `captchaToken` on the client's `signInUsername`.
  - `EmailOtpService`, `PhoneOtpService`, `MagicLinkService`, `MultiFactorService` and `OtpSecondFactorService` now require `Hooks` when their layers are built.
  - The `Hooks` service has a new member, `beforeAuthenticate`: a hand-written `typeof Hooks.Service` implementation must add it.
- fd32f3f: **Security — an organization can no longer self-attest an email domain, and a domain claim no longer reveals or blocks another tenant's (#598).** Any user could create an organization, claim someone else's domain with the `manual` strategy and call `verifyDomain`: holding `domain:manage` was the whole attestation. The claim was then `verified`, so with `jitProvisioning` on, every SSO user at that domain joined the attacker's organization. Because claims were globally unique, the real owner could never claim the domain, and the refusal ("already claimed by another organization") confirmed other tenants' claims.
  
  Now a tenant proves a domain only through DNS, and manual attestation is the application operator's:
  
  - `OrganizationService.addDomain` always makes a `dns` claim with a server-minted token. `AddOrganizationDomainInput` loses `verificationStrategy`, and over HTTP `POST /organizations/:id/domains` answers `400` to `verificationStrategy: "manual"` (`"dns"` is still accepted). The `organization-domains` resource's `createInput` no longer has the attribute.
  - `verifyDomain` runs only the `DomainVerifier` check. It refuses an unverified `manual` claim, and a passed check while another organization holds the domain verified.
  - New `OrganizationService.attestDomain(organizationId, domain)`: a server-side call, with no actor, that the operator makes after checking ownership out of band. It attests the organization's existing claim in place (same id, DNS token dropped) or creates one, `verified` with the `manual` strategy. The platform-admin endpoint is `POST /admin/organization-domains` (the domain as an attribute, the organization as the `organization` relationship), gated on the server's `isAdmin` like SSO connection registration, never on an organization permission: `201` with the claim, `400` on a refusal. The browser client gains `admin.attestDomain({ organizationId, domain })`, typed with the new `Http.AdminAttestDomainPayload`.
  - Claims are unique per organization and domain, not globally. Several organizations may hold pending claims on one domain, each with its own token, and at most one claim per domain is `verified`. `addDomain` consults only the organization's own claims, so it no longer reveals another tenant's claim, and a pending claim cannot squat a domain.
  - **Store contract:** `OrganizationDomainStore.getByDomain` is replaced by `getVerifiedByDomain(domain)`, which answers only the `verified` claim on the domain (or `null`). JIT provisioning reads it.
  
  Migration:
  
  - Replace `getByDomain` in your `OrganizationDomainStore` with `getVerifiedByDomain`, filtering on `verificationState = 'verified'`. Replace a unique index on `domain` with one on `(organization_id, domain)`, plus, where your database has partial indexes, a unique index on `domain` over the verified rows.
  - Drop `verificationStrategy` from `addDomain` calls. A tenant that cannot publish a DNS record asks the operator, who calls `attestDomain` (or `POST /admin/organization-domains`).
- eafa773: **Security — every platform-admin HTTP endpoint now honours a custom `AdminConfig`, and the operator can release and audit domain claims (#680).** The OAuth-client, SSO-provider and domain-attestation endpoints checked only the default admin rule (role `admin`), not the `AdminConfig` given to `AdminService.layer`. A deployment that moved its admins to another role (`adminRoles: ["operator"]`) or to `adminUserIds` locked its real admins out of those endpoints, and left every user with role `admin` able to register OAuth clients and SSO connections and attest domains.
  
  - **Breaking:** the admin gate behind `/oauth-clients`, `POST /sso-providers` and `/admin/organization-domains` now asks the mounted `AdminService`, through its new `isAdmin(user)` method, the same rule `/admin/users` applies. Without an `AdminService` it still falls back to the default `isAdmin` (role `admin`). A role-`admin` user that the configuration does not name is now refused with `403`.
  - New `OrganizationService.releaseDomain(organizationId, domain)`: the operator's server-side release of an organization's claim, whatever its state, to settle a dispute. It answers the released claim, and refuses an unknown organization, an invalid domain or a domain the organization holds no claim on. The platform-admin endpoint is `DELETE /admin/organization-domains/:id` (`204`, `404` for an id that names no claim), gated like the attestation. The browser client gains `admin.releaseDomain(domainId)`.
  - Attestation audit trail: `OrganizationDomain` gains `attestedBy`, the attester `attestDomain(organizationId, domain, { attestedBy })` records (new `AttestDomainOptions`). `POST /admin/organization-domains` passes the admin's user id. On the wire it is the `organization-domains` resource's `attester` relationship (to `users`, `null` when nobody is recorded), and `Http.OrganizationDomainView` gains `attestedBy`. `verifiedAt` is the attestation time. A repeated attestation leaves the claim, and its attester, unchanged.
- 701eebc: Security hardening (#661): an empty entity id names no entity, so it never matches. Before, `Entity.ref("User", "")` was an ordinary principal. An owner permit (`resource.owner == principal`) granted it every row whose owner was `""`, in `Policy.decidePure` and in `ReadScope.compile` alike, so an integrator that used the empty id as a "no user" stand-in granted those rows to signed-out callers.
  
  - **Decoding:** `Entity.EntityRef`'s `id` is now `Schema.NonEmptyString` (breaking). A stored policy, a request or a logged slice that names `""` fails to decode.
  - **Decisions:** `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or resource has an empty id before any policy runs, custom predicates included. `Policy.Decision["reason"]` gains `"invalid-request"` (breaking for exhaustive matches), and `Policy.enforce` and the HTTP `Forbidden` carry it. `Policy.isWellFormed(request)` is the check.
  - **Read scopes:** `ReadScope.compile` returns `ReadScope.deny` for an empty-id principal or action. An empty-id entity value never compiles to an `Eq` atom, so a scope never admits an empty owner column for it.
  - **Equality:** `Entity.refEquals`, `Entity.attributeValueEquals` and `Entity.entityIn` are `false` whenever a side has an empty id, at any depth and even against itself. `Entity.namesEntity(ref)` is the new predicate. `Entity.ref` stays total.
  - **Guards:** `Guard.make` reads a viewer whose `id` is empty as anonymous. `OwnedAccess` and `ReferenceAccess` follow, so `canView` admits only public rows and `readScope` is `public`.
  
  Migration: don't use an empty id for a signed-out caller. Give it a principal of its own type, such as `Anonymous::"anonymous"`, which user-typed policies never match. Handle `"invalid-request"` wherever you switch on `Decision.reason`.
- fe036f1: Security hardening (#666): an empty entity type names no entity, so it never matches, as an empty id already does (#661). Before, `Entity.ref("", "u1")` was an ordinary reference: it decoded, it equalled itself, a permit scoped to `Policy.isType("")` matched it, and an owner permit over an attribute bound to the type `""` compiled to an owner filter.
  
  - **Decoding:** `Entity.EntityRef`'s `type` is now `Schema.NonEmptyString` (breaking). A stored policy, a request or a logged slice that names an entity of type `""` fails to decode.
  - **Decisions:** `Policy.decidePure` and `Policy.decide` deny a request whose principal, action or resource has an empty type with reason `"invalid-request"`, before any policy runs, custom predicates included. `Policy.isWellFormed` checks the type as well as the id.
  - **Read scopes:** `ReadScope.compile` returns `ReadScope.deny` for an empty-type principal or action, and an empty-type entity value never compiles to an `Eq` atom.
  - **Equality:** `Entity.namesEntity` checks both fields, so `Entity.refEquals`, `Entity.attributeValueEquals` and `Entity.entityIn` are `false` whenever a side has an empty type, at any depth and even against itself. No type scope matches an empty type, `Policy.isType("")` included. `Entity.ref` stays total.
  
  Migration: don't use an empty type for any entity. A signed-out caller is a principal of its own type, such as `Anonymous::"anonymous"`.
- de98263: **Security fix (#694):** the first proof of an email address now removes every credential the account held, not only its password and sessions. Before, someone who signed up with an address they did not own and then linked an OAuth provider that reports emails unverified, registered a passkey, minted an API key or enrolled a second factor kept that access after the address's real holder proved it.
  
  When a flow promotes an unverified email identifier to verified on a proof (the verification link, a magic link, an email OTP, an invitation token, or a provider-verified email through OAuth, Google One Tap or SSO), the account's linked OAuth accounts (`OAuthAccountStore`), passkeys (`CredentialStore`), API keys (`ApiKeyStore`), multi-factor enrolment (`MultiFactorStore`: the TOTP secret and backup codes) and trusted devices (`TrustedDeviceStore`) are deleted before its sessions are revoked. Each store is optional: a store the layer's context does not provide is skipped. The holder enrols their own credentials afterwards. In the OAuth sign-in, the provider link being made is created after the sweep and survives it. An address that is already verified keeps everything, as before.
  
  `AuthLifecycleService.verifyEmail` now goes through the same first-proof path as the other flows. `OAuthAccount` and `OAuthAccountStore` moved to their own module; `@thomasfosterau/effect-auth/oauth` and the root `Auth.OAuth` namespace export them as before.
- 3829977: **Security fix (#704):** the first proof of an email address now also removes the phone numbers and OIDC-provider tokens the account's earlier, unproven holder could still use. Before, someone who signed up with an address they did not own kept two ways back in after its real holder proved it: a phone number they had added, which signs in with a phone one-time code, and the access and refresh tokens the core's OIDC provider had issued them (a refresh token mints new access tokens).
  
  `proveAddress` now deletes the account's unverified phone identifiers (through `IdentifierStore.listByUser` and `delete`) and, when the layer's context provides an `OidcTokenStore`, every access and refresh token issued to the user, before its sessions are revoked as before. A phone number the account already verified stays: its holder proved it. JWTs already issued (`Jwt`) cannot be revoked and expire on their own. An address that is already verified keeps everything, as before.
  
  `OidcTokenStore` gains a required `deleteByUserId(userId)`, which deletes every token issued to the user for every client; a custom `OidcTokenStore` must implement it. `Testing.memoryOidcTokenStore` implements it.
- 4037bcf: Security fix (#586): an organization invitation can no longer be accepted with an unverified email identifier on the invitation id alone. An attacker could sign up with an invitee's address (unverified, with a session by default) and accept the invitation, joining at the invited role, owner or admin included. Now each invitation carries a secret 256-bit token, stored only as its SHA-256 digest (`Invitation.tokenHash`) and handed to `sendInvitationEmail` for the link; presenting the token is the proof of the address. `acceptInvitation(userId, { invitationId, token, currentSessionId? })` and `rejectInvitation(userId, { invitationId, token })` take it, and a wrong or missing token answers "Invitation not found". Acceptance still works for apps that run without email verification: when the matching email identifier is unverified, the token is its first proof and goes through the same path as a magic link or an email OTP (#440), clearing the account's password and revoking every session but `currentSessionId` before the identifier is marked verified. `resendInvitation` mints a new token, so the link sent earlier stops working.
  
  Breaking: `sendInvitationEmail` now receives `{ invitation, organization, token }` (`InvitationDelivery`) and is required to invite or resend (without it `inviteMember` refuses). `OrganizationService.layer` now also requires `EmailPasswordStore` and `SessionService`. Store implementations persist the new `tokenHash` field. Over HTTP, `PATCH /invitations/:id` to `accepted` or `rejected` takes the token as the input-only `token` attribute (`400` without it or with a wrong one); the client's `organization.acceptInvitation(invitationId, token)` and `rejectInvitation(invitationId, token)` take it as a second argument, and `./client/testing`'s `makeServerFixture` exposes the delivered tokens as `sentInvitations`.
- 9598882: Attribute, metadata and claims bags are typed as JSON (#443). The core exports `Json` and `JsonObject` (Effect's `Schema.Json` / `Schema.JsonObject`, as types and as schemas), and `Attributes` is now `JsonObject` (was `Record<string, unknown>`). The same type replaces `Record<string, unknown>` for user and session `attributes` and every `sessionAttributes` option, API-key, organization, OIDC-client and one-time-token `metadata`, JWT claims (`definePayload`, `sign`'s extra claims, `verify`, `RemoteJwksVerifier.verify`) and JWKs (`JwtKeyPair.publicKeyJwk`, `Jwks.keys`), Google One Tap `claims`, `OAuthUserInfo`'s extra fields and `mapProfile`'s input, the OIDC provider's `userinfo` and metadata documents, and `Messages` params; the HTTP tier's `Attributes`, `ClaimsView` and `JwksView` schemas validate JSON. In effect-auth-drizzle, the attribute columns are `$type<Auth.JsonObject>()` and `defineSchema`'s `attributes` mappings expect that type. The stores already persisted these bags as JSON, so nothing changes at runtime for JSON values.
  
  Migration: a value in one of these bags must be JSON: a string, a number, a boolean, `null`, or arrays and objects of those. Convert anything else before it goes in: a `Date` to an ISO string or epoch milliseconds, a class instance to a plain object, and leave a key out instead of setting it to `undefined`; functions, `Map`s, `Set`s and `bigint`s have no JSON form. A value read out of a bag is now `Json` rather than `unknown`, so narrow it (`Predicate.isString`, …) before use. An `interface` is not assignable to `JsonObject` (it has no index signature); declare the bag's shape with a `type` alias instead. A drizzle table your app defines writes `jsonb().$type<Auth.JsonObject>()` (or `json()` / `text({ mode: "json" })`) for its attribute bag. `./testing`'s `viewerLayerAs` default `toUser` now copies only the viewer's JSON-valued fields into `attributes`.
- dd8715a: **Breaking (HTTP, client):** admin, impersonation, API keys, OIDC-provider clients, SSO registration and sign-in, JWT issuance and device approval are JSON:API resources (#205, slice 5). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.
  
  | Before                                                         | Now                                                                                                                                                                                       |
  | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `POST /admin/users/list`                                       | `GET /admin/users?filter[email]=…&page[offset]=…&page[limit]=…`: `users` resources, `meta.total`                                                                                          |
  | `POST /admin/users/set-role`                                   | `PATCH /admin/users/:id` with `role`                                                                                                                                                      |
  | `POST /admin/users/remove` · `/admin/users/revoke-sessions`    | `DELETE /admin/users/:id` · `DELETE /admin/users/:id/sessions`: `204`                                                                                                                     |
  | `POST /admin/users/ban` · `/admin/users/unban`                 | `POST /user-bans`, the user as the `user` relationship (`201`: the ban, its id the user's, the user included) · `DELETE /user-bans/:id` (`204`)                                           |
  | `POST /admin/impersonate` · `/admin/stop-impersonating`        | `POST /impersonations`, the user as the `user` relationship (`201`, the session cookie swapped) · `DELETE /impersonations/current` (`204`)                                                |
  | `GET` · `POST /api-keys` · `PATCH` · `DELETE /api-keys/:keyId` | The same paths as JSON:API: `api-keys` resources; the create answers `201` with the plaintext key in `meta.key`                                                                           |
  | `GET /oauth2/clients` · `POST /oauth2/register`                | `GET` · `POST /oauth-clients` (`201`, a confidential client's secret in `meta.clientSecret`); the client's `type` is the `clientType` attribute                                           |
  | `PATCH` · `DELETE /oauth2/clients/:clientId`                   | `PATCH` · `DELETE /oauth-clients/:id`                                                                                                                                                     |
  | `POST /sso/register`                                           | `POST /sso-providers` (`201`): an `sso-providers` resource; the request takes `relationships.organization` (no `organizationId` attribute), and the answer carries it the same way (#642) |
  | `POST /sign-in/sso`                                            | `POST /sso-authorizations` (`201`): the IdP `url`, the round-trip state as the id                                                                                                         |
  | `GET /token`                                                   | `POST /tokens` (`201`): `token` and `expiresAt`, the id the token's SHA-256 digest                                                                                                        |
  | `POST /device/approve` · `/device/deny`                        | `POST /device-authorizations/decisions` with `userCode` and `decision` (`approved`, which needs the session, or `denied`): `204`; the code stays in the body                              |
  
  - **Left as they are**, because their wire format is fixed by a specification: RFC 8628's `POST /device/code` and `/device/token`, the SSO callbacks (`POST /sso/callback`, `POST /sso/saml/acs/:providerId`, `GET /sso/saml/metadata/:providerId`), the JWKS (`/jwks`, `/.well-known/jwks.json`), and the OIDC provider's `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`, RFC 7591 / 7592 `/register` and RFC 8414 discovery.
  - **Discovery:** the OIDC provider's `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` advertise `registration_endpoint` only while dynamic registration is enabled. They used to name the admin-gated `/oauth2/register`, which was never an RFC 7591 endpoint and is gone.
  - **CSRF:** minting a JWT is now a `POST`, so the trusted-origin check covers it like every other write; the special case that treated `GET /token` as state-changing is removed.
  - **`DELETE /impersonations/current` answers `404` on a session that is not an impersonation**; `POST /admin/stop-impersonating` signed any session out. Ending an impersonation also drops the session from a multi-session device list, as `DELETE /sessions/current` does.
  - Permissions and refusal statuses are unchanged: admin calls need `isAdmin` (`403`), an unknown user answers `400`, a key the caller does not own `400`, an unknown or statically configured OAuth client `400`. No store contract changes: every resource is addressed by an id the stores already keep.
  - `./client`: the methods keep their arguments and results and call the new endpoints, except `admin.unbanUser`, which now resolves with nothing (the lifted ban answers `204`, not the user).
  - Every old endpoint, store-contract, client and status-code change of the conversion is in [the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md).
- 325f231: **Breaking (HTTP, store contract, client):** organizations, members, invitations and device sessions are JSON:API resources (#205, slice 4a). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents.
  
  | Before                                                                          | Now                                                                                                                                   |
  | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
  | `GET /multi-session/list`                                                       | `GET /device-sessions`: `device-sessions` resources (`active` marks the current one), their users in `included`                       |
  | `POST /multi-session/set-active`                                                | `PATCH /device-sessions/active` with a `device-sessions` linkage: `204`                                                               |
  | `POST /multi-session/revoke`                                                    | `DELETE /device-sessions/:id`: `204`                                                                                                  |
  | `GET /organizations` · `POST /organization/create`                              | `GET /organizations` · `POST /organizations` (`201`)                                                                                  |
  | `GET` · `PATCH` · `DELETE /organization/:organizationId`                        | `GET` · `PATCH` · `DELETE /organizations/:id`; `GET` answers the organization alone, its members are `GET /organizations/:id/members` |
  | `PUT /organization/:organizationId/default-role`                                | `PATCH /organizations/:id` with `defaultRole`                                                                                         |
  | `POST /organization/set-active`                                                 | `PATCH /organizations/active` with an `organizations` linkage, or `data: null` to clear it: `204`                                     |
  | `POST /organization/:organizationId/members`                                    | `POST /organizations/:id/members`, the user as the `user` relationship: `201`                                                         |
  | `PATCH /organization/:organizationId/members` (by `userId`)                     | `PATCH /organization-members/:id` with `role`                                                                                         |
  | `POST /organization/:organizationId/members/:userId/deactivate` · `/reactivate` | `PATCH /organization-members/:id` with `status: "inactive"` · `"active"`                                                              |
  | `DELETE /organization/:organizationId/members/:userId`                          | `DELETE /organization-members/:id`: `204`                                                                                             |
  | `GET` · `POST /organization/:organizationId/invitations`                        | `GET` · `POST /organizations/:id/invitations` (`201`)                                                                                 |
  | `POST /invitations/:invitationId/accept` · `/reject` · `/cancel`                | `PATCH /invitations/:id` with `status` `accepted` (the new membership in `meta.membership`) · `rejected` · `canceled`                 |
  | `POST /invitations/:invitationId/resend`                                        | `POST /invitations/:id/deliveries`: `202` with the invitation                                                                         |
  
  - **Store contract:** `OrganizationStore` gains `getMemberById(memberId)`, answering the membership with that `Member.id` (in any organization) or `null`. A membership is now addressed by its stored id, so every `OrganizationStore` implementation must add it; `Testing.organizationStoreConformance()` (`@thomasfosterau/effect-auth/testing`) checks it with the rest of the membership contract. `OrganizationService` gains `getMemberById` as well.
  - **Device sessions are named by their stored id** (the hash of the session token), never the token: the old `/multi-session/*` list answered, and its actions took, the raw tokens the device's cookies hold. A device-session id is safe in a URL.
  - `PATCH /organizations/:id` now applies `jitProvisioning` (the old endpoint accepted and dropped it).
  - `Http.UpdateMemberRolePayload` is `{ role }` (no `userId`).
  - `./client`: `organization.updateMemberRole(memberId, { role })`, `removeMember(memberId)`, `deactivateMember(memberId)` and `reactivateMember(memberId)` take the membership's own `id` (from `get(…).members` or `addMember`) instead of `(organizationId, userId)`. `multiSession.setActive` / `revoke` take the `session.id` that `multiSession.list()` answers, now the stored id. The other organization and multi-session methods keep their arguments and results and call the new endpoints.
  - Every old endpoint, store-contract, client and status-code change of the conversion is in [the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md).
- 4649a7b: **Breaking (HTTP, store contract, client):** organization domains, custom roles, teams and team members are JSON:API resources (#205, slice 4b). The endpoints take `application/vnd.api+json` documents and answer JSON:API documents and error documents; nothing is left on the old `/organization/*` routes.
  
  | Before                                                              | Now                                                                                                                                            |
  | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
  | `GET` · `POST /organization/:organizationId/domains`                | `GET` · `POST /organizations/:id/domains` (`201`): `organization-domains` resources                                                            |
  | `DELETE /organization/:organizationId/domains/:domainId`            | `DELETE /organization-domains/:id`: `204`                                                                                                      |
  | `POST /organization/:organizationId/domains/:domainId/verify`       | `POST /organization-domains/:id/verifications`: `200` with the claim                                                                           |
  | `GET /organization/:organizationId/roles`                           | `GET /organizations/:id/roles`: `organization-roles` resources                                                                                 |
  | `PUT /organization/:organizationId/roles/:role` (create or replace) | `POST /organizations/:id/roles` with `role` and `permissions` (`201`; `409` when defined) · `PATCH /organization-roles/:id` with `permissions` |
  | `DELETE /organization/:organizationId/roles/:role`                  | `DELETE /organization-roles/:id`: `204`                                                                                                        |
  | `GET` · `POST /organization/:organizationId/teams`                  | `GET` · `POST /organizations/:id/teams` (`201`): `teams` resources                                                                             |
  | `PATCH` · `DELETE /teams/:teamId`                                   | `PATCH` · `DELETE /teams/:id`                                                                                                                  |
  | `GET` · `POST /teams/:teamId/members`                               | `GET` · `POST /teams/:id/members`, the user as the `user` relationship (`201`): `team-members` resources                                       |
  | `DELETE /teams/:teamId/members/:userId`                             | `DELETE /team-members/:id`: `204`                                                                                                              |
  | `GET /organization/:organizationId/members/:userId/teams`           | `GET /organization-members/:id/teams`                                                                                                          |
  
  - **Store contract:** `TeamMember` and `OrgRole` gain an `id`. `OrganizationStore.addTeamMember` takes the whole `TeamMember` (its id minted by the caller) instead of `(teamId, userId)`, and the store gains `getTeamMemberById(teamMemberId)` and `getOrgRoleById(orgRoleId)`, each answering the record with that id or `null`. `upsertOrgRole` is still keyed by `(organizationId, role)`; the service passes the stored id when it replaces a definition, so a definition keeps its id. Every `OrganizationStore` implementation must add the two lookups, store the ids, and take the new `addTeamMember`; `Testing.organizationStoreConformance()` now checks team memberships and role definitions by id alongside memberships. `OrganizationService` gains `getTeamMemberById`, `getOrgRoleById` and `getDomainById` (no permission check; the operation applied to the record decides).
  - Permissions are unchanged: listing domains, roles, teams and team members needs membership, and a refusal (or a server with no `OrganizationDomainStore`) still answers `403`. An unknown domain claim, role definition, membership or team membership id now answers `404`; an unknown team id still answers `403`.
  - `Http.TeamMemberView` and `Http.OrgRoleView` gain `id`; `Http.CreateOrgRolePayload` (`{ role, permissions }`) is new.
  - `./client`: `organization.removeDomain(domainId)` and `verifyDomain(domainId)` take the claim's `id` alone; `upsertRole` is replaced by `createRole(organizationId, { role, permissions })` and `updateRole(roleId, { permissions })`, and `deleteRole(roleId)` takes the definition's `id`; `listTeamsForMember(memberId)` takes the membership's `id`; `removeTeamMember(teamMemberId)` takes the team membership's `id` (from `addTeamMember` or `listTeamMembers`). The other domain, role and team methods keep their arguments and results and call the new endpoints.
  - Every old endpoint, store-contract, client and status-code change of the conversion is in [the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md).
- d66403e: Purge spent rate-limit entries from the `KeyValueStore` backend (#709). `purgeExpiredKV` now also deletes the `RateLimitStoreKV` entries (and so `layerKV`'s and `Testing.memoryStores`') whose window and block have both passed, and `PurgeExpiredKVResult` gains `rateLimits`, the count it deleted. An entry inside its window or still blocked stays. `KeyValueStore` has no per-entry TTL, so the purge, scheduled by the host, is what keeps these entries bounded.
- cf1e3c9: List the signed-in user's own pending invitations (#706). `OrganizationService.listInvitationsForUser(userId)` answers the pending, unexpired invitations addressed to the user's verified email identifiers (the ones they may accept or reject by id without the emailed token, #673); an unverified address contributes none. The HTTP tier serves it as `GET /invitations`, the top-level `invitations` collection scoped to the caller (`401` without a session), whose resources never carry the token or its digest, and the browser client as `client.organization.listMyInvitations()`.
- 7a651a3: Security fix (#602): identifier lookups no longer resolve a different account when the database compares strings loosely.
  
  On MySQL the identifiers table's `value` column used the server's default collation (`utf8mb4_0900_ai_ci` on MySQL 8), which is case-, accent- and width-insensitive. A password reset or magic link requested for a look-alike address such as `bob@exämple.com` (an IDN domain an attacker holds) found `bob@example.com`'s identifier, so the reset token for Bob's account was mailed to the attacker's address. PostgreSQL and SQLite compare bytes and were not affected.
  
  **effect-auth-drizzle (schema change).** `MySql.tables.identifiers.value` is now `VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`, in the drizzle table and in `MySql.migrationStatements` / `migrationSql`, so the lookup and the `(type, value)` unique key compare byte for byte. New exports: `MySql.binaryVarchar(name, { length })`, a `varchar` column under that collation for your own identifier columns; and `MySql.identifierCollation` (`"utf8mb4_bin"`). An application's own column the stores look identifiers up in, such as the single-table store's `users.email` or a `defineSchema` value column, needs the same collation on MySQL.
  
  **effect-auth (core).** Every service now reads identifiers through the new `lookupIdentifier(store, type, value)`, which treats a record whose `type` or `value` differs from the one asked for as a miss and logs a warning. This covers every store, bring-your-own ones included, and a store that compares loosely: a look-alike reads as an unknown address. `resolveUserByIdentifier`, `claimIdentifier` and `replaceIdentifier` use it too, as does the new `findIdentifierOwner(store, getUser, type, value, onDangling)`, which the sign-in-or-create flows (magic link, email and phone OTP, SSO, Google One Tap) now share. A password reset is bound to, stored with and sent to the resolved identifier's own value, and the email-verification resends go to the identifier's value. Behaviour change for a store that compares loosely: a sign-up of a look-alike value now fails on the store's unique index (`AuthError`) instead of reporting `IdentifierTakenError`. `identifierStoreConformance` (`/testing`) gains a case that checks values differing only by case, accent or width are distinct identifiers.
  
  Whether email input is restricted or punycoded is not decided here.
- 1e7d8f4: **Security fix (#581), breaking:** the raw session token no longer reaches a response body, so `HttpOnly` protects it again. Before, the `id` of the `sessions` resource that `POST /sessions`, `POST /users`, `POST /second-factor-challenges/verifications`, `POST /email-verifications/redemptions` and `GET /sessions/current` answered was the session cookie's value, and `Authorization: Bearer <that id>` was accepted, so any script on the origin could read and replay the session. Every session resource is now named by its stored id, the SHA-256 digest of the token, which is not a credential; the one session has one id across `GET /sessions`, `GET /sessions/:id`, `DELETE /sessions/:id`, `device-sessions` and `impersonations`. The token reaches a client only in the `HttpOnly` session cookie and, in the existing opt-in bearer mode (`cookie.bearerMode`), the `set-auth-token` header.
  
  - **`SessionService.createSession` returns `{ session, token }`** (`Types.IssuedSession`, new), and `Session.id` is always the stored id: `validateSession` and `setSessionAttributes` answer the session under its digest. Every sign-in result carries `token` beside `session` (`AuthResult`, `AuthLifecycleResult`, `MagicLinkResult`, `EmailOtpAuthResult`, `PhoneOtpAuthResult`, `OAuthSignInResult`, `SsoSignInResult`, `GoogleOneTapSignInResult`, `AnonymousResult`, `DevicePollResult`, `MultiFactorVerifyResult`, `OtpSecondFactorVerifyResult`, `redeemOneTimeTokenForSession`); `AdminService.impersonateUser` returns `{ session, token }`. Set the cookie from `token`, not `session.id`.
  - **`revokeOtherSessions(userId, keepSessionId)` and `setSessionAttributes(storedSessionId, …)` take the stored id** (`session.id` as the services answer it), as `revokeSessionById` already did; `EmailPasswordService.changePassword`'s `currentSessionId` is that id too. `validateSession` and `invalidateSession` still take the raw token.
  - **`afterSignOut` observes the stored id**, not the token, so `AuditPlugin`'s `auth.signOut` log no longer records a credential. `afterCreateSession` and `afterValidateSession` see sessions under their stored id.
  - `CurrentSession` and the signed session-data cache cookie hold the digest; a cache cookie issued before this release no longer matches and falls back to one store read.
  - `./client`: `getSession()`, `listSessions()` and the cross-tab `BroadcastChannel` message carry the stored id, which `revokeSession` takes (revoking the current session's id now signs it out). `Http.RemoteSession.read` resolves the session under its stored id.
  - `@thomasfosterau/effect-auth-sveltekit`: with this core, `event.locals.auth.session` carries no credential, so a `load` that returns it no longer serializes the token into the page. No API change.
- 8b65156: **Security — OAuth sign-in proves an unverified address on the provider's verification, as Google One Tap and SSO do (#671).** One policy now holds for every IdP-backed sign-in: the first-proof rule (#440). When a first `OAuthService.signInWithCallback` sign-in's provider-verified email matches an existing user whose email identifier is still unverified, the provider's verification is the address's first proof. The flow runs `proveAddress`: it clears the account's password, revokes all of its sessions and marks the address verified, and only then links the provider identity and mints the signed-in user's session. A squatter who signed up with someone else's address and a password keeps nothing, and the address's real holder gets in without proving the address another way first.
  
  A verified local address still links only under the #588 rules: the provider reports `email_verified: true`, and `autoLinkByVerifiedEmail` (default `true`) or a `trustedProviders` entry applies. Without auto-linking for the provider the match fails with `EmailInUseError` and changes nothing, whether the local address is verified or not. An unverified provider email never links and never takes over an address.
  
  **Breaking:**
  
  - `signInWithCallback` no longer refuses a provider-verified match on an unverified local address with `EmailInUseError` (the #588 behaviour); it takes the address over, clearing the earlier sign-up's password and sessions.
  - `OAuthService.layer` and `OAuth.make` now require `EmailPasswordStore` (for `clearPasswordHash`). `Testing.memoryStores`, `@thomasfosterau/effect-auth/sql`'s `layer` and the other storage adapters provide it; an application that composes its stores by hand adds one.
  
  ADR-0007's amendment gains a #671 note.
- 2096e2a: **Security — OAuth sign-in no longer auto-links to an account whose email is unverified (#588).** `OAuthService.signInWithCallback` linked a new provider identity to the user holding its email whenever the provider reported the email verified, without checking whether the local address was verified. A squatter who signed up with someone else's address and a password (email verification is off by default) got the victim's provider account linked to theirs on the victim's first OAuth sign-in, with the squatter's password and sessions still valid. With `trustedProviders`, the link happened even when the provider reported `email_verified: false`.
  
  Now a first OAuth sign-in whose email matches an existing user is linked only when the provider reports `email_verified: true`, the local email identifier is verified, and auto-linking applies to the provider. `autoLinkByVerifiedEmail` still defaults to `true`. Every other match fails with `EmailInUseError` (a conflict) and changes nothing: no account is linked, no session is minted and the existing account keeps its password and sessions.
  
  **Breaking:**
  
  - `trustedProviders` no longer waives the provider's `email_verified` claim. It now means "auto-link this provider even with `autoLinkByVerifiedEmail: false`", under the same verified-match rule.
  - `signInWithCallback` refuses a claimed email with `EmailInUseError` (its error channel gains it) instead of `AuthError`, including when the user store reports the address taken while the user is being created. Code that caught the `AuthError` for this case catches `EmailInUseError`.
  - The real holder of an address someone signed up with unverified cannot use OAuth sign-in until that account is removed or the address is proven another way: the verification link, a magic link or an email OTP, which clear the earlier sign-up's password and sessions.
  
  ADR-0007 is amended to describe this behaviour.
- efba66d: **Security fix (#715):** an organization's invitation list is readable only by a member whose role carries `invitation:create`, the permission that issues invitations. Before, any signed-in user who knew an organization id could list every invitation it had sent (invitee emails, roles and inviters) through `GET /organizations/:id/invitations`.
  
  - `GET /organizations/:id/invitations` answers `403` to a non-member, to a member without `invitation:create` and to an unknown organization id alike, with the same body, so the answer reveals no ids. The browser client's `organization.listInvitations(organizationId)` is unchanged.
  
  **Breaking:**
  
  - `OrganizationService.listInvitations(organizationId)` is now `listInvitations(actorId, organizationId)` and can fail with an `OrganizationError`.
  - `OrganizationService.acceptInvitation` answers `AcceptedInvitation` (`{ member, invitation }`: the new membership and the invitation as accepted) instead of the bare `Member`, since the invitee can no longer read the invitation through `listInvitations`. Read `.member` where you read the result before.
- 7d9579e: **Security fix (#717):** an organization and its member list are readable only by an active member. Before, any signed-in user who knew an organization id could read the organization and every membership in it (user ids, roles, statuses) through `GET /organizations/:id` and `GET /organizations/:id/members`, and the `404` an unknown id got confirmed which ids exist.
  
  - `GET /organizations/:id` and `GET /organizations/:id/members` answer `403` to a non-member, to a deactivated member and to an unknown organization id alike, with the same body, as `GET /organizations/:id/teams`, `/domains` and `/roles` already did. An unknown id no longer answers `404`. The browser client's `organization.get(organizationId)` is unchanged and rejects with that `403`.
  
  - `OrganizationService.listOrganizations(userId)` (and so `GET /organizations`) lists only the organizations the user is an _active_ member of: a deactivated membership no longer shows its organization, since its holder can no longer read it.
  
  **Security fix (#576):** `PATCH /organizations/active` records only an organization the caller is an active member of. Before, any signed-in user could write any id, another tenant's or one that does not exist, into their session's `activeOrganizationId`, which a host that reads the attribute back as the working organization would trust. A non-member, a deactivated member and an unknown id now get the same `403` and body; `data: null` still clears it without a check.
  
  - New: `OrganizationService.requireMembership(userId, organizationId)` fails with an `OrganizationError` unless the user is an active member, alike for a non-member and an organization that does not exist.
  
  **Breaking:**
  
  - `OrganizationService.getFullOrganization(organizationId)` is now `getFullOrganization(actorId, organizationId)`. It requires the actor's active membership and fails with an `OrganizationError` for a non-member and for an organization that does not exist alike.
- 4037bcf: Security fix (#585): organization members can no longer grant beyond their own permissions. An admin could make themselves (or anyone) owner through `updateMemberRole`, `addMember` or `inviteMember`, then demote or remove the original owners, and could bring back a deactivated owner with `reactivateMember`. Now an actor assigns a role (`addMember`, including the organization's `defaultRole` when no role is named, `inviteMember`, `updateMemberRole`) only when their own role carries every permission that role carries, and changes, deactivates, reactivates or removes a member only when it carries every permission of that member's role (the `previousRole` for a reactivation). This covers the owner role and custom roles alike; a wildcard grant (`team:*`) is satisfied only by a wildcard at least as wide (`team:*` or `*:*`). A role name that neither an `OrgRole` nor `config.roles` defines is now rejected by `addMember`, `inviteMember` and `updateMemberRole` (`setDefaultRole` already rejected one). Over HTTP, each refusal answers `403`.
  
  Migration: a role that carries application permissions (`posts:write`, …) can now be granted only by a member whose role carries them too. With the default roles the owner carries only the organization permissions, so if your custom roles carry application permissions, add them (or `"*:*"`) to the owner role in `OrganizationService.layer({ roles })`. Define a custom role (`upsertOrgRole`) before you assign it.
- e2ff7f7: Organization role management follows the grant rule, and invitations can be answered in-app (#673).
  
  - **The default `owner` role is `"*:*"`** (`defaultOrganizationRoles.owner`), so an owner can grant, define and delete any custom role, application permissions (`posts:write`) and wildcards (`team:*`) included. It stays protected from redefinition. An app that passes its own `roles` map keeps its owner entry as written.
  - **`upsertOrgRole` and `deleteOrgRole` follow #585's grant rule.** Defining or redefining a role needs the actor's role to carry every permission in the new definition and every permission the name resolves to now (its custom definition, else its static `config.roles` entry); deleting one needs every permission the definition held and every permission of the static entry it falls back to. An actor can no longer redefine or delete their own role, so a custom role holding `role:manage` cannot widen itself. Over HTTP each refusal answers `403`, as the other role-management refusals do.
  - **A verified address answers an invitation by id.** `InvitationResponseInput.token` (and so `acceptInvitation` / `rejectInvitation`'s input) is now optional: a signed-in user whose matching email identifier is verified may accept or reject without the emailed token, so a dashboard "pending invitations" list works. An unverified match is refused without the token and still accepts with it, the token being the address's first proof (#586); a user the invitation is not addressed to gets "Invitation not found". `PATCH /invitations/:id` no longer answers `400` for a missing `token` attribute, and the browser client's `organization.acceptInvitation(id, token?)` / `rejectInvitation(id, token?)` take the token optionally.
- 6d33e11: Security fix (#590): email and phone OTP sign-in could be brute-forced, because each resend issued a fresh code with a fresh attempt counter, so `maxAttempts` bounded one code and nothing bounded an address. Every wrong code is now also counted against the (address, purpose) pair in a failure budget that a resend, an expiry or the attempt limit never resets, and `send` backs off once it grows: after `backoff.freeFailures` wrong codes (default 5), `send` fails with `ResendTooSoonError` until `backoff.baseDelay` (default one minute), doubled for each further wrong code and capped at `backoff.maxDelay` (default one day), has passed since the latest one. A successful verification resets the count. There is no lockout: once the delay has passed a send goes through, so an attacker can slow an address's owner down but not lock them out. Under the defaults an attacker gets 18 guesses at an address in the first day and 3 a day after that, where before there was no limit. The backoff applies alike to an address with and without an account. `resendCooldown` now defaults to 60 seconds for `EmailOtpConfig` and `PhoneOtpConfig` (was off; `0` turns it off). Codes stay 6 digits.
  
  Breaking: `EmailOtpStore` and `PhoneOtpStore` gain `getFailures`, `recordFailure(address, purpose, at)` and `clearFailures`, over the new `OtpFailures` type (`{ count, lastFailureAt }`; the three methods are `OtpFailureBudget<Purpose>`), with `OtpBackoffConfig` for the new `backoff` option. A store keeps the budget apart from the code's record, so `upsert`, `delete` and `purgeExpired` leave it, and should make `recordFailure` one atomic statement. `EmailOtpStoreKV` keeps it under `email-otp-failures:<purpose>:<email>`, and `./sql` in the new `auth_email_otp_failures` table, which `migrate` (and so effect-auth-alchemy-cloudflare's `AuthSchema` on the next deploy) creates. `./testing` adds `emailOtpStoreConformance` and `phoneOtpStoreConformance`, `memoryPhoneOtpStore` and `memoryOtpFailures` (the budget's three methods, to spread into a store of your own). Migration: implement the three methods on a custom store and run the new conformance suite against it; run `migrate` once on a SQL database; a caller that sent twice in a row on purpose passes `resendCooldown: 0`.
- b386606: `OwnedAccess` gains the axes a content kernel needs to delegate its read rules (#637), and a new `ReferenceAccess` module decides ownerless reference rows.
  
  - **Moderation:** `OwnedRow.unapproved?: boolean | undefined`, read exactly as `draft: true`. The `owned:public`, `owned:follower` and new `owned:group` permits require it to be `false`; the owner and view-private permits ignore it.
  - **No owner:** `OwnedRow.ownerId` is now `string | undefined` (breaking). `undefined` means the row has no owner: no viewer matches the owner arm, and the decision slice carries no `owner` attribute, never an empty or sentinel id. `IsFollower` is never asked about it.
  - **Groups:** `Visibility` gains `"group"` (breaking for exhaustive matches), `OwnedRow.groupId?: string | undefined` names the group, and the new `IsMember` service (`isMember`, `groupsOf`, with `isMemberNever`) answers membership. It fails closed when it is not provided, like `IsFollower`. The new `owned:group` permit admits a published `group` row to members of its group. A `group` row with no group reads as `private`.
  - **Read scope:** the `member` arm of `OwnedReadScope` gains `groups: FollowingSet` (breaking for code that builds the scope), which is `nobody` without `IsMember`.
  - **Reference rows:** `ReferenceAccess.make({ guards, viewPrivate })` returns `canView(row: ReferenceRow)`, the same `OwnedReadScope`-shaped `readScope`, `policies` and `binding`. A row with no `visibility` (the view has no axis) is visible to everyone. A `followers` row is read by its `followersOf` account and that account's followers, and a `group` row by its group's members. The view-private rung reads everything.
  - **Seams:** `OwnedAccess.relationFacts(accountId, { followersOf, groupId })` asks both seams, failing closed. It never asks about an absent subject.
  - **Compiling the policies:** `OwnedAccess` and `ReferenceAccess` expose `binding`, the `ReadScope.Binding` their `policies` compile against. The owned binding now binds `unapproved` and `group`, and `context.member` is the set `groups`.
  - **Serveability:** `OwnedAccess.serveableAxes` adds `unapproved` (optional, must be `false`), `moderationState` (optional, must be `"approved"`) and `deletedAt` (must be absent). A representation that carries none of them is decided as before.
  - **Docs:** the `OwnedAccess` module docs describe the four role axes (`viewPrivate`, `viewDeleted`, `moderate`, `writeCorpus`) and their fail-closed rule for a role outside the ladder.
  
  Migration: pass `ownerId: undefined` instead of coercing a missing owner to a string, and add `groups` wherever you build a `member` read scope. Give the owned rows your `EntityResolver` hands an `Authorizer` an `unapproved` boolean (`false` for an unmoderated row): like `draft`, a missing `unapproved` now reads as unpublished, so `owned:public` no longer admits the row. `ReadScope.compile` over `OwnedAccess.policies` needs a binding that binds `unapproved` and `group`; use `owned.binding`. An older binding compiles to `Inexact`, which `Cacheability.publicReach` reports as `Undecided`.
- 32ebf2d: **Security (#698), released together with #678's captcha on sends:** passkeys are exempt from `AccountLockoutPlugin`'s account lock, as the one-time codes and magic links are. A WebAuthn assertion is a signature nobody can guess, and a credential id is not secret, so counting passkey attempts let anyone who holds one lock the account. Passkey verification still counts against `IPRateLimitPlugin` and `RateLimitPlugin`. `PhoneOtpService.verifyPhoneNumber` now fires `beforeAuthenticate` (method `phone-otp`, keyed on the signed-in user) before the code is checked.
- a2624ea: Purge expired rate-limit rows (#686). `./sql`'s `purgeExpired` (and so the Alchemy packages' `purgeExpired`) now also deletes the `auth_rate_limits` rows whose window and block have both passed, in one `DELETE`, and `PurgeExpiredResult` gains `rateLimits`, the count it deleted. The drizzle package adds `RateLimitStore.purgeExpired(tables)`, one `DELETE` of the same rows from its rate-limit table. A row inside its window or still blocked stays.
- 211f399: **Security fix (#582, #583), breaking:** `Http.make` and `Http.makeAsync` now rate limit every sensitive endpoint per client address by default, and no spelling of a path escapes the limit. Before, `ipRateLimit` was off unless set, so `Http.make({ services })` served unlimited password guessing, sign-up and OTP, magic-link and reset sends (email bombing, SMS toll fraud) and an unauthenticated PBKDF2 CPU sink on `POST /sessions`. With it set, its rules compared the raw request path exactly and case-sensitively while the router is case-insensitive and ignores trailing, duplicate and percent-encoded slashes and letters, so `/sessions/`, `/Sessions`, `//sessions` and `/%73essions` reached `POST /sessions` with no limit at all, as did every other limited endpoint.
  
  What breaks:
  
  - **`ipRateLimit` is on unless it is `false`.** Omitted (or `{}`), `defaultEndpointRules` apply, so `Http.make` throws, and `Http.makeAsync` rejects, at startup without what the limit needs: a `RateLimiter` in `services` (`RateLimiterConfigError`) and a client address source, `trustedProxy` (`ClientAddressConfigError`). Give the handler both (behind Cloudflare, `trustedProxy: ClientIP.cloudflare` and `RateLimiter.layer()` over a shared `RateLimitStore`), or pass `ipRateLimit: false` to serve without the limit, for example behind an edge that already limits per address or in tests. `ipRateLimit` now accepts `false`, the only opt-out.
  - **Rules match the endpoint the router matched, not the request path.** An `EndpointRateLimitRule`'s `path` is the endpoint's path template as the OpenAPI document writes it (`"/sessions"`, `"/sso/saml/acs/{providerId}"`; the router's `:providerId` form is accepted too), and a `RegExp` rule is tested against that template rather than the concrete path. Rules for fixed paths keep working unchanged; a `RegExp` written against concrete ids (`/^\/sso\/saml\/acs\/acme$/`) must name the template instead. A request is counted only once it routes to an endpoint, so a path no endpoint serves is no longer counted (it answers `404` as before). The limit now runs as router middleware on each auth route, still before the request is decoded or any auth logic runs.
  - **`defaultEndpointRules` cover more endpoints.** Besides sign-in, sign-up, `POST /otp-challenges`, `POST /password-resets`, second-factor verification and `POST /register`, the defaults now limit `POST /email-verifications`, `POST /password-resets/redemptions`, `POST /email-verifications/redemptions`, `PATCH /users/me/password`, `POST`, `PATCH` and `DELETE` on `/multi-factor-enrollments[/current]`, `POST /backup-code-sets`, `POST /google-one-tap-nonces`, `POST /device/code`, `POST /device/token` (300 polls per 15 minutes), `POST /device-authorizations/decisions`, `POST /sso-authorizations`, `POST /sso/callback`, `POST /sso/saml/acs/{providerId}` and `POST /oauth2/token` (60 per minute). The table on `defaultEndpointRules` gives each limit. A deployment that relied on these being unlimited (a backend making many `POST /oauth2/token` calls from one address, say) passes its own `rules`.
  - **`/client/testing`'s `makeServerFixture` serves with `ipRateLimit: false`**, since its one in-process client has no address.
  
  The startup error messages name `ipRateLimit: false`. `docs/ARCHITECTURE.md` no longer claims that the HTTP API provides account lockout: `AccountLockoutPlugin`, `IPRateLimitPlugin`, captcha and the passwordless `resendCooldown` stay opt-in, and their defaults are unchanged.
- 93685f4: **Security hardening (#682), breaking:** `allowMissingClientIp: true` no longer starts a handler that would refuse every rate-limited request, and the magic link and the email-verification resend get the 60-second resend cooldown the OTPs have.
  
  - **`allowMissingClientIp: true` without a `trustedProxy` refuses to start.** Under `Http.make` a Web `Request` has no socket address, so with no `trustedProxy` no request has one, and every request the IP limit (`ipRateLimit`), an `IPRateLimitPlugin` or the dynamic client registration limit covers was answered `429`. `Http.make` now throws `ClientAddressConfigError`, and `Http.makeAsync` rejects with it, whenever one of those limits is on with no `trustedProxy`, whether or not `allowMissingClientIp` is set; the error's message says why when it is. Give the handler a `trustedProxy` (for example `ClientIP.cloudflare`), or pass `ipRateLimit: false`, still the only way to serve without the IP limit. With a `trustedProxy`, a request whose forwarded address is missing or unusable is refused with `429` on a limited endpoint as before.
  - **Magic link and email verification have a 60 s `resendCooldown` by default** (was off for the magic link, and absent for email verification), as the email and phone OTPs have since #590; `0` turns it off. `MagicLinkConfig.resendCooldown` defaults to `60_000`. `EmailVerificationConfig` gains `resendCooldown` (default `60_000`): `resendVerification` fails with `ResendTooSoonError`, sending nothing and keeping the outstanding link usable, when the user's newest token is younger than it. `POST /email-verifications` and the `AuthLifecycleService` sign-in and duplicate sign-up resends answer a resend inside the window as they answer any other, so it never tells an unverified account from an unknown address.
  - **`EmailVerificationStore` has a new method, `getLatestByUserId(userId)`**, the user's verification with the greatest `createdAt` or `null`, which the cooldown reads. The `./sql` store, `EmailVerificationStoreKV` and effect-auth-drizzle's token store implement it; a custom store must add it.
  - **The default IP limits stay**, and the README and `ipRateLimit`'s TSDoc now show how to override one endpoint: the first matching rule wins, so a rule ahead of `...Http.defaultEndpointRules` (for example a higher `POST /oauth2/token` limit for a confidential client's backend calling from one address) replaces that endpoint's default and keeps the rest.
- f43b53d: **Security fix (#684):** every unauthenticated send is capped per recipient, so clients spread across many addresses can no longer flood one email address or phone number with codes and links (email bombing, SMS toll fraud).
  
  - **The cap.** `EmailOtpService.send`, `PhoneOtpService.send`, `MagicLinkService.send`, `PasswordResetService.requestPasswordReset` and `EmailVerificationService.resendVerification` allow at most 5 sends per recipient and purpose an hour by default. A new `recipientSendLimit` option on each service's config (`RecipientSendLimit`: `{ max, windowMs }`) changes it, and `false` turns it off. A send past it fails with `RateLimitError` (`429` over HTTP, `retryAfter` set to what is left of the window). The cap comes on top of the `resendCooldown`s and the OTP failure backoff, and counts only the sends they let through. `PhoneOtpService`'s `phone-verification` sends count too.
  - **No enumeration.** The cap counts a request whether or not the address has an account, so an unknown address is refused exactly as a known one. `POST /email-verifications` and the `AuthLifecycleService` sign-in and duplicate sign-up resends answer a capped resend as they answer any other, as they do inside the cooldown.
  - **Storage.** The counts go through the existing `RateLimitStore`, under `recipient-send:<purpose>:<digest>` keys, where the digest is `hashToken` of the normalized address: no raw address is stored. The five services therefore now require a `RateLimitStore` in their layer's context. `layerKV`, `./sql`'s `layer` and `Testing.memoryStores` already provide one; a hand-built composition adds one (`RateLimitStoreKV` over a `KeyValueStore`, for example). `Testing.memoryRateLimitStore` is a map-backed one for tests.
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
- 68faced: `SessionCookieCache`'s gate attributes are now an Effect `HashSet<string>` instead of a native `ReadonlySet<string>`, matching `UserService`'s `serverOnlyAttributes`: `sessionCacheGateAttributes` yields one, and `encodeSessionCacheCookie` / `decodeSessionCacheCookie` take one as their `gateAttributes` argument (#443).
  
  **Breaking:** a caller that passes a native `Set` as `gateAttributes` must pass a `HashSet` instead. Migration: `HashSet.fromIterable(set)`.
- b96f201: **Security hardening (#669), breaking:** no hook ever sees a raw session token. `beforeValidateSession` and `beforeSignOut` now receive the session's stored id, `hashToken(token)` (the SHA-256 digest `session.id` already carries), instead of the token the client presented, so a plugin can no longer read, log or forward the credential. This completes #581, which moved every response body, cache cookie and after-hook to the stored id.
  
  - **Both hooks are observe-or-deny.** A plugin refuses the validation or the sign-out by failing, as before. What the hook returns is no longer read back: `SessionService.validateSession` and `invalidateSession` look up and delete the session the presented token names, so a hook cannot rewrite the token or redirect the operation to another session.
  - **Migrating a plugin:** compare `ref.sessionId` with `session.id` (or `hashToken(token)`), not with the cookie value. A plugin that rewrote the token has no replacement; validate a different credential before calling the service instead.
- c50edb9: Security fix: a sign-up can no longer set authority-bearing attributes (#580). An unauthenticated `POST /users` carrying `attributes: { role: "admin" }` created an admin, because `UserServiceConfig.serverOnlyAttributes` was enforced only on `updateUserAttributes`.
  
  - **Breaking:** `POST /users` now keeps only the `attributes` keys named in the new `signUpAttributes` option of `Http.make` / `Http.makeAsync` (also the third argument of `groupLayers` and `usersGroupLayer`). The default is none, so a client that set attributes at sign-up must have them listed there. A key the list doesn't name is dropped without an error; the kept attributes may take at most `SIGN_UP_ATTRIBUTES_MAX_BYTES` (4096) bytes as UTF-8 JSON, and a larger bag is refused with `400`.
  - `EmailPasswordService.signUp` (and so `UsernameService.signUp`) and `AuthLifecycleService.signUp` always drop, whatever the allow-list says and after the `beforeSignUp` hooks, the `UserService`'s server-only attributes (default `["role"]`) and the new `SIGN_UP_PROTECTED_ATTRIBUTES`: the ban keys (`banned`, `banReason`, `banExpires`), the SCIM keys (`scimUserName`, `scimDeactivated`, `scimExternalId`) and `isAnonymous`. Set those after the user exists, through `AdminService` or SCIM. Anti-enumeration stand-in users carry the same stripped attributes.
  - `./client/testing`'s `makeServerFixture` takes `signUpAttributes` too.
- 63e45ac: **Security fix (#685), breaking:** the OAuth and OIDC SSO callback `state` is single-use. Before, `SsoService.handleCallback` (`POST /sso/callback`) and `OAuthService.handleCallback` / `signInWithCallback` / `linkAccount` read the state with `OAuthStateStore.get` and deleted it only after a successful code exchange, so a state stayed valid for its whole 10-minute window after a failed exchange, and two concurrent callbacks carrying it both passed the check. A captured callback could be replayed. Each callback now spends the state first, with an atomic get-and-delete, and refuses any later use, successful first use or not.
  
  - **`OAuthStateStore` replaces `get` and `delete` with `consume(state)`** (breaking for a store you implement): atomically fetch and delete the entry, `null` when it is unknown or already consumed. Two concurrent callers passing the same state must not both receive it. `./sql`'s `makeOAuthStateStore` (SQLite, D1 and PostgreSQL) implements it as one `DELETE … RETURNING`; `oauthStateStoreKV` runs its read and remove under a semaphore the store owns, which makes it atomic within one process only, since a `KeyValueStore` has no get-and-delete. Behind several instances sharing one backend, use `./sql` or a store with a native atomic consume (Redis `GETDEL`).
  - **A replayed callback fails** with `OAuthStateNotFoundError` (message "OAuth state not found, expired or already used") from `OAuthService`, and with `SsoError` ("SSO state not found, expired or already used") from `SsoService`, which `POST /sso/callback` answers with `400`. `linkAccount` now spends the state before it checks the provider, so a state presented for the wrong provider is spent too.
  - The SAML `RelayState` was already single-use: it lives only on its `AuthnRequest` record, which `SamlReplayStore.consume` spends. Regression tests now replay the ACS POST as well.
- e57ea3c: Add `Testing.sessionServiceLayer({ users, config? })`, `Testing.apiKeyServiceLayer({ keys?, config? })` and `Testing.memoryApiKeyStore` (also part of `Testing.memoryStores`) to `./testing`: `SessionService` and `ApiKeyService` over seeded in-memory stores, so tests need not assemble them by hand.
- e1770e3: Security fix (#584): `trustedProxy: { hopCount }` no longer lets a client choose its own rate-limit key on a Web `Request`. A Web `Request` (what `Http.make` handles) has no socket address, but `resolveClientIP` indexed the chain as though the socket peer were its last entry, so it selected one entry too far left: under `hopCount: 1` an honest client behind one proxy (`X-Forwarded-For: 203.0.113.9`) was refused with `429`, while a client that prepended a fresh value to every request (`X-Forwarded-For: 10.9.9.<i>, 203.0.113.9`) got a fresh bucket each time and was never limited. The same address feeds `ipRateLimit`, `IPRateLimitPlugin`, the `/register` limit and every hook that reads `ClientIP`.
  
  With no socket address, `hopCount: n` now selects the `n`-th header entry from the right, the one the outermost trusted proxy wrote; with a socket address the arithmetic is unchanged. Under both `hopCount` and `trustedProxyCidrs`, header entries are now parsed as single IPv4 or IPv6 literals (IPv6 canonicalised as RFC 5952, IPv4-mapped IPv6 as dotted IPv4, as `ClientIP.trustedHeader` already did): a selected entry, or one a trusted proxy wrote, that is not an IP literal (`garbage`, a hostname, `203.0.113.9:443`, `[2001:db8::1]`) resolves no address instead of becoming a key, and `trustedProxyCidrs` no longer skips such an entry to reach one further left. A `hopCount` that is not a non-negative integer resolves no address.
  
  Migration: under `Http.make`, a `hopCount` set one higher than the number of proxies to make the old arithmetic work should now be the real number of proxies; `hopCount: 0` there trusts no header entry and resolves no address. A request whose address no longer resolves is refused with `429` on rate-limited endpoints, never let through.
- 88cd0a1: Security fix (#591): WebAuthn challenges are bound to their ceremony, user verification is enforced, and registration stores the attested credential.
  
  - **Ceremony binding.** `WebAuthnChallenge` gains a required `ceremony: "registration" | "authentication"` (`Auth.MultiFactor.WebAuthnCeremony`, with `isWebAuthnCeremony`). `verifyRegistration` refuses an authentication challenge and `verifyAuthentication` a registration one, so a user-bound login challenge can no longer be answered with an attestation that registers an attacker's key on the victim's account. A stored challenge with no known ceremony reads as `null`, so challenges in flight at upgrade must be reissued.
  - **`verifyRegistration(userId, challenge, response)`** now takes the signed-in user's id first (from the session, never the request) and refuses a challenge issued to anyone else; the credential is filed under that id.
  - **User verification.** `userVerification: "required"` is enforced in both ceremonies: a response without the UV flag is refused. `RegistrationResult` and `AuthenticationResult` report `userVerified`, `backupEligible` and `backupState` (`AuthenticatorFlags`); `RegistrationResult.verified` is replaced by `userVerified`. A backup state on a credential that is not backup eligible is refused.
  - **Registration storage.** The stored credential id is the one inside the attestation, which must equal `response.credentialId`, and an id already registered (to any user) is refused rather than overwritten.
  - **Smaller checks.** A `clientDataJSON` with `crossOrigin: true` is refused, an ES256 key must be on P-256, and a malformed public key fails with `WebAuthnVerificationError` instead of a defect.
  - **Stores.** `ChallengeStoreKV` persists the ceremony. `./sql` keeps it in a new table, `auth_webauthn_challenge_ceremonies` (run `migrate`; D1 and Alchemy Postgres deployments pick it up through `AuthSchema`), and `ChallengeStore.delete` now runs in a transaction. `./testing` adds `challengeStoreConformance`.
  
  Migration: pass the session's user id as the first argument of `verifyRegistration`; read `userVerified` instead of `verified`; a custom `ChallengeStore` must store and return `ceremony` (check it with `Testing.challengeStoreConformance`).

### Patch Changes

- ea7f4ea: The JSON:API conversion of the HTTP tier is complete (#205, slice 6). Every endpoint effect-auth designs is a JSON:API resource operation; the endpoints whose wire format another specification fixes (RFC 8628's `/device/code` and `/device/token`, OAuth 2.0 / OIDC's `/oauth2/*`, RFC 7591 / 7592's `/register`, RFC 8414 and OIDC discovery, the JWKS, the SSO callbacks and SAML metadata, and SCIM 2.0) keep it as the RFC tier, recorded in [ADR-0024](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0024-json-api-http-tier.md). No endpoint's behaviour changes in this release.
  
  - **Migration guide:** [docs/guides/jsonapi-migration.md](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/jsonapi-migration.md) maps every removed route to its replacement in one table, with the store-contract changes (`getMemberById`, `getTeamMemberById`, `getOrgRoleById`, the `TeamMember` and `OrgRole` ids, `addTeamMember(record)`), the client method changes and the status-code changes.
  - **Endpoint reference:** the README's "HTTP endpoint reference" lists the JSON:API resources and the RFC tier, each RFC endpoint with its specification and wire format.
  - The doc comments on the `./http` groups (`Http.sessionsGroup`, `Http.adminUsersGroup`, `Http.impersonationsGroup`, `Http.oauthClientsGroup`, `Http.ssoProvidersGroup`, `Http.ssoAuthorizationsGroup`, `Http.tokensGroup`, `Http.deviceAuthorizationsGroup`) no longer name the routes they replaced.
  - The RFC tier is pinned by tests: the OpenAPI document declares `application/vnd.api+json` on every resource group and on no RFC-tier endpoint, each RFC endpoint's media type is checked on the wire, and the browser client may call only routes the contract serves.
- f49ee5d: Drop redundant default type arguments from the published declarations (`Redacted.Redacted<string>` is now written `Redacted.Redacted`, `Effect.Effect<A, E, never>` is `Effect.Effect<A, E>`, and so on); every type is unchanged (#503). Values that were stringified with `String(…)` are now converted explicitly: an OAuth profile id that is neither a string nor a number becomes `""` rather than `"[object Object]"`, the unsupported `id_token` algorithm error formats the header value (`"HS256"`), and a Twilio error body whose `code` or `message` is not a string is rendered as JSON.
- cc2bac6: Import Effect's helper modules (`Array`, `Option`, `Predicate`, `Record`, `Schema`, `String`) from their own entry points (`effect/Array`, …) rather than the `effect` barrel. The emitted `dist/` and `.d.ts` change their import specifiers only; no API or behaviour changes.

## 0.2.0

### Minor Changes

- 55637b0: `Cacheability.publicReach` and `publicReachByType` add a drift guard for viewer-less caches (#191). They compile each resource type's read scope for the anonymous principal and classify the type. `All` means every row is public, so a cache may admit the type wholesale. `Some` means only the rows a filter admits are public: check each representation with `publiclyServeable`. `None` means no row is public. `Undecided` means the policies read rows in a way a scope can't express, and it never counts as public. Pin the result in a test: a policy change that moves a type from public to owned then fails the build, where a hand-kept list of public types would go stale without anyone noticing.
- 1cacf66: Drop the error paths for drawing randomness, which cannot fail: Effect 4.1's `SecureRandom` has a `never` error channel (#520). `generateVerificationToken` and `generateMagicLinkToken` now return `Effect<string>` (was `Effect<string, AuthError>`); a `catchTag("AuthError", …)` on either can go. `generateState` and `generateNonce` drop a no-op `Effect.orDie`. The services' own signatures are unchanged; they no longer produce an `AuthError` they could never raise.
- 7f12561: The in-memory stores and `EntitySlice` use Effect collections instead of native `Map`s and `Set`s (#443).
  
  Migration (these are test and single-process helpers):
  
  - Every `memory*Store` that took a pre-seeded `Map` now takes a `MutableHashMap` from `effect`: `memorySessionStore`, `memoryMultiFactorStore`, `memoryTrustedDeviceStore`, `memoryOtpSecondFactorStore`, `memoryOAuthAccountStore`, the four `memoryOidc*Store`s, `memoryIdentifierStore`, `memoryAccountLockoutStore`, `memoryOrganizationDomainStore`, `memorySamlReplayStore`, `memoryScimConnectionStore` and `memoryPolicyStore` (its `policies`, `templates` and `links`). `MemoryUserTable`'s `users` and `passwordHashes` are `MutableHashMap`s too. Build one with `MutableHashMap.empty()` or `MutableHashMap.fromIterable(entries)` and read it with `MutableHashMap.get` (an `Option`), `MutableHashMap.values` and `MutableHashMap.size`.
  - `EntitySlice.entities` is a `HashMap<string, Entity>`. Build slices with `Entity.slice` and read them with `Entity.getEntity`, as before; code that read `entities` directly uses `HashMap.get`.
  - `./client/testing`'s `makeServerFixture` returns `sessions`, `usersById`, `identifierRecords` and `domainRecords` as `MutableHashMap`s and `publishedDnsDomains` as a `MutableHashSet` (`MutableHashSet.add(fixture.publishedDnsDomains, domain)`).
- 47534bb: `purgeExpiredKV` no longer requires `KeyValueStoreKeys` (#521). Without one, it finds the records through the `KeyValueStore`'s own `keys`, new in Effect 4.1, so it runs over any store, `KeyValueStore.layerMemory` included. `KeyValueStoreKeys` stays as an optional prefix listing for backends that list one prefix more cheaply than they list every key, such as a large or shared Workers KV namespace, or Redis. When it is provided, the purge uses it.

### Patch Changes

- 3c140a6: Ship `CHANGELOG.md` in the published tarball, so the release notes can be read from `node_modules` (#545).
- e52a95d: Pay down oxlint adoption allowances (#503): `AuthDatabase.delete` drops its unused type parameter, and the core's message catalog, header detection and client session refresh are rewritten without behaviour changes for valid inputs.
- 4c48eb4: `./saml`: the tamper check on `InResponseTo` reads the values from the raw XML rather than from node-saml's `profile.inResponseTo` (#532). node-saml 5.2 fills that field from the signed confirmation data, so on 5.2 the check compared the signed value with itself and never fired. A rewritten Response attribute is rejected again on both 5.1 and 5.2. So is any second `InResponseTo` anywhere in the document that disagrees with the signed one.

## 0.1.0

### Minor Changes

- 68709bf: The API layout: directory structure, package exports, service classes and naming conventions.
  Highlights:
  
  - The package is published as `@thomasfosterau/effect-auth` (the bare `effect-auth` npm name
    belongs to an unrelated package), and the client as `@thomasfosterau/effect-auth/client`.
  - Feature modules live in lowercase cluster directories (`email/`, `http/`, `oauth/`,
    `password/`, `plugins/`, `multifactor/`), and the package publishes
    per-cluster subpath exports (`@thomasfosterau/effect-auth/email`, `.../http`, ...) alongside
    the root export. Authorization and session management are deliberately _not_ clusters: their
    modules (`Policy.ts`, `Entity.ts`, `Authorizer.ts`, `Protected.ts`, `Rbac.ts`,
    `SessionService.ts`, `SessionStore.ts`, `UserStore.ts`, `TrustedDevice.ts`, …) sit flat in
    `src/` and are reached from the root (`Auth.Policy.permit`, `Auth.Rbac.layer`,
    `Auth.SessionService`), with no `./authz` or `./session` subpath.
  - Service tag strings and exported type names match their class names exactly, and every
    acronym follows Effect's Pascal-case convention — `ApiKeyService`, `OidcProviderService`,
    `JwtService`, `ScimService`, `SsoService`, `SamlVerifier`, `EmailOtpStore`,
    `OtpSecondFactorService`, `SmsSender`, and the `Auth.Http` cluster namespace. Only
    SCREAMING_SNAKE constants (`DEFAULT_OIDC_SCOPES`, `SCIM_USER_SCHEMA`) and protocol wire
    values (HTTP paths, operationIds, `SAMLResponse` form fields, `type: "oidc" | "saml"`)
    keep their all-caps spelling.
  - There are no `*Shape` interfaces; an implementation's type is `typeof FooService.Service`.
  - Services resolve their store and session/hook dependencies once at Layer construction, so
    method signatures carry `R = never` and dependencies are wired into the service layer rather
    than threaded through each call.
  - Most services use Effect's `Crypto` service rather than `node:crypto`; a layer built from a
    raw `make` needs `Crypto.Crypto` (or a test double) in context.
  - Constructors are module-scoped `make` / `layer` exports.
- 106bb64: `makeAuthorizationMiddleware` takes the guard's name as its first argument: `makeAuthorizationMiddleware("RequireDocRead", input)`. The name is the guard's TypeScript type, so attaching one guard to an endpoint and providing only another guard's `.layer` is a compile error rather than a runtime missing-service failure (#320). Two guards built with the same name literal share a type, so a mix-up between them is not caught at compile time.
  
  The name must be one non-empty string literal. A `string`, a template pattern such as `` `${string}Guard` ``, a union or `""` is a compile error: the first three would widen the guard's type to the others', and the last names no guard. The name also labels the runtime tag, `@effect-auth/AuthorizationMiddleware/<name>#<n>`, which stays unique per call.
  
  The middleware's types are checked rather than widened to `any`, so an attached guard's requirements (`Authorizer`, `CurrentPrincipal`, and the input's own services other than the router's per-request ones) appear in the endpoint's layer requirements. New export: `AuthorizationRequires`. `AuthorizationMiddlewareClass` and `AuthorizationMiddlewareInstance` take the name as an optional second type parameter, defaulting to `string`.
- 95f9ba6: Add the two viewer-less-cache questions, kept apart (#191). `Cacheability.publiclyServeable(axes)`
  answers whether a representation may be stored in and served from a cache with no viewer in its key,
  failing closed on every declared axis (a present value must be exactly the serveable literal; a
  required axis that is absent is not serveable; an `absent: true` axis such as `deletedAt` refuses any
  value). `OwnedAccess.serveableAxes` are those axes derived from the owned-read policy, and admit a row
  exactly when every viewer, anonymous included, may see it. `Cacheability.bypassesForFreshness(guards,
  axes)` answers the separate question of whether the current viewer must be routed around a
  public-only cache, and `Cacheability.shouldIncludeDeleted(guards, viewDeleted)` requires both the
  opt-in and the rung. The module documents the `private, no-store` rule for any response rendered
  after a principal was resolved, and the ordering that makes it enforceable.
- 29d011c: Client IP resolution can trust one named header. `TrustedProxyConfig` has a third form, `{ trustedHeader: "<name>" }`, which reads only that header and takes it as the client address when it holds exactly one IPv4 or IPv6 address. An accepted IPv6 address is canonicalised (RFC 5952) and an IPv4-mapped one becomes dotted IPv4. An absent, empty or malformed value, a comma-separated list, or duplicate headers fall back to the socket address; a Web `Request` under `Http.make` has none, so then no address resolves (#358). `X-Forwarded-For` and every other header are never read.
  
  Two named forms sit on the `ClientIP` service. `ClientIP.trustedHeader(name)` builds that configuration, and `ClientIP.cloudflare` is the preset that trusts `CF-Connecting-IP`. Pass either as `trustedProxy` to `Http.make`, or to `clientIPLayer`, so per-IP rate limits key on the visitor's address behind Cloudflare. The trust assumption is opt-in: it holds only when the app is reachable solely through that edge, and the TSDoc and README state it.
- afd57ae: Time is read from the `Clock`, and instants from outside are decoded rather than trusted (#443). **Breaking** for these call sites:
  
  - `makeIdentifier` and `PolicyStore.makeLink`: `now` is now **required**. Pass the caller's time, e.g. `now: yield* DateTime.nowAsDate`.
  - `isBanned(user)` now returns `Effect<boolean>`, reading the `Clock`, so `TestClock` decides when a ban lapses: `const banned = yield* isBanned(user)`.
  - `Testing.sessionFor(user, now)` now returns `Effect<SessionWithUser, SchemaError>`, failing on an Invalid Date instead of building one.
  - `Http.fromSessionWithUserView(view)` (`./http`) now returns `Effect<SessionWithUser, SchemaError>`: the remote server's epoch millis are decoded with `Schema.DateFromMillis`. `RemoteSession`'s `read` reports an undecodable instant as a `RemoteSessionError` ("Session read body did not decode").
  
  effect-auth/sql decodes stored epoch-millis columns with `Schema.DateFromMillis`; a value outside the `Date` range fails as an `AuthError` instead of producing an Invalid Date.
  
  effect-auth/saml reads `NotOnOrAfter` instants as UTC via `DateTime`, and **rejects** an instant with no time zone (SAML `xs:dateTime`s must carry one) or one that does not parse, where it used to read a zone-less instant as the server's local time and ignore an unparseable one.
- c1b0737: The browser client, SQL storage and SAML now ship as subpaths of the core (ADR-0022), not as packages of their own:
  
  - `@thomasfosterau/effect-auth/client` — the typed browser client and its observable session store (formerly `@thomasfosterau/effect-auth-client`). Its in-memory server fixture is `@thomasfosterau/effect-auth/client/testing` (formerly `@thomasfosterau/effect-auth-client/testing`).
  - `@thomasfosterau/effect-auth/sql` — every store it covers over `effect/sql`, the `auth_*` DDL and `migrate` (formerly `@thomasfosterau/effect-auth-sql`). It adds no dependency: `effect/sql` ships in `effect`. New: `authTableNames`, the tables the DDL creates.
  - `@thomasfosterau/effect-auth/saml` — the `SamlVerifier` over `@node-saml/node-saml` (formerly `@thomasfosterau/effect-auth-saml`). `@node-saml/node-saml` (`^5.1.0`) is a new optional peer of the core, imported only by this subpath, which is Node-only.
  
  The root barrel reaches none of the three, nor `@node-saml/node-saml`. Replace each former package import with its subpath and depend on `@thomasfosterau/effect-auth`.
- 416fc73: A store's `createUser` receives the login handle the user is created with, as an optional `identifier` (`NewUserIdentifier`: `type`, normalised `value`, `verified` and, when verified, `verifiedAt`) on `CreateUserInput`, `OAuthCreateUserInput`, `MagicLinkCreateUserInput`, `EmailOtpCreateUserInput`, `PhoneOtpCreateUserInput` and the `AdminUserStore.createUser` and `ScimUserStore.create` inputs. Email and password sign-up, magic link, email OTP and phone OTP sign-up, OAuth, SSO and Google One Tap first sign-in, SCIM provisioning (its `userName`) and admin creation (its primary email, trimmed and lower-cased) pass it. A store that keeps the address on the user row writes it there on insert, so a `NOT NULL` address column works with core sign-up; a store that keeps identifiers in a table of their own ignores the field (#380).
  
  Each of those `createUser` seams resolves to a `CreateUserResult`, `{ user, created }`, where `created` is `true` only when the call inserted the user. A writer that finds or creates on the address reports `created: false` for a user who already existed, and the flow fails with the address in use (`IdentifierTakenError`, mapped to each flow's own error) without writing anything to that user: no password, no linked account, no verified address (#406).
  
  `createUserWithIdentifier(identifiers, identifier, create)` creates the user and claims the handle. A `create` that reports `created: false` fails with `IdentifierTakenError` and claims nothing. After a fresh insert, a claim that finds the handle already held by the new user succeeds with that record (marked verified when the flow asked for a verified handle), and a handle another user holds fails with `IdentifierTakenError`, both when the claim loses and when the store's unique index rejects the user row's insert. When the lookup that tells those cases apart fails, `create`'s own error is the result.
- 2d26680: Add a credential class to the resolved principal, distinguishing an interactive session
  (the session cookie) from a machine credential (an `Authorization: Bearer/Token` header —
  the same delivery path a consuming app's own API-key middleware would use), and gate
  minting a new API key on it (#198).
  
  - `Authorizer.CredentialClass` (`"interactive" | "machine"`) and `Authorizer.CurrentCredential`
    — a `Context.Service`, mirroring `CurrentPrincipal`, carrying how the current principal
    authenticated. Kept as its own service rather than folded into the principal entity or the
    session record: neither a bare `EntityRef` nor a machine credential (which has no
    `Types.Session`) has a natural place to carry it, and a separate tag lets non-HTTP callers
    (a worker, a CLI, an RPC handler) provide it without fabricating either.
  - `Authorizer.authorize`/`check` merge `CurrentCredential`, when present, into the decision's
    `context.credentialClass` attribute — visible to declarative policies
    (`Condition.attr("context", "credentialClass")`) and custom policy predicates alike, not
    just to the HTTP layer. The ambient value always wins over anything a caller passes in
    `AuthorizeInput.context.credentialClass`, so a call site cannot spoof its own class.
  - `Http.AuthMiddleware`/`OptionalAuthMiddleware` now also provide `CurrentCredential`
    alongside `CurrentPrincipal`: `"interactive"` for the session cookie, `"machine"` for the
    `Authorization` header. `Http.credentialClassFromRequest` exposes the same classification
    for handlers built outside the middleware.
  - The built-in `POST /api-keys` (`apiKeyCreate`) endpoint now requires an interactive
    credential, failing with `Forbidden` (403, added to its error union) for a bearer-delivered
    session — closing the concrete case this issue named ("a key can mint a key") for the
    API surface this library ships, and giving consuming apps the same primitive
    (`CurrentCredential` + a declarative policy) to gate their own sensitive, session-only
    operations.
- aa7b6e6: Sends that would reveal whether an account exists now go through a host scheduler seam, and every other send is awaited inline again (#196).
  
  - **`DeliveryScheduler`** is the host's way to run work after the response. `DeliveryScheduler.waitUntil(fn)` is for Cloudflare Workers' `ExecutionContext.waitUntil`, and `DeliveryScheduler.forkDetach` (the default) is a detached fiber for long-lived servers. Each send reads the scheduler from the calling fiber, so providing it per request works even when the services are built once.
  - **Off the response path:** the sign-up verification email and existing-account notice, the magic link with `disableSignUp`, email OTP `sign-in` with `disableSignUp` and `forget-password`, phone OTP `sign-in` with `disableSignUp`, and the password-reset email. These flows hand the send to the scheduler whichever callback they were given. A failed send never fails the request: it is logged, counted on `effect_auth_delivery_sends_total`, and passed to the new `afterDeliveryFailure` hook, which `AuditPlugin` logs as `auth.deliveryFailure`. None of these record the message's token or code.
  - **Inline again:** `emailCallbacks` / `smsCallbacks` await their send, so a failed magic link, code, verification email, change-email or delete-account mail, or second-factor code fails the flow that sent it, where existence isn't hidden. Previously every derived send was detached.
  - A failed sign-up send no longer fails the sign-up with `EmailVerificationError`.
  - `EmailVerificationService.createVerification` and `resendVerification` take an optional `{ offResponsePath }`.
  - `EmailSender.logging` and `SmsSender.logging` are explicit development transports. They log each message's recipient and purpose and send nothing.
  - `Testing.inlineDeliveryScheduler` runs detached sends in place for tests.
  - The README's new "Delivery" section lists each flow's posture and the reason for it.
  
  effect-auth-resend adds `layerConfig`, which reads `RESEND_API_KEY` (or a `Config` you pass) and fails the layer's construction when it is missing or empty. There is no no-op fallback; use `EmailSender.logging` explicitly in development.
- 51edf74: Built for Effect `4.1` (#501, #499).
  
  **Breaking peer ranges:** every package above now requires `effect ^4.1.0`, and the Alchemy packages require `alchemy` `2.0.0-beta.85` (effect-auth-alchemy-postgres also `@effect/sql-pg ^4.1.0`). Effect 4.1 removed the root `Crypto` module in favour of `effect/crypto`; alchemy beta.84 and earlier import that removed module, and beta.85 peers on `effect ^4.1.0` itself.
  
  **Breaking — randomness and digests come from `effect/crypto`.** Services that yielded `Crypto.Crypto` now yield `SecureRandom.SecureRandom`, and the ones that hash (OAuth PKCE, the OIDC provider, WebAuthn, `HaveIBeenPwnedPlugin`) also yield `Digest.Digest`. Every `static layer` still provides both through `PlatformCrypto.layer`, so only code that builds a service from its raw `make` changes: provide `SecureRandom.layerWebCrypto` and `Digest.layerWebCrypto` (or your own implementations) where it provided `Crypto.Crypto`. The OTP primitives that took a `Crypto` instance (`generateBase32Secret` and friends) take a `SecureRandom` service instead. `OAuthProvider.generateAuthorizationUrl`, `generatePKCE` and `SsoService.signIn` add `Digest.Digest` to their requirements.
  
  `layerMemoryKeyValueStore` implements `KeyValueStore.keys`, which Effect 4.1 added to the interface. effect-auth-alchemy-cloudflare's `D1Client` names its driver (`SqlClient.driver` is `"d1"`).
- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).
- b165354: **Security — magic link, email OTP, Google One Tap and SSO no longer hand the prover an account whose password someone else chose (#440, following #425).** Each of these flows promotes an email address held unverified to verified when the caller proves it (the link, the code, or the IdP's verified email claim), then signs the caller in. That address's account was created by a sign-up that proved nothing about it, so a squatter who signed up with someone else's address and a password they know kept that password, and their sessions, once the real holder signed in this way. Now, as `AuthLifecycleService.verifyEmail` does since #425, the first proof of an address clears the account's password and revokes all of its sessions before marking the address verified. Signing in to an account whose address is already verified changes nothing.
  
  **Breaking — `EmailPasswordStore` is now required** by `MagicLinkService`, `EmailOtpService` and `GoogleOneTapService` (at layer construction) and by `SsoService`'s callback methods (in their context), to clear the password. An app that runs one of these flows must provide an `EmailPasswordStore`: effect-auth/sql's `makeEmailPasswordStore`, or the app's own, with the `clearPasswordHash` that #425 added.
- cc67083: Framework packages, form components, and adapter reworks.
  
  - The Svelte binding moved out of the client into its own package, `@thomasfosterau/effect-auth-svelte`, authored as Svelte 5 runes `.svelte` components, with six out-of-the-box headless form components: `SignInForm`, `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, `EmailOtpForm`. The client package no longer has `./react`, `./svelte`, `./vue`, or `./types` subpaths; wire types come from the core package's `Http` namespace, and the client's `emailOTP`/`phoneOTP` sections are now `emailOtp`/`phoneOtp`.
  - `@thomasfosterau/effect-auth-drizzle` supports PostgreSQL, SQLite, and MySQL through per-dialect table modules (`Pg`, `Sqlite`, `MySql`) over a structural database seam, and its store modules are namespaced with `make`/`layer` exports (`SessionStore.make`, `UserStore.layer`, `Requests.layer`, ...).
  - `@thomasfosterau/effect-auth-alchemy-cloudflare` was rebuilt: the bespoke D1 wrapper and hand-rolled stores are gone; a D1-backed `SqlClient` now drives the shared `@thomasfosterau/effect-auth/sql` stores, and the `AuthSchema` resource runs through the real Alchemy engine.
- fa438cf: `IdentifierStore.create` gains a typed refusal, `IdentifierRefusedError`, for an identifier a store cannot hold by its own shape: a store that keeps one email per user refuses a second, and an emails-only store refuses any other type. `claimIdentifier` passes it through. SCIM answers it with `409` and `scimType: "uniqueness"` instead of a `500`, so a `userName` change on a one-email store reaches the IdP as a request to reconcile. The other flows (sign-up, email change, username, phone number, admin extras) report it as an `AuthError`, as before, through the new `refusalAuthError` (#379).
  
  effect-auth-drizzle's `SingleTableIdentifierStore` raises `IdentifierRefusedError` where it raised `AuthError` for those two refusals; a user with no row is still an `AuthError`.
- 9ff7ded: `IdentifierStore.replace(from, to)` swaps one of a user's identifiers for a new value: it claims `to` and releases `from` as one change, so the user is never left holding neither. A store with transactions writes both at once; a store without them claims `to` before it releases `from`. It resolves to the replacement, or `null` when the user does not hold `from`, and fails with `AuthError` when another user holds `to`'s value, as `create` does. `replace` is a required member of the contract, so a custom `IdentifierStore` implements it (see `docs/guides/byo-stores.md`). `memoryIdentifierStore` and `IdentifierStoreKV` implement it, and `replaceInputError` gives an implementation the shared refusal for a `to` with another user, another type, `from`'s own id or the same value. Of two concurrent replaces of the same `from`, the in-memory store lets one succeed; `IdentifierStoreKV` checks `from` before it writes and releases it unguarded, so both can succeed and leave the user holding both new values.
  
  `replaceIdentifier(store, from, to)` calls it with readable failures: `IdentifierTakenError` when another user holds the value, `IdentifierNotFoundError` when the user does not hold `from` (including when the store refused `to` because a concurrent replace of `from` already gave the user that value), `AuthError` for other store failures.
  
  `AccountManagement.confirmEmailChange` changes the user's email of record through `replaceIdentifier`, then releases any other email the user holds; a user with no email claims the new one. If the email of record changes during the confirmation, it succeeds when the user already holds the new address (a double-submitted confirmation) and otherwise fails with `AccountTokenError`, keeping the token. A user with no email whose claim finds the address already theirs succeeds the same way, and in every case the new address ends verified; when a concurrent delete removes the new address first, the confirmation fails with `AccountTokenError` and keeps the token. It works on every identifier store, including one that holds a single email per user (#381).
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
  - effect-auth/client: `changePassword`, `changeEmail`, `deleteUser` and `multiFactor` keep their arguments and results and call the new endpoints.
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
  
  effect-auth/client keeps its method signatures and maps the documents onto the same view types. `revokeSession(id)` now takes the id `listSessions()` reports, and an error's `message` is read from a JSON:API error document's `detail`.
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
- c1ba5f6: The last-login-method plugin's constructor is now `LastLoginMethodPlugin`, matching its siblings (`AuditPlugin`, `RateLimitPlugin`, …), instead of a bare `make` (#284). Through the barrel it surfaced as `Auth.Plugins.make` (and `make` from `@thomasfosterau/effect-auth/plugins`), which read as a constructor for the whole plugins cluster. Like the other plugins that take no config, `LastLoginMethodPlugin` is the layer itself rather than a function: replace `Plugins.make()` with `Plugins.LastLoginMethodPlugin`. It still requires `SessionService` and isolates its taps.
- 2484af6: `Http.makeAsync` is the asynchronous counterpart of `Http.make`, for `services` that build asynchronously: a database connection or other `Effect.promise` step, merged layers that yield, or finalizers that do asynchronous work. It takes the same options, waits for the `services` build however it is composed, and resolves to the same `{ handler, dispose }`. The handler serves that one build, and `dispose` releases it. The promise rejects with the errors `make` throws, so the app fails to start: `ClientAddressConfigError`, `RateLimiterConfigError`, or any failure of the `services` build (its error, or for a defect the defect itself). It releases what the build acquired and waits for every finalizer, asynchronous ones included, then rejects; a finalizer that fails is logged as an error. `Http.AuthWebHandler` names the `{ handler, dispose }` pair that both constructors return (#400).
- 90d7a79: `Http.make` takes `strict`, an opt-in for an app that wants `make` to fail at startup whenever it cannot check the `services` build. With `strict: true`, `make` throws `ServicesBuildPendingError` when the `services` build has not finished after `make` has run it synchronously: a build that waits on asynchronous work (a database connection, `Effect.promise`), on a merged layer that yields, on a forked fiber, or, when the build fails, on a finalizer that does asynchronous work. The error's message names `Http.makeAsync`, which waits for such a build. `make` interrupts the build and releases what the build acquired, as far as that runs synchronously, then throws; a finalizer that does asynchronous work, and the whole release of a build in an uninterruptible step that awaits (an `Effect.acquireRelease` acquire), finish after `make` has thrown. When the build fails on its own account, as a step that fails while a finalizer it runs awaits does, `make` logs that failure with `Effect.logError` once the build ends. A build that finishes synchronously is unaffected: `make` throws the startup errors or the build's own failure, or returns the handler. Without the option, `make` returns for an unfinished build, and the startup checks run when the build finishes, failing the handler's build. `Http.makeAsync` ignores the option. `ServicesBuildPendingError` is exported from the package root and as `Http.ServicesBuildPendingError` (#416).
- d767491: Core and effect-auth/saml no longer use the Node `Buffer` global outside the `node:crypto` corral (`password/Password.ts`, `TokenHash.ts`, `Cipher.ts`): encoding goes through `effect/encoding` (`Base64`, `Base64Url`, `Hex`), `TextEncoder` and `Uint8Array`, so these modules don't depend on a Node global in Workers and browsers (#481). Lint now rejects `Buffer` outside that corral and Node-only code.
  
  **Breaking — the OTP primitives use `Uint8Array`, not `Buffer`.** `generateSecret` and `decodeBase32` resolve to a `Uint8Array`, and `encodeBase32`, `generateHotp`, `verifyHotp`, `generateTotp` and `verifyTotp` take one (a `Buffer` is still accepted, since it is a `Uint8Array`).
  
  Decoding is now strict where `Buffer` was lenient: `constantTimeHashEqual` is `false` when either side is not hex (two different non-hex strings used to compare equal); a JWT segment that is not base64url fails as malformed; a session-cache cookie or `Authorization: Basic` value that is not base64 is ignored; a WebAuthn base64url value that does not decode reads as no bytes. effect-auth/saml drops whitespace from a `SAMLResponse` before decoding it, so a line-wrapped one is accepted, and rejects one that is not base64 with "SAMLResponse is not valid base64".
- 7f5206e: A rate limit that cannot run refuses the request or stops the app from starting; it never skips silently (#389).
  
  - **Missing `RateLimiter`.** `Http.make` throws `RateLimiterConfigError` (exported from the package root) when a limit is configured and no `RateLimiter` is in `services`. The limits are `ipRateLimit`, the dynamic client registration limit and the device user-code limit on approve/deny. `make` builds `services` once, synchronously where it can, and the handler reuses that build. When `services` does asynchronous work while building, `make` cannot see the result before it returns: the handler's build fails with the same error instead, and every request rejects with it.
  - **Device user-code limit.** It counts as configured whenever a `DeviceAuthorizationService` is in `services`. `DeviceAuthorizationConfig.allowMissingRateLimiter: true` is the explicit opt-out: approve and deny then run without the limit when no `RateLimiter` is present.
  - **`IPRateLimitPlugin` needs an address source.** `Http.make` throws `ClientAddressConfigError` when the `Hooks` in `services` include `IPRateLimitPlugin` and neither `trustedProxy` nor `allowMissingClientIp: true` is set, because a Web `Request` has no socket address.
  - **Requests that cannot be limited are refused.** `IPRateLimitPlugin` fails a hook with `RateLimitError` (`429` over HTTP) when the request has no client address, including when no `ClientIP` service is in scope, as for a hook run outside an HTTP request. The group layers composed by hand outside `Http.make` (`authGroupLayer`) answer `429` when a configured limit has no `RateLimiter` in scope, or when the registration limit has no client address. Such a request is never let through unlimited and never counted under a bucket shared with other callers.
- e6c3a64: Dynamic client registration is rate limited per client address, keyed on the `ClientIP` that `Http.make` and `Http.makeAsync` resolve from their `trustedProxy`, the one address source every address-keyed limit shares (#388, #398). With registration enabled in the `services`' `OidcProviderService` and neither `trustedProxy` (for example `ClientIP.cloudflare`) nor `allowMissingClientIp: true`, `Http.make` throws `ClientAddressConfigError` at startup and `Http.makeAsync` rejects with it, before any request. `allowMissingClientIp` skips only that check: a registration with no address is refused with `429`, and is never counted under a shared bucket. `mcpProviderPreset` always enables dynamic registration, so an MCP server's handler must set one of the two. `OidcDynamicRegistrationConfig` has no address options of its own, and `OidcProviderService.layer` no longer fails with `ClientAddressConfigError`.
- 39654ad: One authorization model: the policy kernel. RBAC is authoring sugar that compiles into it, and
  there is no separate flat permission-string path. See
  [ADR 0018](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0018-one-authorization-kernel.md)
  for the decision and the rejected alternative, and
  [the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/authorization-kernel-migration.md)
  for moving code written against the earlier `RoleStore` / `AuthorizationPolicy` design.
  
  **Why.** Only the kernel can be partially evaluated: a read scope needs an unbound resource slot
  and a condition AST to residualise, and `checkPermission(userId, resource, action) => boolean` has
  neither. A rule authored through the flat path could therefore never participate in read
  authorization — a property of its shape, not a gap in its implementation. Two evaluation paths
  also meant two places a security control could live, with no rule saying which one wins.
  
  `Auth.Rbac` is a namespaced root export and a **policy builder**. A
  `{ userRoles, rolePermissions, roleHierarchy }` configuration produces kernel artefacts:
  
  - `Rbac.policies(config)` — one `DeclarativePolicy` per (role, permission) pair, scoped
    `principal in Role::"<role>"` / `action == Action::"<action>"` / `resource is <resource>`.
  - `Rbac.entities(config)` — the principal → role → parent-role entity fragment.
  - `Rbac.model(config)` — the derived `AuthorizationModel` the generated policies validate against.
  - `Rbac.entityResolver(config)` / `Rbac.entityResolverLayer(config)` / `Rbac.layer(config)` — the
    one-call `Authorizer` setup.
  - `Rbac.RbacConfig`, plus `Rbac.roleRef`,
    `Rbac.policyId` and the `RoleEntityType` / `ActionEntityType` / `DefaultPrincipalType` constants.
  
  `{ resource: "*", action: "*" }` compiles to a permit with both slots unscoped. Role inheritance
  is a `Role -> Role` edge resolved by the kernel's cycle-safe `in` check rather than a pre-expanded
  permission set, so an inherited grant is determined by the _parent's_ policy id in the trace.
  
  **`@thomasfosterau/effect-auth/sql`.** The RBAC tables feed the kernel in two halves:
  `makeRbacEntityResolver` / `RbacEntityResolverLayer` project `auth_user_roles` into `Role::`
  parents, and `readRbacPolicies` compiles `auth_role_permissions` into declarative permits via
  `Rbac.policies`. Neither is part of the bundled `Sql.layer` — `EntityResolver` is a slot an
  application composes, not a store to bundle — and `readRbacPolicies` reads once at wiring time
  (put policies behind a `PolicyStore` if tenant edits must apply without a restart).
  
  `Errors.PermissionDeniedError` is exported for application use, but nothing in the library raises
  it; a kernel denial is `Policy.AuthorizationDeniedError`, which carries the full `Decision` trace.
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
- ec17f5d: `OwnedAccess.policies` are read policies (#387): each `owned:public`, `owned:owner`, `owned:view-private` and `owned:follower` permit is scoped to `Action::"read"`. Handed to an `Authorizer` alongside write gates, the set allows a user nothing on update or delete, including on a public row. `canView` and `readScope` decide reads only, and they agree with these policies on every read, so the drizzle `ownedListFilter` agreement holds.
- 8e5fc41: Add owned-material read access and its drizzle rendering (#190).
  
  `Auth.OwnedAccess.make({ guards, viewPrivate })` interprets a three-state visibility axis
  (`public | followers | private`) plus an orthogonal `draft` flag, in two shapes built from the same
  facts: `canView(row)`, the per-row predicate (never fails — a `false` is a 404 to the caller,
  decided by the policy kernel over `OwnedAccess.policies`), and `readScope`, the per-request
  `all | public | member(userId, following)` scope a list renders as its `WHERE`. The `followers`
  state resolves through the `IsFollower` service (a row check plus the viewer's follow set) read with
  `Effect.serviceOption`, so a runtime that does not provide it fails closed; `isFollowerNever` makes
  that explicit.
  
  `@thomasfosterau/effect-auth-drizzle` adds `ownedListFilter(columns)(scope)`, which renders the scope
  over any table's or view's owner / visibility / draft columns — the follow set nested as an
  `owner IN (SELECT …)` subquery, never a materialised list — and `isFollowerLayer`, the follower seam
  over an application's own follow table. A property test runs the rendered filter and `canView` over
  one corpus in PGlite and requires them to agree on every row.
- c99689b: The `password` cluster no longer exports `PasswordReset`'s raw `make` (#259). Through the barrel it surfaced as `Auth.Password.make` (and `make` from `@thomasfosterau/effect-auth/password`), which reads as the cluster's password hasher but built a `PasswordResetService`. Build the service with `PasswordResetService.layer(config)`, the same public constructor the `email/` and `multifactor/` services use. The rest of the password-reset surface (`PasswordResetService`, `PasswordResetStore`, `PasswordResetUserStore` and the `PasswordResetToken`, `PasswordResetConfig` and `PasswordResetResult` types) is unchanged.
- 3de5d6a: `pbkdf2Hasher` takes an `iterations` option, as `scryptHasher` takes `cost`, and `PasswordHasher.layer` forwards it: `pbkdf2Hasher({ iterations })` and `PasswordHasher.layer({ iterations })`. The default is unchanged at 600,000 iterations (the OWASP figure for PBKDF2-HMAC-SHA256), so existing callers and stored hashes behave exactly as before. The count must be an integer from 1 to 2147483647, Node's limit for `crypto.pbkdf2`. `hash` refuses any other value with a `HashingError` rather than writing a hash `verify` cannot read. `needsRehash` compares stored hashes against the configured count, so a hash made at a lower count is upgraded on the next successful sign-in. `verify` still reads the count from the stored hash, and refuses, before running PBKDF2, a stored count above max(5,000,000, the configured count). Lower counts are for tests and other cases where cost is not the point; keep the default in production (#290).
- a108a36: Add `makeApiKeyStore`/`ApiKeyStoreLayer` and `makeAdminUserStore`/`AdminUserStoreLayer`, closing the two SQL storage gaps blocking the API-key and admin planes.
  
  - **`ApiKeyStore`** backs a new `auth_api_keys` table. Every core field round-trips, including `permissions`/`metadata` (JSON), the refill quota fields, and the optional per-key `rateLimit`; `key_hash` carries a unique index for `getByHash` lookups and, like every other bearer-token column in this schema, is the only form of the key ever persisted.
  - **`AdminUserStore`** reuses `auth_users` (via the same `userQueries` helpers as `EmailPasswordStore`) for `createUser`/`setPasswordHash`, and resolves `listUsers`'s `searchEmail` against each user's earliest `auth_identifiers` email record — matching, sorting, and paginating in memory, mirroring the reference semantics in core's `Admin.test.ts`.
  
  Both are now included in the aggregate `layer` export and `migrate`'s schema statements.
- ef58828: Publish testing fixture as a public entry point at `@thomasfosterau/effect-auth/client/testing`. The fixture provides a fully functional in-memory effect-auth server and cookie-jar fetch for end-to-end testing. This unblocks consumers who previously had to hand-roll their own test harness (see #180).
  
  Also adds `effect` to peerDependencies (range `>=4.0.0-rc.112`) since fixture.ts imports Effect's `Layer` and `Effect` utilities.
- 00aa6e9: `purgeExpiredKV` deletes the magic-link tokens and email OTP records whose `expiresAt` has passed from the `KeyValueStore`-backed stores (`MagicLinkStoreKV`, `EmailOtpStoreKV`, so `layerKV` and `Testing.memoryStores`) and reports how many it deleted from each; a purged magic link also leaves its address's index. A `KeyValueStore` cannot list its keys, so the purge also requires the new `KeyValueStoreKeys` service, whose `list(prefix)` the host implements over its backend (Workers KV `list({ prefix })`, Redis `SCAN`). `layerMemoryKeyValueStore` is an in-memory `KeyValueStore` with that listing over the same map, and `Testing.memoryStores` now runs on it and provides both services, so the purge runs against it. As with effect-auth/sql's `purgeExpired`, the host schedules it; no store deletes these records on its own (#420).
  
  effect-auth/sql's `purgeExpired` now keeps a row whose `expires_at` equals the current time: the services still accept such a code or link, so deleting it changed an outcome.
- 8213f5b: `purgeExpired` deletes the magic-link and email-OTP rows whose expiry has passed and reports how many it deleted from each table. No store deletes them on its own, and the sends that hide whether an account exists write one for any address, so a host schedules this (a cron trigger on Workers, a timer on a long-lived server) to keep the tables bounded. effect-auth/sql exports it over the ambient `SqlClient`; effect-auth-alchemy-cloudflare exports `purgeExpired(db)` over a D1 binding. The schema gains an `expires_at` index on each of the two tables, which `migrate` adds on the next run (#420).
- d2d8163: `RateLimiter.consumeToken` now decides from the count `RateLimitStore.increment` returns instead of a count it read before incrementing, so concurrent requests at the limit no longer all pass, and concurrent first requests in a window no longer overwrite each other's count (#455). It also checks a block before the window, so a `blockDurationMs` longer than `windowMs` is no longer lifted when the window expires.
  
  **Breaking: the `RateLimitStore.increment` contract is now stated and relied on.** It must start a new window (count 1, `resetAt` `ttl` seconds away) when the key has no entry or its window has expired, and return the new count atomically. effect-auth/sql's store and the `KeyValueStore`-backed store already do. A custom store whose `increment` only bumps an existing entry (relying on `consumeToken` to `set` a new window) must be updated, or `consumeToken` never refuses. The client's in-memory testing fixture is updated to match.
  
  **Breaking: `RateLimitError.retryAfter` is now an `effect/Duration`** instead of a bare number, which was seconds from `RateLimiter.make()` but milliseconds from `rateLimiterPersistenceLayer`. Both now report the same `Duration`. Read it with `Duration.toMillis` / `Duration.toSeconds`. The HTTP IP rate limit (`ipRateLimit`) sends it as a `Retry-After` header in whole seconds, rounded up, and keeps the 429 body's `retryAfter` as the same whole seconds.
- 856d6fe: New `readScopeWhere(scope, { columns, sets? })` (#190): renders a core `ReadScope` as a SQL `WHERE` fragment over any relation's columns, so a LIST filters in the database. It is two-valued on NULL columns, keeps named sets as subqueries, narrows when a set's fragment is missing, and lists nothing when a column is missing.
- 8235dad: New `ReadScope` module (ADR-0020, #203): compile a declarative policy set into the rows a principal may read, for a LIST to render as its `WHERE`. `ReadScope.compile(policies, binding, request)` partially evaluates the policies over an unbound row and returns `Exact` with one of three scopes: `AllowAll`, `Deny`, or a `Filter` over a bound-scalar `Predicate` (text, integer, double, boolean, instant). Relationships compile to named sets (`InSet`), never inlined members. A policy the predicate can't express is flagged `Inexact` with its reasons, never approximated. The predicate is two-valued: absence is its own atom, so the kernel's absent-attribute rule survives the move to SQL. `ReadScope.matches` is the single-row form of the same residual, and `ReadScope.withoutSets` narrows a scope whose sets can't be resolved. `Condition.evaluateOperand` is now exported.
- 213497b: `UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
  writes the password hash through
  `Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
  `@thomasfosterau/effect-auth/sql` and `@thomasfosterau/effect-auth-drizzle`
  implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
  `UserStore.GetUser` batch user reads.
- f5bf843: Rate limits keyed by client address need an address source. A Web `Request` carries no socket address, so `Http.make` with `ipRateLimit` requires `trustedProxy` (for example `ClientIP.cloudflare`), and throws `ClientAddressConfigError` at build without one. An app that sets `trustedProxy` also gets `429` on rate-limited endpoints when a request's trusted header is missing or unusable and so has no socket address, such as service-binding or health-check traffic. The new `allowMissingClientIp: true` option accepts that address-less requests to rate-limited endpoints are refused with `429`. Such a request is never let through unlimited and never counted under a bucket shared with other callers. This includes the dynamic client registration limit on `POST /register`, which refuses it too (#358).
- a517a32: **Security — verifying an address no longer hands the verifier an account whose password someone else chose (#425).** The first time `AuthLifecycleService.verifyEmail` verifies an address (`POST /email-verification/verify`), it clears the account's password and revokes all of its sessions before marking the address verified. Until then no one had proven they own the address, so an attacker could sign up with a victim's address and a password they know, and the victim's later verification (from the attacker's sign-up email, a re-send, or the victim's own recovered sign-up) left the attacker able to sign in. The verifier now sets a password afterwards, with `EmailPasswordService.setPassword` from the session the verification issues (with `autoSignInAfterVerification`, the default) or through a password reset. Verifying an address already verified changes neither.
  
  This applies to every first verification, the account's real owner included: after verifying, a user who signed up with a password has none until they set one, and any session they held before verifying is signed out.
  
  **Breaking — `EmailPasswordStore` gains a required `clearPasswordHash(userId)`**, which removes the user's password so `getPasswordHash` returns `null` (a no-op when there is none). `EmailPasswordService` gains `clearPassword(userId)` over it. effect-auth/sql's `EmailPasswordStore` implements it (`password_hash = NULL`); the effect-auth/client `./testing` server implements it in memory.
  
  **The recovered sign-up acts on the address the `beforeSignUp` hooks returned (#426).** With `antiEnumeration` off, a sign-up for an address held unverified looks the holder up by the address `EmailPasswordService.signUp` found taken, not the raw submitted one, and answers with that address as its `identifier`. `EmailInUseError` carries that address as an optional `email` (never sent over HTTP); `AccountManagementService`'s change-email sets it too.
- 5e1d6ce: **Breaking: `AccountLockedError.retryAfter` and `ResendTooSoonError.retryAfter` are now an `effect/Duration`** instead of a bare number of milliseconds, matching `RateLimitError.retryAfter`. Read them with `Duration.toMillis` / `Duration.toSeconds`. `AccountLockoutPlugin` now also sets `retryAfter` to the time left on the lock, where before it left it unset.
- 311e9cb: Make the `role` attribute safe to authorize on (#193, the parts that pair with the ladder).
  
  - **Server-only attributes.** `UserService.updateUserAttributes` now refuses — with
    `InvalidInputError`, writing nothing — any key in `UserServiceConfig.serverOnlyAttributes`, which
    defaults to `["role"]`: a profile-update path built on it can no longer let a user set their own
    rung. **Behaviour change:** code that set `role` through `updateUserAttributes` must move to
    `AdminService.setRole` (or pass `UserService.layer({ serverOnlyAttributes: [] })` to opt out).
  - **Constrained values.** `AdminConfig.roles` (an app's `Ladder` satisfies it) makes `setRole` and
    `createUser` refuse a role off the ladder with `AdminError`, whichever door the role comes in by.
  - **Declared once.** `LadderSchema.rung(ladder)` is the ladder's rungs as a `Schema`, and
    `@thomasfosterau/effect-auth-drizzle`'s `ladderCheck(column, ladder)` is the matching `CHECK`
    expression (rungs inlined as quoted literals), so the type, the runtime check and the database
    backstop come from one declaration.
- a81a752: Add an ordered role ladder (#188): `Ladder.make([...rungs])` gives a totally ordered set of rungs,
  `rank` (`-1` off the ladder), the one "at least this rung" comparison (`hasAtLeast`, failing closed
  on anonymous and on an off-ladder role), and named capability axes (`ladder.axes({ corpusWrite:
  "contributor", … })`) so moving a capability between rungs is a one-line change. The module imports
  nothing and is also published on its own subpath, `@thomasfosterau/effect-auth/ladder`, so a browser
  bundle can read the ladder for UX gates.
  
  `Policy.roleAtLeast(ladder, axis, options)` (and `Policy.roleAtLeastCondition`) compile an axis into
  an ordinary declarative policy — `principal.role` is one of the rungs at or above the axis — so a
  ladder comparison is storable and model-checkable like any other policy.
  `AuthorizationModel.validatePolicies` now also checks, where a policy pins its principal or resource
  to a declared type with a struct of attributes, that every attribute its condition reads on that
  slot is declared.
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
  
  `effect-auth/client` now imports its wire types from `@thomasfosterau/effect-auth/http`; its own API is unchanged.
- 36788a7: New `safeRedirect(target, fallback)` (#200): follow a client-supplied post-authentication redirect only when it is a same-origin path. Absolute and protocol-relative URLs, backslash forms, schemes, control characters and a missing target all fall back.
- 408285d: **Security — a pending second-factor challenge accepts at most 5 wrong codes (#496).** `MultiFactorService.verifyTotp` and `verifyBackupCode` used to accept wrong codes against one challenge until it expired, capped only by the HTTP layer's per-address rate limit. Wrong TOTP and backup codes now count against the challenge together, and the attempt that reaches `MultiFactorConfig.maxFailedAttempts` (default 5) deletes it. That attempt, and every later one against the same token, answers as a wrong code does (`MultiFactorError` with the method's "Invalid multi-factor code" / "Invalid backup code" message), so a caller cannot tell a capped challenge from a wrong code. An unknown challenge token now answers the same way, where it used to say "Invalid or expired multi-factor challenge token"; an expired one still says it has expired.
  
  **Breaking — `PendingMultiFactorStore` has a new required member,** `recordFailedAttempt(token): Effect<number, AuthError>`, which counts one wrong code against an existing challenge and resolves to the count so far; `delete` now also drops the count. `PendingMultiFactorStoreKV` keeps the count in the challenge's record (read-modify-write, like the KV store's other counters). New conformance suite: `Testing.pendingMultiFactorStoreConformance`.
  
  effect-auth/sql adds the `auth_pending_multi_factor_attempts` table (`migrate` creates it; a table of its own because SQLite has no idempotent `ADD COLUMN`). `recordFailedAttempt` is one `INSERT … SELECT … ON CONFLICT … DO UPDATE … RETURNING`, and `delete` removes the challenge before its count. effect-auth/client's `./testing` fixture implements the new member.
- a3131b6: The session cookie cache (`cookie.cache`) is treated as the authorization bound it is (#194).
  
  - **`cookie.cache.version`**: a static cache epoch carried in every cookie. A cookie issued under another epoch is rejected and the request falls through to the store, so changing it invalidates every outstanding cache cookie at once. A function of the cached payload can't do this (it would always agree with itself), so it is a string.
  - **Server-only attributes never come from the cookie.** A user holding any of `UserService`'s server-only attributes (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never snapshotted, and a cookie carrying one (for example one issued before this release) is never served. Their requests read the store, so `role` is always current. `UserService` exposes the list as an optional `serverOnlyAttributes` (`DEFAULT_SERVER_ONLY_ATTRIBUTES` when an implementation leaves it unset); `encodeSessionCacheCookie` and `decodeSessionCacheCookie` take it as an optional argument, and `encodeSessionCacheCookie` returns `undefined` for such a user. With the default list, the cache now helps only users who hold no `role`.
  - **`cookie.cache.encrypt: true`** encrypts the payload with AES-256-GCM under a key derived from the cache secret, separate from the HMAC key, so the browser can't read it. The default stays signed-only.
  - The `SessionCookieCache` module docs and `SECURITY.md` spell out the revoked-session and stale-user windows and the "change the version and revoke the sessions" procedure.
- f87095c: Session context is now separable from session resolution, so a runtime that never saw an HTTP
  request can be handed an already-resolved session and run gated code (#185).
  
  `CurrentSession`, `CurrentUser` and `MaybeCurrentSession` move to a new top-level
  `SessionContext` module. They were previously declared inside `http/HttpMiddleware.ts` and
  provided in exactly one place — the middleware's handler wrapper — so the only way to carry a
  session was to be inside an `HttpApi` handler. That does not fit a SvelteKit `hooks.server.ts`
  that resolves the session into `event.locals`, a Worker route that dispatches before the router
  runs, or a test harness whose whole job is "run this effect as this fixture viewer".
  
  New, all additive:
  
  - `SessionContext.authenticatedLayer(resolved)` — provides `CurrentSession`, `CurrentUser`,
    `MaybeCurrentSession` (as `Option.some`) and `CurrentPrincipal` from a `SessionWithUser`.
  - `SessionContext.anonymousLayer` — `MaybeCurrentSession` as `Option.none()`. It deliberately
    provides no `CurrentUser` and no `CurrentPrincipal`: there is no user, and inventing one would
    let gated code type-check against a context that cannot satisfy it.
  - `SessionContext.layer(resolved)` — takes whatever an app edge produced (a `SessionWithUser`, an
    `Option` of one, `null`, `undefined`) and provides the read-path service. It provides
    `MaybeCurrentSession` only, because the richer services are conditional on a session having
    resolved — code given this layer has to handle the anonymous branch.
  - `SessionContext.userLayer(user)` / `userSessionLayer(session, user)`, `SessionContext.principalOf`,
    and the accessors `currentUserOption`, `currentSessionOption`, `isAuthenticated`,
    `requireCurrentUser`, `requireCurrentSession`.
  - `Errors.NotAuthenticatedError` (`NOT_AUTHENTICATED`) — the authentication counterpart to
    `PermissionDeniedError`, raised by the failing accessors so a guard can turn an anonymous
    context into a typed failure without reaching for the HTTP layer's `Unauthorized`.
  
  `AuthMiddleware` now also provides `MaybeCurrentSession` (always `Option.some` there, since it
  only reaches the handler when a session resolved). That is what makes one effect written against
  the read-path service run unchanged under required auth, under `OptionalAuthMiddleware`, and under
  `SessionContext.layer` at a non-HTTP edge.
  
  **Nothing to migrate.** `CurrentUser` keeps its `Types.User` type and its `@effect-auth/CurrentUser`
  tag string; `Http.CurrentSession` / `Http.CurrentUser` / `Http.MaybeCurrentSession` still resolve,
  re-exported from their new home. Widening `AuthMiddleware`'s `provides` only ever removes
  requirements from a handler, so existing handlers are unaffected.
  
  Read-path code should depend on `MaybeCurrentSession` rather than `CurrentUser`: "signed out" is a
  value there (`Option.none()`), so a predicate like "may this viewer see deleted rows?" can answer
  `false` for an anonymous caller instead of failing — which is most of a real read path.
  `requireCurrentUser` is the derived convenience for the gated case, not the other way round.
- 2510ce4: Session resolution at an application's own edge: credential-presence predicates over a raw
  request, a stated fault posture, and one auth-outcome signal (#186).
  
  An app that resolves the session before any effect-auth handler runs — a SvelteKit
  `hooks.server.ts`, a Worker calling an auth service binding — had to answer three questions the
  library gave it no help with, and answered all three by hand.
  
  **Does this request carry a credential at all?** New `SessionResolution.detectCredential` /
  `hasSessionCredential` answer it from a plain `Headers`, a header record, or a cookie jar, with
  no Effect runtime involved. The cookie names they look for come from the new `SessionCookies`
  module, which `http/HttpServer.ts`'s `resolveCookieConfig` now also calls — so the effective
  name, including the computed `__Host-` prefix, has exactly one derivation. Changing `name`,
  `secure` or `hostPrefix` cannot desynchronise an app's fast-path predicate from what the
  middleware reads, because there is nothing left to keep in sync. `extractApiKey` and
  `extractSessionToken` back both the predicate and the credential read, so a gate and the thing
  behind it cannot disagree about what a credential is.
  
  **What happens when resolution faults?** `SessionResolution.resolve` fails closed;
  `resolveFailOpen` degrades the request to anonymous and reports it. Neither is a default.
  `resolveFailOpen` takes a _mandatory_ `onDegraded` callback — fail-open's failure mode is
  silence, and there is deliberately no overload that omits it. It catches defects as well as
  typed failures, since an unreachable binding usually arrives as a thrown `TypeError`.
  `docs/ARCHITECTURE.md` ("Fail-open vs fail-closed session resolution") states the precondition that makes fail-open safe (anonymous must be the
  lower-privilege outcome) and the shapes where it is an escalation instead.
  
  **What just happened?** One `AuthOutcome` — `skipped` | `resolved` | `anonymous` | `degraded` —
  derived in one place and reported by the resolver itself, on a new
  `effect_auth_session_resolutions_total` counter and as an `auth.outcome` attribute on the
  `effect-auth.resolve-session` span. Callers do not derive it and do not wire it up. The four
  states stay distinct: `anonymous` paid the round trip that `skipped` did not, so folding them
  corrupts the duration bucket, and `degraded` means something broke rather than that nobody was
  signed in.
- 45e863a: Sign-up can answer without disclosing whether an address is registered, and delivery sends run off the response path.
  
  - `EmailPasswordConfig.antiEnumeration` (default `false`): a sign-up for an
    address another user holds answers like a fresh one rather than with
    `EmailInUseError`. It hashes the submitted password (so the two branches
    cost comparable work) and answers with the same no-session result shape a
    fresh sign-up gets, built only from the caller's own input, never the real
    account's data. With the flag set, a fresh sign-up gets no immediate
    session either, so neither branch sets a cookie. With it unset, a duplicate
    fails with `EmailInUseError`.
  - Each callback from `emailCallbacks`/`smsCallbacks` in `Delivery.ts`
    dispatches `sender.send` on a detached fiber, so a flow that sends mail or
    SMS on only one of its branches (like sign-up's fresh-registration branch)
    does not reveal that branch through response timing. A failed send never
    fails the flow that triggered it; it is logged and counted in
    `effect_auth_delivery_sends_total`.
- 03a3219: Auth as a separate service is now a supported deployment: a remote session-resolution client
  and a documented `Set-Cookie` relay (#187).
  
  `Http.make` mounted in its own internal service — reached over a Cloudflare service binding, a
  private container, an in-process handler under test — needs two things a typed client cannot
  give. Both are new in `Http.RemoteSession`.
  
  **A transport that is not `globalThis.fetch`.** `layerFetcher(binding)` builds an `HttpClient`
  from any fetch-alike, so `Http.client(baseUrl)` works unchanged over a service binding. The
  typed contract already classifies status codes into tagged failures, which replaces the
  hand-written "POST to an auth route and map the status" service this topology otherwise grows.
  
  **A channel for `Set-Cookie`.** `make({ fetcher })` returns a client with `read` (resolve the
  session, returning the `Set-Cookie` lines to replay) and `relay` (forward a session-mutating
  request and return the upstream response verbatim — status, body and `Set-Cookie` intact).
  `resolveAtEdge` / `resolveAtEdgeFailOpen` compose that with #186's credential skip, fault
  posture and `AuthOutcome`, so a cookieless request never reaches the binding and an
  unreachable one degrades loudly rather than 500ing every route.
  
  Three rules the library now owns rather than each app rediscovering:
  
  - **Header forwarding is an allow-list.** `content-type` and `content-length` are not on it.
    Forwarding an inbound request's content headers onto a bodyless `GET` makes a router believe
    the request has a body, at which point its content-type allow-list rejects the app's own
    dispatch type with 415 — the session fails to resolve, the request degrades to anonymous, and
    every gated route answers 401. An allow-list makes that unreachable rather than something you
    remember to strip.
  - **Session _reads_ need the relay too.** With the signed cookie cache on, a read refreshes it
    via `Set-Cookie`; drop that and the cache stops refreshing after its first window, silently.
  - **Never relay a cookie to a machine caller.** `Set-Cookie` is dropped unless the inbound
    request carried a browser session cookie and no machine credential — the mixed cookie+key case
    and the bearer-only native client included. `relayResponse` applies the same rule to a
    hand-rolled relay.
  
  `SessionResolution.resolveWith` / `resolveWithFailOpen` generalise the `resolve` pair over a
  payload that carries more than the session, so the remote resolver threads its cookies through
  the one outcome derivation instead of calling the transport twice.
  
  New guide: `docs/guides/split-auth-service.md` — when to split and when to just mount
  `Http.make` in the app, the transport, the fault posture, the relay, and the CSRF implication
  of a server-to-server hop (effect-auth's trusted-origin guard allows a request with no `Origin`,
  so a binding need not synthesise one — but the forwarded browser origin must be in the auth
  service's `trustedOrigins`).
- ca3abfb: Every SQL `createUser` seam (`EmailPasswordStore`, `OAuthUserStore`, `MagicLinkUserStore`, `EmailOtpUserStore` and `AdminUserStore`) resolves to core's `CreateUserResult`, `{ user, created: true }`: each is a plain `INSERT` with a fresh id, so every success is a new user (#406).
- 9ff7ded: The SQL `IdentifierStore` implements `replace`: it inserts the new identifier and deletes the old one inside `sql.withTransaction`, so a value another user holds is refused by the `(type, value)` unique index and the transaction rolls back with the old identifier in place. The release is a `DELETE … RETURNING` guarded on the old identifier's id, user, type and value: when it deletes nothing, the new identifier is deleted again and `replace` resolves to `null`, so of two concurrent replaces of the same identifier one succeeds (at PostgreSQL's default READ COMMITTED isolation; at stricter levels the losing call fails with a serialization error, surfaced as `AuthError`). On Cloudflare D1 (`@thomasfosterau/effect-auth-alchemy-cloudflare`), which has no transactions, the two statements autocommit in the same order, so a failure between them leaves the user holding both identifiers, never neither, and confirming an email change again releases the old one; the losing call of two concurrent replaces deletes its new identifier in a statement of its own, so a failure before it leaves the user holding both new identifiers (#381).
- f7bafc0: System principals get a Guard gate and an audit event (#362, following ADR-0019).
  
  - **`Guard.requireSystem({ action, resource })`** admits the `CurrentPrincipal` when it is a system principal (`System::"<name>"`) that the `Authorizer` in context grants the action on the resource, and yields its `EntityRef`. It fails with `Unauthorized` when there is no current principal or it is not a system principal, and with `Forbidden` when no policy grants it. The decision is the `Authorizer`'s, so it is logged as `authorization.decision` with the job's name. The viewer gates (`requireUser`, `requireRoleAtLeast`, `requireOwnerOrRole`) are unchanged and stay user-only; the `Guard` module docs show both composed for an operation either may perform.
  - **`Hooks.afterWrite`**, a new tap carrying a `WriteEvent` (`{ principal, action, resource }`), which the application fires with the new **`recordWrite(event)`** after a write commits. **`AuditPlugin`** logs it as `auth.write` with the acting principal (`User::"<id>"` or `System::"<name>"`), whether it is a system principal, the action and the resource. A `Hooks` implementation written out in full (rather than through `makePlugin` or `Hooks.Default`) needs the new `afterWrite` member.
- c092987: Add system principals: a reserved `System::"<name>"` entity for background jobs, cron handlers and pipeline steps, denied everything by default and allowed exactly what an explicit grant names (#192).
  
  - `System.provide(name)` and `System.layer(name)` provide `Authorizer.CurrentPrincipal` as the named system principal, with no session or user.
  - `System.grant(name, { id, action, resource, when? })` builds the grant: a permit scoped to that principal, naming one action and one resource scope. `System.declaration` is the model entry grants validate against.
  - `System.ref`, `System.isSystem` and `System.entityType` construct and recognise the reserved type.
  - The policy kernel keeps system principals default-deny under every policy set (#377): a permit reaches a system principal only when its principal scope names the `System` type (`System.grant`, `Policy.eq(System.ref(…))`, `Policy.isType("System")`). Unscoped permits (`Policy.permit` with no principal, `Policy.permission`, including `{ action: "*", resource: "*" }`, `Policy.action`, `Policy.roleAtLeast`, the `OwnedAccess` policies), role permits and `Policy.custom` permits never match one. Forbids bind system principals like any other principal.
  - Role assignment is for users: `Rbac.entities`, `Rbac.model` and `Rbac.layer` refuse `"System"` as the principal type.
  - `Guard.make` refuses `"System"` as a viewer's principal type, and its rung and owner policies are scoped to the viewer's principal type.
  - `Authorizer` and `protectedField` log every decision about a system principal, allows at info and denials at warning, with the principal's name and the determining policy ids. A denial's error message names the principal.
- ef0207d: `@thomasfosterau/effect-auth/testing` adds fixture users with UUID ids: `fixtureUsers()` (an admin, a member and a second member, with fixed v4 UUIDs in `fixtureUserIds`) and `fixtureUser()` (one user, a fresh random UUID by default). Ids, roles (`attributes.role`) and timestamps are overridable.
- bfa558e: `@thomasfosterau/effect-auth/testing` adds guard-negative helpers: `expectGuarded` asserts in one call that an operation refuses an anonymous viewer and a viewer one rung too low (`Unauthorized` / `Forbidden` for a write, the app's not-found for a read), admits its minimum rung, and admits the owner. `expectRefusesAnonymous`, `expectRefusesBelow` and `expectAllowsOwner` check one case each. A failure is a `GuardExpectationError` listing every mismatched case.
- 3875062: `@thomasfosterau/effect-auth/testing` adds in-memory reference stores. `memoryStores` is one layer with sessions, users, identifiers, TOTP and OTP second factors, trusted devices, JWT keys, OAuth accounts and users, the four OIDC provider stores, and the `KeyValueStore`-backed token stores. Each store is also exported on its own as `memoryXStore()`. With them, a test or demo builds `SessionService`, `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService` and `OidcProviderService` without a database. The JSDoc examples for `aes256GcmCipher`, `mcpProviderPreset`, `TrustedDeviceWithMultiFactorGateLayer`, `MultiFactorGateLayer`, `OtpSecondFactorGateLayer` and `TrustedDeviceWithOtpSecondFactorGateLayer` now build their layers over these stores and run.
- 1031ed5: Add the `@thomasfosterau/effect-auth/testing` subpath with `runAs` / `runAsViewer` (and their `layerAs` / `viewerLayerAs` layers): run an Effect as a fixture principal, signed in or anonymous, in one call. Signed in, the effect gets the session context the required-auth middleware provides; `runAsViewer` also provides the app's own viewer service through `SessionContext.viewerLayer`.
- 5ab2078: `@thomasfosterau/effect-auth/testing` adds store-contract conformance suites for bring-your-own stores: `sessionStoreConformance`, `userStoreConformance`, `identifierStoreConformance` and `apiKeyStoreConformance`. Each suite is a list of cases, and each case is an `Effect` that fails with `ConformanceError` when the store departs from its contract. The suites import no test runner; register the cases with your own (see `docs/guides/byo-stores.md` §7).
- 9b1fe6f: Add zero-IO guards over an already-resolved viewer (#189). `Guard.make({ ladder, viewer })` builds,
  for one ladder and one application-declared viewer service (`Option<AppUser>`, where
  `AppUser extends { id: string; role: string }`):
  
  - gates that yield the viewer or fail — `requireUser` (`Unauthorized`), `requireRoleAtLeast(axis)`
    and `requireOwnerOrRole(ownerId, axis)` (`Unauthorized | Forbidden`);
  - never-failing predicates that treat anonymous as `false` — `isSignedIn`, `hasRoleAtLeast`,
    `isOwnerOrRole` — for read paths, where a `false` becomes a 404, never a 403;
  - capability hooks — `roleCapabilities(axis)` and `ownedCapabilities(axis, ownerOf)` — that restate a
    write gate as `meta.canEdit` / `canDelete`;
  - `policies.roleAtLeast` / `policies.ownerOrRole`: the declarative policies the gates decide.
  
  Every decision is `Policy.decidePure` over a slice built from facts the caller already holds, so the
  gates need no `EntityResolver` or `Authorizer`, and a gate cannot disagree with a stored policy built
  from the same axis.
  
  `Unauthorized` and `Forbidden` are now defined in the core (and exported from the root); the HTTP
  tier's `Http` error schemas re-export the same classes, so a guard's failure encodes at the edge
  without translation.
  
  `SessionContext.viewerLayer(tag, user)` and `SessionContext.viewerFromSession(tag, project)` provide
  an application's viewer service; `SessionContext.withRole(attribute)` projects the library's
  `SessionWithUser` into a viewer whose rung is read from `user.attributes`.

### Patch Changes

- 84c9180: `AdminService.createUser` normalises each of `AdminCreateUserInput.identifiers` for its type before claiming it, as it already did the primary email (#408): an email or username is trimmed and lower-cased, and a phone number goes through the new `AdminConfig.normalizePhoneNumber` (default: trim only, as `PhoneOtpConfig.normalizePhoneNumber`'s default; pass the same function to both). An extra address such as `Alice@Example.com ` is now stored as `alice@example.com`, so it collides with that address held by another user and sign-in by it finds it. A failing phone normaliser fails `createUser` before anything is written.
- 8ebcb4a: With `antiEnumeration: true`, `POST /sign-up` answers an email and password sign-up for an address another user holds as it answers a fresh one (#414), with the same id shape when the store's ids are random UUIDs or it implements `newUserId`: a `200` with the same headers and no `Set-Cookie`, and a `user` with the same fields, whose `email` is the submitted address, trimmed and lower-cased, with `emailVerified: false`. Response timing can differ between the two; the `EmailPasswordConfig.antiEnumeration` docs say how. The sign-up response takes `email` from the address submitted with the sign-up, which `AuthLifecycleResult` carries as `identifier`.
  
  The stand-in user in that answer has one timestamp for both `createdAt` and `updatedAt`. Its id is a random UUID, or comes from the optional `EmailPasswordStore.newUserId` seam, so a store whose ids have another shape can give the stand-in an id of that shape.
  
  `UsernameService.signUp` claims no username for the stand-in, so a sign-up with a held address cannot squat a username. It fails with `UsernameError` when someone holds the username by then, as the claim does. The `EmailPasswordConfig.antiEnumeration` docs list what the two answers share and what tells them apart.
- a1b01ae: With `EmailPasswordConfig.antiEnumeration` and email verification on, `AuthLifecycleService.signUp` stores a verification record, runs the `beforeCreateVerification` and `afterCreateVerification` hooks and sends a verification link only for a fresh sign-up (#422). A sign-up for an address another user holds is answered by a stand-in user that no row backs, so it gets none of these: the address's holder is never sent a link that can't verify.
  
  The optional `AuthLifecycleConfig.sendExistingAccountNotice` sends that holder a notice that someone tried to sign up with the address, so each of the two answers makes one send. `emailCallbacks(...).sendExistingAccountNotice` derives it from an `EmailSender`, under the `"existing-account"` delivery purpose, off the response path like the other derived callbacks. A failed notice fails the sign-up with the same `EmailVerificationError` a failed verification send does. Without the option, such a sign-up sends nothing.
- b9a8437: With `antiEnumeration: true`, email and password sign-up answers an address found taken at the insert (a lost race, or a store whose `createUser` reports `created: false`) exactly as it answers one the pre-check finds taken: it hashes the submitted password and returns the same no-session result, so neither the response nor its timing tells an existing account apart (#410).
  
  `CreateUserResult` and every `createUser` seam's docs state that a writer leaves an existing user's row unmodified: a plain `INSERT` that lets the unique index fail, or `ON CONFLICT DO NOTHING` followed by a select, and never `ON CONFLICT DO UPDATE`. effect-auth-drizzle's `SingleTableIdentifierStore` docs and README say the same for `onConflictDoNothing` and `onConflictDoUpdate`, and the README's writers return the user's `name`.
- b2e7fd4: `makeAuthorizationMiddleware` results can now be attached with `HttpApiEndpoint.middleware(...)` and `HttpApiGroup.middleware(...)`, which rejected them with a type error. The factory's return type named the class value rather than its instance; it now uses the instance type, the same shape `AuthMiddleware` has. Runtime behaviour is unchanged. The `.layer` property is now typed as providing that instance type, which is what an attached endpoint requires; two types are newly exported, `AuthorizationMiddlewareConfig` and `AuthorizationMiddlewareInstance` (#313).
- bbb24fe: TSDoc for `makeAuthorizationMiddleware` gives the runtime key of a guard: `@effect-auth/AuthorizationMiddleware/<name>#<n>`, where `<n>` counts factory calls. The type-level key is the bare name, so the two differ.
- ca3abfb: The `./testing` in-memory server's `createUser` seams resolve to core's `CreateUserResult`, `{ user, created: true }`, since each call inserts a new user (#406). No change to the fixture's own API.
- 7f5206e: The `./testing` in-memory server's feature set (`features: true`) includes an in-memory `RateLimiter`, because the core requires one for device authorization (`Http.make` throws `RateLimiterConfigError` without it, #389). Device approve and deny on the fixture are therefore rate limited as in production: 5 attempts per user code per 15 minutes, then `429`. No API change.
- 20cde53: `identifierStoreConformance` works from each identifier as the store reports it rather than the record it handed in. A store that keeps one email on the user's own row reports the user's id as the identifier's id, which the contract allows; the suite used to fail such a store's `setVerified`, `delete` and `replace` cases. It now also checks that `getByValue` reports the same id `create` returned.
- 048e031: Documentation only: the JSDoc `@example` blocks now type-check, so `vp run docs` (the API reference generator) passes and CI runs it. No runtime change.
- 69b1d18: Doc comments only: the `Ladder.make` and `Hooks` class examples now run under docgen. The `Ladder` example moved from the module comment (which docgen does not read) onto `make`, and the `Hooks.tap` example moved from the `static readonly` member (which docgen does not extract) onto the `Hooks` class. Both assert their results. The `.d.ts` changes are those doc comments.
- 6d6bf02: Doc comments only: the `@example` blocks now run under docgen (`runExamples`), so each one is a standalone program with in-memory stores and inline config, and it fails if its assertions do not hold. The `.d.ts` changes are the rewritten examples.
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
- 0def0c5: The `effect` peer range is now `^4.1.0` (was `>=4.1.0`), and effect-auth-alchemy-postgres's `@effect/sql-pg` peer is `^4.1.0` too. The floor is unchanged: the packages need `effect/crypto`, which first shipped in Effect 4.1. The caret form stops the range from claiming a future Effect 5 it was never tested against.
- 03bdfea: Email change claims the new address first and releases the previous address after the claim succeeds. A failed claim, whether another account took the address or the identifier store failed, leaves the user's previous address in place and verified, and the confirm token is not consumed (#364).
- 42d0f03: Drop the remaining Node `Buffer` uses in the OAuth module and the SQL stores, in favour of `effect/encoding`, `Schema`'s base64 codecs and `TextEncoder`, so they no longer rely on a Node global in Workers and browsers. `RenderedEmail.html` and `.text` in effect-auth-resend are now `?: string | undefined`, so a renderer can forward an optional value under `exactOptionalPropertyTypes`.
- 5ab2078: `IdentifierStoreKV.create` refuses a `(type, value)` another identifier already holds with `AuthError`, as the `IdentifierStore` contract requires and as `claimIdentifier` expects. It used to overwrite the lookup key, which moved the address to the new record. The check is a read before the write, so two concurrent creates can still both succeed on a `KeyValueStore`.
- 78dac5f: Widen the optional option fields to `?: T | undefined` so callers under `exactOptionalPropertyTypes` can forward their own optional values: `AuthClientOptions` (`fetch`, `headers`, `refresh`) and `RefreshOptions` (`intervalMs`, `onFocus`, `crossTab`) in the client, and the `render` / `baseUrl` / `fetch` fields of `ResendEmailSenderConfig` and `TwilioSmsSenderConfig`.
- 78dac5f: Correct the `layer` doc comment: core's `KeyValueStore`-backed layers do not cover the stores this package lacks (one-time token, trusted device, phone OTP, organization, OIDC, SSO, device authorization), so implement those yourself until they land here.
- e03530e: `jwtServiceConfig` (and so `JwtService.layerFromEnv`) now validates `JWT_ALGORITHM`. An unset variable still selects the default algorithm, but a value other than `ES256` or `EdDSA` fails the config with a `ConfigError`. Previously any value was cast through unchecked, and a read failure was swallowed into "unset" (#443).
- 4c70cd2: The `./ladder` module's overview now lives on the `Ladder` interface's doc comment, which comes first in the module, so the API reference shows it on the module page and on `Ladder` instead of `RungHolder`'s one-line description (#349).
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- 4e6293b: Type-only tidying from the lint paydown (#503); no runtime change. Optional parameters no longer repeat `| undefined` (which an optional parameter already admits): `EmailVerificationService.createVerification` / `resendVerification`'s `options` and `Testing.sessionFor`'s `overrides`. Callers are unaffected.
- 6bee50c: `Http.make` runs the `services` build until it finishes, and no further. A fiber the build forks with `Effect.forkChild` is interrupted when the layer that forks it finishes building. Under `Layer.merge` or `Layer.mergeAll` that is the merged layer's own build, which can end ahead of the whole `services` build, so a fiber that has not started by then never runs. A fiber forked into the layer's scope (`Effect.forkScoped`) keeps running under the default scheduler after `make` returns, and stops on `dispose`; a fiber forked with `Effect.forkDetach` keeps running, and `dispose` does not stop it. Any failure of a `services` build that finishes while `make` runs makes `make` throw, so the app fails to start: the failure's error, or for a defect the defect itself, as `Effect.runSync` throws. An example is the OIDC layer's `ClientAddressConfigError` for dynamic registration with no address source. `make` releases what the build acquired, then throws: a finalizer that does asynchronous work finishes after `make` has thrown, and a finalizer that fails is logged as an error. A `services` build that waits on asynchronous work, on a merged layer that yields or runs past Effect's per-slice operation budget, or, when it fails, on a finalizer that does asynchronous work, finishes after `make` returns. Its failure then fails the handler's build instead, and every request rejects with it; `Http.makeAsync` rejects at startup for those builds (#402). The startup errors and the release log name both `Http.make` and `Http.makeAsync`.
- f4f6606: Tighten the empty encryption-secret check introduced with the rc.118 move (#252).
  
  - A secret that is present but **whitespace-only** (for example `"   "` or a lone newline) now fails `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with the same "set but empty" `ConfigError` as `""`. A secret with surrounding spaces but non-space content is still accepted, unchanged and untrimmed. An unset variable still leaves encryption off.
  - Fix a false "set but empty" when the secret is unset but variables whose names extend it with numeric suffixes (`TWO_FACTOR_ENCRYPT_SECRET_0`, `_1`) are set; they are now treated as sharing the prefix.
- 373bb87: Email OTP and phone OTP verification answer an address with and without an account alike where `send` hides which addresses have one: sign-in with `disableSignUp`, and email OTP `forget-password` (#417).
  
  - In those configurations, every code that fails verification answers `Invalid or expired OTP`, whether the code is wrong, has expired or has reached `maxAttempts`, so `/sign-in/email-otp` and `/sign-in/phone-otp` return the same 400 body for every address. The reason is recorded on the `signIn` / `check` span as `auth.otp.failure`. Everywhere else, an expired code answers `OTP has expired` and the attempt limit answers `Too many attempts`.
  - In the same configurations, and in magic-link sign-in with `disableSignUp`, `send` stores an undelivered marker record for an address with no account whether or not `resendCooldown` is set, so a known and an unknown address get the same store work. An OTP marker expires and counts attempts exactly as a code's record does, and no code redeems it.
- 504ae0d: Export the `EmailAddress`, `Attributes` (from the HTTP schemas) and `ApiKeyRateLimit` types alongside their schemas. effect-auth/sql mints row ids with `globalThis.crypto.randomUUID()` instead of importing `node:crypto`.
- 1d47091: `pbkdf2Hasher().verify` now refuses a stored iteration count above a cap before running PBKDF2, as `scryptHasher` already does for N, r and p. A crafted `pbkdf2-sha256$<iterations>$…` hash could previously make `verify` run PBKDF2 at up to Node's 2³¹−1 (about 3,500 times the 600,000 default, minutes of CPU per attempt); exploiting it needs write access to the password-hash store. The refusal is a `HashingError` ("Invalid hash parameters: …"), and `needsRehash` returns true for such a hash.
  
  The cap is max(5,000,000, the configured `iterations`), so the hasher's own hashes always verify, including at a configured count above 5,000,000. A non-finite, fractional or out-of-range `iterations` option does not raise the cap. A hash written at more than 5,000,000 iterations verifies only on a hasher configured at that count or higher, so lowering `iterations` below such a count makes those hashes unverifiable (#328).
- 624f356: Metric counter names follow the Prometheus naming rule (`[a-zA-Z_:][a-zA-Z0-9_:]*`), using underscores only: `effect_auth_sign_in_total`, `effect_auth_sign_up_total`, `effect_auth_sessions_created_total`, `effect_auth_sessions_validated_total`, `effect_auth_sessions_invalidated_total`, `effect_auth_session_resolutions_total`, `effect_auth_token_verifications_total`, `effect_auth_rate_limit_hits_total`, `effect_auth_multi_factor_challenges_total`, `effect_auth_multi_factor_verifications_total`, `effect_auth_oauth_callbacks_total`, `effect_auth_oauth_refreshes_total`, `effect_auth_webauthn_registrations_total`, `effect_auth_webauthn_authentications_total`, `effect_auth_oidc_token_requests_total` and `effect_auth_delivery_sends_total`.
  
  OpenTelemetry span names use dotted notation and are exported as constants in `Observability.spanNames`.
- 5a48055: Services, stores and the HTTP handlers read the current time from Effect's `Clock` (`Clock.currentTimeMillis`, `DateTime.now`, `DateTime.nowAsDate`) instead of `Date.now()` / `new Date()` (#443). Under the default clock nothing changes; under `TestClock` (or any custom `Clock` layer) token, OTP, session, invitation, rate-limit and JWT expiry, `createdAt` / `updatedAt` / `verifiedAt` stamps, the SAML subject-confirmation window and the in-memory stores in `@thomasfosterau/effect-auth/testing` all follow that clock. `generateTotp` reads the time when its effect runs, not when it is built.
- 89749b6: With `antiEnumeration` off, `AuthLifecycleService.signUp` answers a sign-up for an address another user holds unverified with no session, `needsEmailVerification: true` and a stand-in user built only from the caller's input (#421): a random UUID for its `id`, the submitted `name` and `attributes`, no `image`, and one timestamp for both `createdAt` and `updatedAt`. The holder's id, profile and timestamps stay out of the response, both from `signUp` and from `POST /sign-up`. When `sendOnSignUp` is set, the holder's verification is re-issued to the address. An address held verified fails with `EmailInUseError` (`409` over HTTP). The `AuthLifecycleResult.identifier` docs describe each answer.
- 5ab875a: The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
- 8fce539: `resendCooldown` answers a known and an unknown address alike in the passwordless flows that hide whether an account exists: magic-link, email OTP and phone OTP sign-in with `disableSignUp`, and email OTP `forget-password` (#415). A request for an address with no account stores an undelivered record as its cooldown marker, so a repeat within the window fails with `ResendTooSoonError` (HTTP 429, the same body and headers) exactly as it does for an account holder. The marker is never sent and can't be redeemed: a magic-link marker is a random 32-byte token, and an OTP marker holds the hash of a random 32-byte secret rather than of a code, so no code matches it. Every OTP send draws both the code and the marker secret, so the random work is the same for a known and an unknown address. If an address gains an account within the window, the marker delays its first send by up to the cooldown.
- 68e339a: scrypt hashing and verifying no longer fail when `p + 2 > N` (for example a stored hash with N = 4, p = 8): `maxmem` is now `128 * r * (N + p + 2)`, the memory OpenSSL's scrypt needs.
- 2ba63b6: scrypt `verify` now checks the N, r and p it reads from a stored hash before it runs the KDF, and refuses a set outside the limits with a `HashingError` rather than a defect or a boolean. N must be a power of two with 2 ≤ N ≤ max(2^20, the configured cost). r must be an integer from 1 to max(32, the configured block size), and p an integer from 1 to max(16, the configured parallelization). The memory a derivation needs, `128 * r * (N + p + 2)`, must not exceed max(256 MiB, the memory the configured parameters need), so the hasher's own hashes always verify while a crafted hash cannot request gigabytes. A synchronous throw from Node's `crypto.scrypt` is now also a `HashingError`. `needsRehash` returns true for a hash `verify` would refuse, and for one whose r or p is below the configured value, as it already did for N. `hash` now applies the same checks to the configured cost, block size and parallelization, and fails with a `HashingError` for a configuration its own `verify` would refuse (for example `blockSize: 0`, which Node accepts), instead of writing a hash that can never verify. A non-finite configured value cannot lift the caps.
- fed9d0c: Doc comments name `@thomasfosterau/effect-auth-svelte` as the one framework binding: the React, Vue and Solid bindings were removed before their first release. No API change.
- cbeda0d: Document the supported dialects. `@thomasfosterau/effect-auth/sql` supports SQLite, Cloudflare D1 and PostgreSQL. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). `@thomasfosterau/effect-auth-alchemy-cloudflare`'s module docs say the sql DDL is valid on SQLite, D1 and PostgreSQL, not MySQL.
- 8f78034: Fix `rateLimit.increment` and `accountLockout.registerAttempt` on PostgreSQL. Their `ON CONFLICT … DO UPDATE SET` right-hand sides now qualify the target table's columns, which PostgreSQL rejected as ambiguous (`column reference "reset_at" is ambiguous`). SQLite behaviour is unchanged. The store suite now also runs over PostgreSQL (PGlite), and the README, module docs and TSDoc list PostgreSQL as a supported dialect.
