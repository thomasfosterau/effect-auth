# @thomasfosterau/effect-auth

## 0.2.0

### Minor Changes

- 68709bf: The API layout: directory structure, package exports, service classes and naming conventions.
  Highlights:
  
  - The package is published as `@thomasfosterau/effect-auth` (the bare `effect-auth` npm name
    belongs to an unrelated package), and the client as `@thomasfosterau/effect-auth-client`.
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
- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).
- 9ff7ded: `IdentifierStore.replace(from, to)` swaps one of a user's identifiers for a new value: it claims `to` and releases `from` as one change, so the user is never left holding neither. A store with transactions writes both at once; a store without them claims `to` before it releases `from`. It resolves to the replacement, or `null` when the user does not hold `from`, and fails with `AuthError` when another user holds `to`'s value, as `create` does. `replace` is a required member of the contract, so a custom `IdentifierStore` implements it (see `docs/guides/byo-stores.md`). `memoryIdentifierStore` and `IdentifierStoreKV` implement it, and `replaceInputError` gives an implementation the shared refusal for a `to` with another user, another type, `from`'s own id or the same value. Of two concurrent replaces of the same `from`, the in-memory store lets one succeed; `IdentifierStoreKV` checks `from` before it writes and releases it unguarded, so both can succeed and leave the user holding both new values.
  
  `replaceIdentifier(store, from, to)` calls it with readable failures: `IdentifierTakenError` when another user holds the value, `IdentifierNotFoundError` when the user does not hold `from` (including when the store refused `to` because a concurrent replace of `from` already gave the user that value), `AuthError` for other store failures.
  
  `AccountManagement.confirmEmailChange` changes the user's email of record through `replaceIdentifier`, then releases any other email the user holds; a user with no email claims the new one. If the email of record changes during the confirmation, it succeeds when the user already holds the new address (a double-submitted confirmation) and otherwise fails with `AccountTokenError`, keeping the token. A user with no email whose claim finds the address already theirs succeeds the same way, and in every case the new address ends verified; when a concurrent delete removes the new address first, the confirmation fails with `AccountTokenError` and keeps the token. It works on every identifier store, including one that holds a single email per user (#381).
- c1ba5f6: The last-login-method plugin's constructor is now `LastLoginMethodPlugin`, matching its siblings (`AuditPlugin`, `RateLimitPlugin`, …), instead of a bare `make` (#284). Through the barrel it surfaced as `Auth.Plugins.make` (and `make` from `@thomasfosterau/effect-auth/plugins`), which read as a constructor for the whole plugins cluster. Like the other plugins that take no config, `LastLoginMethodPlugin` is the layer itself rather than a function: replace `Plugins.make()` with `Plugins.LastLoginMethodPlugin`. It still requires `SessionService` and isolates its taps.
- 2484af6: `Http.makeAsync` is the asynchronous counterpart of `Http.make`, for `services` that build asynchronously: a database connection or other `Effect.promise` step, merged layers that yield, or finalizers that do asynchronous work. It takes the same options, waits for the `services` build however it is composed, and resolves to the same `{ handler, dispose }`. The handler serves that one build, and `dispose` releases it. The promise rejects with the errors `make` throws, so the app fails to start: `ClientAddressConfigError`, `RateLimiterConfigError`, or any failure of the `services` build (its error, or for a defect the defect itself). It releases what the build acquired and waits for every finalizer, asynchronous ones included, then rejects; a finalizer that fails is logged as an error. `Http.AuthWebHandler` names the `{ handler, dispose }` pair that both constructors return (#400).
- 90d7a79: `Http.make` takes `strict`, an opt-in for an app that wants `make` to fail at startup whenever it cannot check the `services` build. With `strict: true`, `make` throws `ServicesBuildPendingError` when the `services` build has not finished after `make` has run it synchronously: a build that waits on asynchronous work (a database connection, `Effect.promise`), on a merged layer that yields, on a forked fiber, or, when the build fails, on a finalizer that does asynchronous work. The error's message names `Http.makeAsync`, which waits for such a build. `make` interrupts the build and releases what the build acquired, as far as that runs synchronously, then throws; a finalizer that does asynchronous work, and the whole release of a build in an uninterruptible step that awaits (an `Effect.acquireRelease` acquire), finish after `make` has thrown. When the build fails on its own account, as a step that fails while a finalizer it runs awaits does, `make` logs that failure with `Effect.logError` once the build ends. A build that finishes synchronously is unaffected: `make` throws the startup errors or the build's own failure, or returns the handler. Without the option, `make` returns for an unfinished build, and the startup checks run when the build finishes, failing the handler's build. `Http.makeAsync` ignores the option. `ServicesBuildPendingError` is exported from the package root and as `Http.ServicesBuildPendingError` (#416).
- 7f5206e: A rate limit that cannot run refuses the request or stops the app from starting; it never skips silently (#389).
  
  - **Missing `RateLimiter`.** `Http.make` throws `RateLimiterConfigError` (exported from the package root) when a limit is configured and no `RateLimiter` is in `services`. The limits are `ipRateLimit`, the dynamic client registration limit and the device user-code limit on approve/deny. `make` builds `services` once, synchronously where it can, and the handler reuses that build. When `services` does asynchronous work while building, `make` cannot see the result before it returns: the handler's build fails with the same error instead, and every request rejects with it.
  - **Device user-code limit.** It counts as configured whenever a `DeviceAuthorizationService` is in `services`. `DeviceAuthorizationConfig.allowMissingRateLimiter: true` is the explicit opt-out: approve and deny then run without the limit when no `RateLimiter` is present.
  - **`IPRateLimitPlugin` needs an address source.** `Http.make` throws `ClientAddressConfigError` when the `Hooks` in `services` include `IPRateLimitPlugin` and neither `trustedProxy` nor `allowMissingClientIp: true` is set, because a Web `Request` has no socket address.
  - **Requests that cannot be limited are refused.** `IPRateLimitPlugin` fails a hook with `RateLimitError` (`429` over HTTP) when the request has no client address, including when no `ClientIP` service is in scope, as for a hook run outside an HTTP request. The group layers composed by hand outside `Http.make` (`authGroupLayer`) answer `429` when a configured limit has no `RateLimiter` in scope, or when the registration limit has no client address. Such a request is never let through unlimited and never counted under a bucket shared with other callers.
- e6c3a64: Dynamic client registration is rate limited per client address, so `OidcProviderService.layer` (and `OidcProvider.make`) needs an address source when `dynamicRegistration` is set. With neither `dynamicRegistration.trustedProxy` nor the opt-out `dynamicRegistration.allowMissingClientIp: true`, the layer fails at build with `ClientAddressConfigError`, before any request. `trustedProxy` takes the same value as the app's `Http.make` `trustedProxy` (for example `ClientIP.cloudflare`); the OIDC layer uses it only for this check and resolves no addresses itself. The opt-out skips only the build check: a registration with no address is refused with `429`, and is never counted under a shared bucket. `mcpProviderPreset` always enables dynamic registration, so an MCP provider must also declare one of the two (#388).
  
  `ClientAddressConfigError` is exported from the package root as well as from `./http` (`Http.ClientAddressConfigError`); both names are the same class.
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
  
  **`@thomasfosterau/effect-auth-sql`.** The RBAC tables feed the kernel in two halves:
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
- 213497b: `UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
  writes the password hash through
  `Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
  `@thomasfosterau/effect-auth-sql` and `@thomasfosterau/effect-auth-drizzle`
  implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
  `UserStore.GetUser` batch user reads.
- f5bf843: Rate limits keyed by client address need an address source. A Web `Request` carries no socket address, so `Http.make` with `ipRateLimit` requires `trustedProxy` (for example `ClientIP.cloudflare`), and throws `ClientAddressConfigError` at build without one. An app that sets `trustedProxy` also gets `429` on rate-limited endpoints when a request's trusted header is missing or unusable and so has no socket address, such as service-binding or health-check traffic. The new `allowMissingClientIp: true` option accepts that address-less requests to rate-limited endpoints are refused with `429`. Such a request is never let through unlimited and never counted under a bucket shared with other callers. This includes the dynamic client registration limit on `POST /register`, which refuses it too (#358).
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
- c092987: Add system principals: a reserved `System::"<name>"` entity for background jobs, cron handlers and pipeline steps, denied everything by default and allowed exactly what an explicit grant names (#192).
  
  - `System.provide(name)` and `System.layer(name)` provide `Authorizer.CurrentPrincipal` as the named system principal, with no session or user.
  - `System.grant(name, { id, action, resource, when? })` builds the grant: a permit scoped to that principal, naming one action and one resource scope. `System.declaration` is the model entry grants validate against.
  - `System.ref`, `System.isSystem` and `System.entityType` construct and recognise the reserved type.
  - The policy kernel keeps system principals default-deny under every policy set (#377): a permit reaches a system principal only when its principal scope names the `System` type (`System.grant`, `Policy.eq(System.ref(…))`, `Policy.isType("System")`). Unscoped permits (`Policy.permit` with no principal, `Policy.permission`, including `{ action: "*", resource: "*" }`, `Policy.action`, `Policy.roleAtLeast`, the `OwnedAccess` policies), role permits and `Policy.custom` permits never match one. Forbids bind system principals like any other principal.
  - Role assignment is for users: `Rbac.entities`, `Rbac.model` and `Rbac.layer` refuse `"System"` as the principal type.
  - `Guard.make` refuses `"System"` as a viewer's principal type, and its rung and owner policies are scoped to the viewer's principal type.
  - `Authorizer` and `protectedField` log every decision about a system principal, allows at info and denials at warning, with the principal's name and the determining policy ids. A denial's error message names the principal.
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

- 8ebcb4a: With `antiEnumeration: true`, `POST /sign-up` answers an email and password sign-up for an address another user holds as it answers a fresh one (#414), with the same id shape when the store's ids are random UUIDs or it implements `newUserId`: a `200` with the same headers and no `Set-Cookie`, and a `user` with the same fields, whose `email` is the submitted address, trimmed and lower-cased, with `emailVerified: false`. Response timing can differ between the two; the `EmailPasswordConfig.antiEnumeration` docs say how. The sign-up response takes `email` from the address submitted with the sign-up, which `AuthLifecycleResult` carries as `identifier`.
  
  The stand-in user in that answer has one timestamp for both `createdAt` and `updatedAt`. Its id is a random UUID, or comes from the optional `EmailPasswordStore.newUserId` seam, so a store whose ids have another shape can give the stand-in an id of that shape.
  
  `UsernameService.signUp` claims no username for the stand-in, so a sign-up with a held address cannot squat a username. It fails with `UsernameError` when someone holds the username by then, as the claim does. The `EmailPasswordConfig.antiEnumeration` docs list what the two answers share and what tells them apart.
- a1b01ae: With `EmailPasswordConfig.antiEnumeration` and email verification on, `AuthLifecycleService.signUp` stores a verification record, runs the `beforeCreateVerification` and `afterCreateVerification` hooks and sends a verification link only for a fresh sign-up (#422). A sign-up for an address another user holds is answered by a stand-in user that no row backs, so it gets none of these: the address's holder is never sent a link that can't verify.
  
  The optional `AuthLifecycleConfig.sendExistingAccountNotice` sends that holder a notice that someone tried to sign up with the address, so each of the two answers makes one send. `emailCallbacks(...).sendExistingAccountNotice` derives it from an `EmailSender`, under the `"existing-account"` delivery purpose, off the response path like the other derived callbacks. A failed notice fails the sign-up with the same `EmailVerificationError` a failed verification send does. Without the option, such a sign-up sends nothing.
- b9a8437: With `antiEnumeration: true`, email and password sign-up answers an address found taken at the insert (a lost race, or a store whose `createUser` reports `created: false`) exactly as it answers one the pre-check finds taken: it hashes the submitted password and returns the same no-session result, so neither the response nor its timing tells an existing account apart (#410).
  
  `CreateUserResult` and every `createUser` seam's docs state that a writer leaves an existing user's row unmodified: a plain `INSERT` that lets the unique index fail, or `ON CONFLICT DO NOTHING` followed by a select, and never `ON CONFLICT DO UPDATE`. effect-auth-drizzle's `SingleTableIdentifierStore` docs and README say the same for `onConflictDoNothing` and `onConflictDoUpdate`, and the README's writers return the user's `name`.
- b2e7fd4: `makeAuthorizationMiddleware` results can now be attached with `HttpApiEndpoint.middleware(...)` and `HttpApiGroup.middleware(...)`, which rejected them with a type error. The factory's return type named the class value rather than its instance; it now uses the instance type, the same shape `AuthMiddleware` has. Runtime behaviour is unchanged. The `.layer` property is now typed as providing that instance type, which is what an attached endpoint requires; two types are newly exported, `AuthorizationMiddlewareConfig` and `AuthorizationMiddlewareInstance` (#313).
- bbb24fe: TSDoc for `makeAuthorizationMiddleware` gives the runtime key of a guard: `@effect-auth/AuthorizationMiddleware/<name>#<n>`, where `<n>` counts factory calls. The type-level key is the bare name, so the two differ.
- 048e031: Documentation only: the JSDoc `@example` blocks now type-check, so `vp run docs` (the API reference generator) passes and CI runs it. No runtime change.
- 69b1d18: Doc comments only: the `Ladder.make` and `Hooks` class examples now run under docgen. The `Ladder` example moved from the module comment (which docgen does not read) onto `make`, and the `Hooks.tap` example moved from the `static readonly` member (which docgen does not extract) onto the `Hooks` class. Both assert their results. The `.d.ts` changes are those doc comments.
- 6d6bf02: Doc comments only: the `@example` blocks now run under docgen (`runExamples`), so each one is a standalone program with in-memory stores and inline config, and it fails if its assertions do not hold. The `.d.ts` changes are the rewritten examples.
- 61847b0: Every exported symbol has a doc-comment summary that shows in editor hovers: the core's service classes (with the stores each one requires), configs and results, the `Condition` and `Policy` scope constructors, the `Observability` record helpers, the HTTP list views and error schemas, the SQL stores and their layers, drizzle's row types and every `databaseLayer` overload, and `AuthClientOptions`. `hashToken` carries its own doc comment, and the client module overview opens with its summary rather than a tag line.
  
  Doc comments on `SessionResolution.resolveFailOpen` and `resolveAtEdgeFailOpen` (`http/RemoteSession.ts`) point at `docs/ARCHITECTURE.md` for the fail-open precondition.
- 89802ec: Built and tested against Effect `4.0.0`. The `effect` peer floor is unchanged (`>=4.0.0-rc.118`), so consumers still on `4.0.0-rc.118` keep working; `@effect/*` companions such as `@effect/sql-pg` should match whichever `effect` you install.
- 03bdfea: Email change claims the new address first and releases the previous address after the claim succeeds. A failed claim, whether another account took the address or the identifier store failed, leaves the user's previous address in place and verified, and the confirm token is not consumed (#364).
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- 6bee50c: `Http.make` runs the `services` build until it finishes, and no further. A fiber the build forks with `Effect.forkChild` is interrupted when the layer that forks it finishes building. Under `Layer.merge` or `Layer.mergeAll` that is the merged layer's own build, which can end ahead of the whole `services` build, so a fiber that has not started by then never runs. A fiber forked into the layer's scope (`Effect.forkScoped`) keeps running under the default scheduler after `make` returns, and stops on `dispose`; a fiber forked with `Effect.forkDetach` keeps running, and `dispose` does not stop it. Any failure of a `services` build that finishes while `make` runs makes `make` throw, so the app fails to start: the failure's error, or for a defect the defect itself, as `Effect.runSync` throws. An example is the OIDC layer's `ClientAddressConfigError` for dynamic registration with no address source. `make` releases what the build acquired, then throws: a finalizer that does asynchronous work finishes after `make` has thrown, and a finalizer that fails is logged as an error. A `services` build that waits on asynchronous work, on a merged layer that yields or runs past Effect's per-slice operation budget, or, when it fails, on a finalizer that does asynchronous work, finishes after `make` returns. Its failure then fails the handler's build instead, and every request rejects with it; `Http.makeAsync` rejects at startup for those builds (#402). The startup errors and the release log name both `Http.make` and `Http.makeAsync`.
- f4f6606: Tighten the empty encryption-secret check introduced with the rc.118 move (#252).
  
  - A secret that is present but **whitespace-only** (for example `"   "` or a lone newline) now fails `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with the same "set but empty" `ConfigError` as `""`. A secret with surrounding spaces but non-space content is still accepted, unchanged and untrimmed. An unset variable still leaves encryption off.
  - Fix a false "set but empty" when the secret is unset but variables whose names extend it with numeric suffixes (`TWO_FACTOR_ENCRYPT_SECRET_0`, `_1`) are set; they are now treated as sharing the prefix.
- 373bb87: Email OTP and phone OTP verification answer an address with and without an account alike where `send` hides which addresses have one: sign-in with `disableSignUp`, and email OTP `forget-password` (#417).
  
  - In those configurations, every code that fails verification answers `Invalid or expired OTP`, whether the code is wrong, has expired or has reached `maxAttempts`, so `/sign-in/email-otp` and `/sign-in/phone-otp` return the same 400 body for every address. The reason is recorded on the `signIn` / `check` span as `auth.otp.failure`. Everywhere else, an expired code answers `OTP has expired` and the attempt limit answers `Too many attempts`.
  - In the same configurations, and in magic-link sign-in with `disableSignUp`, `send` stores an undelivered marker record for an address with no account whether or not `resendCooldown` is set, so a known and an unknown address get the same store work. An OTP marker expires and counts attempts exactly as a code's record does, and no code redeems it.
- 1d47091: `pbkdf2Hasher().verify` now refuses a stored iteration count above a cap before running PBKDF2, as `scryptHasher` already does for N, r and p. A crafted `pbkdf2-sha256$<iterations>$…` hash could previously make `verify` run PBKDF2 at up to Node's 2³¹−1 (about 3,500 times the 600,000 default, minutes of CPU per attempt); exploiting it needs write access to the password-hash store. The refusal is a `HashingError` ("Invalid hash parameters: …"), and `needsRehash` returns true for such a hash.
  
  The cap is max(5,000,000, the configured `iterations`), so the hasher's own hashes always verify, including at a configured count above 5,000,000. A non-finite, fractional or out-of-range `iterations` option does not raise the cap. A hash written at more than 5,000,000 iterations verifies only on a hasher configured at that count or higher, so lowering `iterations` below such a count makes those hashes unverifiable (#328).
- 624f356: Metric counter names follow the Prometheus naming rule (`[a-zA-Z_:][a-zA-Z0-9_:]*`), using underscores only: `effect_auth_sign_in_total`, `effect_auth_sign_up_total`, `effect_auth_sessions_created_total`, `effect_auth_sessions_validated_total`, `effect_auth_sessions_invalidated_total`, `effect_auth_session_resolutions_total`, `effect_auth_token_verifications_total`, `effect_auth_rate_limit_hits_total`, `effect_auth_multi_factor_challenges_total`, `effect_auth_multi_factor_verifications_total`, `effect_auth_oauth_callbacks_total`, `effect_auth_oauth_refreshes_total`, `effect_auth_webauthn_registrations_total`, `effect_auth_webauthn_authentications_total`, `effect_auth_oidc_token_requests_total` and `effect_auth_delivery_sends_total`.
  
  OpenTelemetry span names use dotted notation and are exported as constants in `Observability.spanNames`.
- 89749b6: With `antiEnumeration` off, `AuthLifecycleService.signUp` answers a sign-up for an address another user holds unverified with no session, `needsEmailVerification: true` and a stand-in user built only from the caller's input (#421): a random UUID for its `id`, the submitted `name` and `attributes`, no `image`, and one timestamp for both `createdAt` and `updatedAt`. The holder's id, profile and timestamps stay out of the response, both from `signUp` and from `POST /sign-up`. When `sendOnSignUp` is set, the holder's verification is re-issued to the address. An address held verified fails with `EmailInUseError` (`409` over HTTP). The `AuthLifecycleResult.identifier` docs describe each answer.
- 8fce539: `resendCooldown` answers a known and an unknown address alike in the passwordless flows that hide whether an account exists: magic-link, email OTP and phone OTP sign-in with `disableSignUp`, and email OTP `forget-password` (#415). A request for an address with no account stores an undelivered record as its cooldown marker, so a repeat within the window fails with `ResendTooSoonError` (HTTP 429, the same body and headers) exactly as it does for an account holder. The marker is never sent and can't be redeemed: a magic-link marker is a random 32-byte token, and an OTP marker holds the hash of a random 32-byte secret rather than of a code, so no code matches it. Every OTP send draws both the code and the marker secret, so the random work is the same for a known and an unknown address. If an address gains an account within the window, the marker delays its first send by up to the cooldown.
- 68e339a: scrypt hashing and verifying no longer fail when `p + 2 > N` (for example a stored hash with N = 4, p = 8): `maxmem` is now `128 * r * (N + p + 2)`, the memory OpenSSL's scrypt needs.
- 2ba63b6: scrypt `verify` now checks the N, r and p it reads from a stored hash before it runs the KDF, and refuses a set outside the limits with a `HashingError` rather than a defect or a boolean. N must be a power of two with 2 ≤ N ≤ max(2^20, the configured cost). r must be an integer from 1 to max(32, the configured block size), and p an integer from 1 to max(16, the configured parallelization). The memory a derivation needs, `128 * r * (N + p + 2)`, must not exceed max(256 MiB, the memory the configured parameters need), so the hasher's own hashes always verify while a crafted hash cannot request gigabytes. A synchronous throw from Node's `crypto.scrypt` is now also a `HashingError`. `needsRehash` returns true for a hash `verify` would refuse, and for one whose r or p is below the configured value, as it already did for N. `hash` now applies the same checks to the configured cost, block size and parallelization, and fails with a `HashingError` for a configuration its own `verify` would refuse (for example `blockSize: 0`, which Node accepts), instead of writing a hash that can never verify. A non-finite configured value cannot lift the caps.
