# @thomasfosterau/effect-auth-sql

## 0.2.0

### Minor Changes

- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).
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
- a108a36: Add `makeApiKeyStore`/`ApiKeyStoreLayer` and `makeAdminUserStore`/`AdminUserStoreLayer`, closing the two SQL storage gaps blocking the API-key and admin planes.
  
  - **`ApiKeyStore`** backs a new `auth_api_keys` table. Every core field round-trips, including `permissions`/`metadata` (JSON), the refill quota fields, and the optional per-key `rateLimit`; `key_hash` carries a unique index for `getByHash` lookups and, like every other bearer-token column in this schema, is the only form of the key ever persisted.
  - **`AdminUserStore`** reuses `auth_users` (via the same `userQueries` helpers as `EmailPasswordStore`) for `createUser`/`setPasswordHash`, and resolves `listUsers`'s `searchEmail` against each user's earliest `auth_identifiers` email record — matching, sorting, and paginating in memory, mirroring the reference semantics in core's `Admin.test.ts`.
  
  Both are now included in the aggregate `layer` export and `migrate`'s schema statements.
- 8213f5b: `purgeExpired` deletes the magic-link and email-OTP rows whose expiry has passed and reports how many it deleted from each table. No store deletes them on its own, and the sends that hide whether an account exists write one for any address, so a host schedules this (a cron trigger on Workers, a timer on a long-lived server) to keep the tables bounded. effect-auth-sql exports it over the ambient `SqlClient`; effect-auth-alchemy exports `purgeExpired(db)` over a D1 binding. The schema gains an `expires_at` index on each of the two tables, which `migrate` adds on the next run (#420).
- 856d6fe: New `readScopeWhere(scope, { columns, sets? })` (#190): renders a core `ReadScope` as a SQL `WHERE` fragment over any relation's columns, so a LIST filters in the database. It is two-valued on NULL columns, keeps named sets as subqueries, narrows when a set's fragment is missing, and lists nothing when a column is missing.
- 213497b: `UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
  writes the password hash through
  `Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
  `@thomasfosterau/effect-auth-sql` and `@thomasfosterau/effect-auth-drizzle`
  implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
  `UserStore.GetUser` batch user reads.
- a517a32: **Security — verifying an address no longer hands the verifier an account whose password someone else chose (#425).** The first time `AuthLifecycleService.verifyEmail` verifies an address (`POST /email-verification/verify`), it clears the account's password and revokes all of its sessions before marking the address verified. Until then no one had proven they own the address, so an attacker could sign up with a victim's address and a password they know, and the victim's later verification (from the attacker's sign-up email, a re-send, or the victim's own recovered sign-up) left the attacker able to sign in. The verifier now sets a password afterwards, with `EmailPasswordService.setPassword` from the session the verification issues (with `autoSignInAfterVerification`, the default) or through a password reset. Verifying an address already verified changes neither.
  
  This applies to every first verification, the account's real owner included: after verifying, a user who signed up with a password has none until they set one, and any session they held before verifying is signed out.
  
  **Breaking — `EmailPasswordStore` gains a required `clearPasswordHash(userId)`**, which removes the user's password so `getPasswordHash` returns `null` (a no-op when there is none). `EmailPasswordService` gains `clearPassword(userId)` over it. effect-auth-sql's `EmailPasswordStore` implements it (`password_hash = NULL`); the effect-auth-client `./testing` server implements it in memory.
  
  **The recovered sign-up acts on the address the `beforeSignUp` hooks returned (#426).** With `antiEnumeration` off, a sign-up for an address held unverified looks the holder up by the address `EmailPasswordService.signUp` found taken, not the raw submitted one, and answers with that address as its `identifier`. `EmailInUseError` carries that address as an optional `email` (never sent over HTTP); `AccountManagementService`'s change-email sets it too.
- ca3abfb: Every SQL `createUser` seam (`EmailPasswordStore`, `OAuthUserStore`, `MagicLinkUserStore`, `EmailOtpUserStore` and `AdminUserStore`) resolves to core's `CreateUserResult`, `{ user, created: true }`: each is a plain `INSERT` with a fresh id, so every success is a new user (#406).
- 9ff7ded: The SQL `IdentifierStore` implements `replace`: it inserts the new identifier and deletes the old one inside `sql.withTransaction`, so a value another user holds is refused by the `(type, value)` unique index and the transaction rolls back with the old identifier in place. The release is a `DELETE … RETURNING` guarded on the old identifier's id, user, type and value: when it deletes nothing, the new identifier is deleted again and `replace` resolves to `null`, so of two concurrent replaces of the same identifier one succeeds (at PostgreSQL's default READ COMMITTED isolation; at stricter levels the losing call fails with a serialization error, surfaced as `AuthError`). On Cloudflare D1 (`@thomasfosterau/effect-auth-alchemy`), which has no transactions, the two statements autocommit in the same order, so a failure between them leaves the user holding both identifiers, never neither, and confirming an email change again releases the old one; the losing call of two concurrent replaces deletes its new identifier in a statement of its own, so a failure before it leaves the user holding both new identifiers (#381).

### Patch Changes

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
- 42d0f03: Drop the remaining Node `Buffer` uses in the OAuth module and the SQL stores, in favour of `effect/encoding`, `Schema`'s base64 codecs and `TextEncoder`, so they no longer rely on a Node global in Workers and browsers. `RenderedEmail.html` and `.text` in effect-auth-resend are now `?: string | undefined`, so a renderer can forward an optional value under `exactOptionalPropertyTypes`.
- 78dac5f: Correct the `layer` doc comment: core's `KeyValueStore`-backed layers do not cover the stores this package lacks (one-time token, trusted device, phone OTP, organization, OIDC, SSO, device authorization), so implement those yourself until they land here.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- 504ae0d: Export the `EmailAddress`, `Attributes` (from the HTTP schemas) and `ApiKeyRateLimit` types alongside their schemas. effect-auth-sql mints row ids with `globalThis.crypto.randomUUID()` instead of importing `node:crypto`.
- 00aa6e9: `purgeExpiredKV` deletes the magic-link tokens and email OTP records whose `expiresAt` has passed from the `KeyValueStore`-backed stores (`MagicLinkStoreKV`, `EmailOtpStoreKV`, so `layerKV` and `Testing.memoryStores`) and reports how many it deleted from each; a purged magic link also leaves its address's index. A `KeyValueStore` cannot list its keys, so the purge also requires the new `KeyValueStoreKeys` service, whose `list(prefix)` the host implements over its backend (Workers KV `list({ prefix })`, Redis `SCAN`). `layerMemoryKeyValueStore` is an in-memory `KeyValueStore` with that listing over the same map, and `Testing.memoryStores` now runs on it and provides both services, so the purge runs against it. As with effect-auth-sql's `purgeExpired`, the host schedules it; no store deletes these records on its own (#420).
  
  effect-auth-sql's `purgeExpired` now keeps a row whose `expires_at` equals the current time: the services still accept such a code or link, so deleting it changed an outcome.
- 5a48055: Services, stores and the HTTP handlers read the current time from Effect's `Clock` (`Clock.currentTimeMillis`, `DateTime.now`, `DateTime.nowAsDate`) instead of `Date.now()` / `new Date()` (#443). Under the default clock nothing changes; under `TestClock` (or any custom `Clock` layer) token, OTP, session, invitation, rate-limit and JWT expiry, `createdAt` / `updatedAt` / `verifiedAt` stamps, the SAML subject-confirmation window and the in-memory stores in `@thomasfosterau/effect-auth/testing` all follow that clock. `generateTotp` reads the time when its effect runs, not when it is built.
- cbeda0d: Document the supported dialects. `@thomasfosterau/effect-auth-sql` supports SQLite, Cloudflare D1 and PostgreSQL. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). `@thomasfosterau/effect-auth-alchemy`'s module docs say the sql DDL is valid on SQLite, D1 and PostgreSQL, not MySQL.
- 8f78034: Fix `rateLimit.increment` and `accountLockout.registerAttempt` on PostgreSQL. Their `ON CONFLICT … DO UPDATE SET` right-hand sides now qualify the target table's columns, which PostgreSQL rejected as ambiguous (`column reference "reset_at" is ambiguous`). SQLite behaviour is unchanged. The store suite now also runs over PostgreSQL (PGlite), and the README, module docs and TSDoc list PostgreSQL as a supported dialect.
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
