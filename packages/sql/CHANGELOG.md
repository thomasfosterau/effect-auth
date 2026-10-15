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
- 213497b: `UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
  writes the password hash through
  `Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
  `@thomasfosterau/effect-auth-sql` and `@thomasfosterau/effect-auth-drizzle`
  implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
  `UserStore.GetUser` batch user reads.
- ca3abfb: Every SQL `createUser` seam (`EmailPasswordStore`, `OAuthUserStore`, `MagicLinkUserStore`, `EmailOtpUserStore` and `AdminUserStore`) resolves to core's `CreateUserResult`, `{ user, created: true }`: each is a plain `INSERT` with a fresh id, so every success is a new user (#406).
- 9ff7ded: The SQL `IdentifierStore` implements `replace`: it inserts the new identifier and deletes the old one inside `sql.withTransaction`, so a value another user holds is refused by the `(type, value)` unique index and the transaction rolls back with the old identifier in place. The release is a `DELETE … RETURNING` guarded on the old identifier's id, user, type and value: when it deletes nothing, the new identifier is deleted again and `replace` resolves to `null`, so of two concurrent replaces of the same identifier one succeeds (at PostgreSQL's default READ COMMITTED isolation; at stricter levels the losing call fails with a serialization error, surfaced as `AuthError`). On Cloudflare D1 (`@thomasfosterau/effect-auth-alchemy`), which has no transactions, the two statements autocommit in the same order, so a failure between them leaves the user holding both identifiers, never neither, and confirming an email change again releases the old one; the losing call of two concurrent replaces deletes its new identifier in a statement of its own, so a failure before it leaves the user holding both new identifiers (#381).

### Patch Changes

- 61847b0: Every exported symbol has a doc-comment summary that shows in editor hovers: the core's service classes (with the stores each one requires), configs and results, the `Condition` and `Policy` scope constructors, the `Observability` record helpers, the HTTP list views and error schemas, the SQL stores and their layers, drizzle's row types and every `databaseLayer` overload, and `AuthClientOptions`. `hashToken` carries its own doc comment, and the client module overview opens with its summary rather than a tag line.
  
  Doc comments on `SessionResolution.resolveFailOpen` and `resolveAtEdgeFailOpen` (`http/RemoteSession.ts`) point at `docs/ARCHITECTURE.md` for the fail-open precondition.
- 89802ec: Built and tested against Effect `4.0.0`. The `effect` peer floor is unchanged (`>=4.0.0-rc.118`), so consumers still on `4.0.0-rc.118` keep working; `@effect/*` companions such as `@effect/sql-pg` should match whichever `effect` you install.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- cbeda0d: Document the supported dialects. `@thomasfosterau/effect-auth-sql` supports SQLite, Cloudflare D1 and PostgreSQL. MySQL is not supported: its upserts and counters use `ON CONFLICT`, which MySQL lacks, so MySQL users should take `@thomasfosterau/effect-auth-drizzle`'s MySQL tables (#260). `@thomasfosterau/effect-auth-alchemy`'s module docs say the sql DDL is valid on SQLite, D1 and PostgreSQL, not MySQL.
- 8f78034: Fix `rateLimit.increment` and `accountLockout.registerAttempt` on PostgreSQL. Their `ON CONFLICT … DO UPDATE SET` right-hand sides now qualify the target table's columns, which PostgreSQL rejected as ambiguous (`column reference "reset_at" is ambiguous`). SQLite behaviour is unchanged. The store suite now also runs over PostgreSQL (PGlite), and the README, module docs and TSDoc list PostgreSQL as a supported dialect.
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [29d011c]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [9ff7ded]
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
- Updated dependencies [c99689b]
- Updated dependencies [1d47091]
- Updated dependencies [3de5d6a]
- Updated dependencies [624f356]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
- Updated dependencies [f5bf843]
- Updated dependencies [8fce539]
- Updated dependencies [311e9cb]
- Updated dependencies [a81a752]
- Updated dependencies [68e339a]
- Updated dependencies [2ba63b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [03a3219]
- Updated dependencies [c092987]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.2.0
