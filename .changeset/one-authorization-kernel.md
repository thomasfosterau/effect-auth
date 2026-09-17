---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": minor
---

BREAKING: one authorization model. The flat permission-string path is **removed** and RBAC is
recast as authoring sugar that compiles into the policy kernel. Pre-1.0, so this ships as a minor
per semver's 0.x carve-out; there is no compatibility shim, and every consumer of `RoleStore` or
`AuthorizationPolicy` will get compile errors until they migrate. See
[ADR 0017](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/adr/0017-one-authorization-kernel.md)
for the decision and the rejected alternative, and
[the migration guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/authorization-kernel-migration.md)
for a step-by-step.

**Why.** Only the kernel can be partially evaluated: a read scope needs an unbound resource slot
and a condition AST to residualise, and `checkPermission(userId, resource, action) => boolean` has
neither. A rule authored through the flat path could therefore never participate in read
authorization — a property of its shape, not a gap in its implementation. Two evaluation paths
also meant two places a security control could live, with no rule saying which one wins.

**Removed from `@thomasfosterau/effect-auth`** (all previously root exports):
`AuthorizationPolicy`, `RoleStore`, `requirePermission`, `can`, `requireAllPermissions`,
`requireAnyPermission`, `allowAll`, `denyAll`, `fromPredicate`, `anyOf`, `allOf`, `not`, and the
`InMemoryRoleStoreConfig` type. `src/Authorization.ts` is deleted. `Rbac.make` (which returned a
`RoleStore`) is gone.

**Added.** `Auth.Rbac` is now a namespaced root export and a **policy builder**. The same
`{ userRoles, rolePermissions, roleHierarchy }` configuration produces kernel artefacts:

- `Rbac.policies(config)` — one `DeclarativePolicy` per (role, permission) pair, scoped
  `principal in Role::"<role>"` / `action == Action::"<action>"` / `resource is <resource>`.
- `Rbac.entities(config)` — the principal → role → parent-role entity fragment.
- `Rbac.model(config)` — the derived `AuthorizationModel` the generated policies validate against.
- `Rbac.entityResolver(config)` / `Rbac.entityResolverLayer(config)` / `Rbac.layer(config)` — the
  one-call `Authorizer` setup.
- `Rbac.RbacConfig` (replaces `InMemoryRoleStoreConfig`, same shape), plus `Rbac.roleRef`,
  `Rbac.policyId` and the `RoleEntityType` / `ActionEntityType` / `DefaultPrincipalType` constants.

`"*"` wildcard semantics are unchanged: `{ resource: "*", action: "*" }` compiles to a permit with
both slots unscoped. Role inheritance is unchanged in meaning but not in mechanism — it is now a
`Role -> Role` edge resolved by the kernel's cycle-safe `in` check rather than a pre-expanded
permission set, so an inherited grant is determined by the _parent's_ policy id in the trace.

**`@thomasfosterau/effect-auth-sql`.** `makeRoleStore` and `RoleStoreLayer` are removed. The same
tables now feed the kernel in two halves: `makeRbacEntityResolver` / `RbacEntityResolverLayer`
project `auth_user_roles` into `Role::` parents, and `readRbacPolicies` compiles
`auth_role_permissions` into declarative permits via `Rbac.policies`. `Auth.RoleStore` is no
longer part of the bundled `Sql.layer` — `EntityResolver` is a slot an application composes, not a
store to bundle — and `readRbacPolicies` reads once at wiring time where the old store read per
check (put policies behind a `PolicyStore` if tenant edits must apply without a restart).

`Errors.PermissionDeniedError` remains exported for application use, but nothing in the library
raises it any more; a kernel denial is `Policy.AuthorizationDeniedError`, which carries the full
`Decision` trace.
