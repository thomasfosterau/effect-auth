---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": minor
---

One authorization model: the policy kernel. RBAC is authoring sugar that compiles into it, and
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
