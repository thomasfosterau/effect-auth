# One authorization kernel; RBAC is authoring sugar over it

The library shipped two ways to answer "may this caller do this", co-exported from one barrel as
peers with no stated relationship between them.

The **flat path** was `Authorization.AuthorizationPolicy` — a single method,
`checkPermission(userId: string, resource: string, action: string) => Effect<boolean, never>` —
evaluated over a `RoleStore` (`getUserRoles` / `getRolePermissions`) of `{ resource, action }`
permission pairs, with `Rbac.make` building an in-memory store that pre-expanded role inheritance
into a flattened permission set. The **kernel** was `Policy` / `Condition` / `Entity` /
`AuthorizationModel` / `PolicyStore` / `Authorizer`: Cedar-shaped PARC requests, declarative
storable policies with a serialisable condition AST, a pure total decision procedure over a
pre-fetched `EntitySlice`, forbid-overrides-permit, fail-closed in both directions, and a
`Decision` carrying the determining policies (`docs/DESIGN.md` §D13).
`Protected.protectedField` was never a third model — it is the kernel projected onto schema
encode/decode, and says so.

**Only the kernel can be compiled.** A read scope — partially evaluating a policy against a known
principal and an _unbound_ resource to get back "which rows" — needs an unbound resource slot and
a condition AST to residualise. `checkPermission(userId, resource, action) => boolean` has
neither. This is a property of the flat path's _shape_, not a gap in its implementation: no amount
of work on `RoleStore` makes a rule authored through it participate in read authorisation. A
second cost compounded it: two places a security control could live, so "what may this role do"
had two answers and no rule saying which one wins.

## Decision

Collapse onto the kernel, and keep the flat _authoring_ surface as sugar that compiles into it.

`Rbac` is recast as a **policy builder**. The same `{ userRoles, rolePermissions, roleHierarchy }`
configuration now produces the two kernel artefacts instead of a store:

- `Rbac.policies(config)` — one `DeclarativePolicy` per (role, permission) pair, scoped
  `principal in Role::"<role>"`, `action == Action::"<action>"`, `resource is <resource>`. `"*"`
  maps to an unscoped slot, so `{ resource: "*", action: "*" }` stays superadmin.
- `Rbac.entities(config)` — the principal → role → parent-role fragment of the entity graph.
- `Rbac.model(config)` — the derived `AuthorizationModel`, so the generated policies validate.
- `Rbac.layer(config)` — the three wired into an `Authorizer`, which is the one-call setup the
  flat path used to be.

Role inheritance stops being a set union computed by a store and becomes a `Role -> Role` edge in
the entity graph, resolved by the kernel's cycle-safe `in` check. Inherited grants are therefore
**not** duplicated per child role: one policy per authored permission, and the hierarchy does the
rest. `Authorization.ts` — `AuthorizationPolicy`, `RoleStore`, `Authorization.make`, the
`allowAll` / `denyAll` / `fromPredicate` / `anyOf` / `allOf` / `not` combinators, and the
`requirePermission` / `can` / `requireAllPermissions` / `requireAnyPermission` guards — is deleted
outright. In `@thomasfosterau/effect-auth-sql`, `auth_user_roles` becomes an `EntityResolver`
(`makeRbacEntityResolver`) and `auth_role_permissions` becomes policies (`readRbacPolicies`),
routed through `Rbac.policies` so SQL rows and a hand-written configuration compile identically.

The rule, stated once: **there is one authorization model.** `Protected` is its data-boundary
projection, a read scope is its set-shaped projection, and RBAC is a way of _authoring_ policies,
not a second engine.

## The alternative we rejected

**Deprecate the flat path outright** — mark `AuthorizationPolicy`, `RoleStore` and `Rbac`
deprecated with a migration recipe and remove them at the next major, leaving the kernel as the
only surface. It is the simpler change: no builder to write, no mapping to keep honest, and the
smallest amount of code to carry.

We rejected it because it deletes the low-ceremony entry point along with the second engine, and
those are separable. The flat API's ergonomics were never the problem — its _evaluation_ was. Under
"deprecate outright", a first RBAC setup goes from a ten-line configuration object to declaring an
entity model, writing a resolver and hand-authoring one policy per grant, which is a real
regression for the majority of deployments whose authorisation genuinely is "roles grant
permissions". Recasting `Rbac` as a builder keeps that ten-line path _and_ makes everything
written through it compilable, traceable and model-checkable — so the shortest path and the
capable path stop being different paths.

The cost we accept is a mapping to maintain: the (role, permission) → policy translation is
library code that must stay faithful to the kernel's semantics, and it is one more thing to
document. We judge that cheaper than either carrying two evaluation paths or losing the adopters
on the flat one. Both routes break every existing consumer of `RoleStore`; the difference is
whether they land on a configuration object they already have (route taken) or on a hand-authored
policy set (route rejected).

## What this does not decide

The ordered role ladder (#188) and the zero-IO principal guards (#189) are deliberately left
unimplemented here. They now have one model to build on: an ordered ladder is a `memberOf` chain
or a comparison condition, and the guards are the kernel's zero-IO fast path over a resolved
slice. The read-scope residual (#203/#190) is likewise out of scope — what this ADR guarantees is
that a rule authored the short way is now a `DeclarativePolicy`, which is the thing a read scope
can be compiled from.
