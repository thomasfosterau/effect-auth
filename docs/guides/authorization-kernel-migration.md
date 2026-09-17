# Migrating off `RoleStore` and `AuthorizationPolicy`

effect-auth used to ship two authorization models. It now ships one — the policy kernel — and RBAC
is authoring sugar that compiles into it. See
[ADR 0018](../adr/0018-one-authorization-kernel.md) for why.

This is a breaking change with no compatibility shim. Everything below is a compile error until
you migrate, which is deliberate: an authorization surface that silently changes meaning is worse
than one that refuses to build.

## What was removed

| Removed                                               | Replacement                                                                           |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `Auth.AuthorizationPolicy`                            | `Auth.Authorizer`                                                                     |
| `Auth.RoleStore`                                      | `Auth.Rbac.entities` / an `Auth.EntityResolver`                                       |
| `Rbac.make(config)` (returned a `RoleStore`)          | `Auth.Rbac.policies` / `.entities` / `.model` / `.layer`                              |
| `Auth.InMemoryRoleStoreConfig`                        | `Auth.Rbac.RbacConfig` (same shape)                                                   |
| `Auth.requirePermission(userId, resource, action)`    | `Authorizer.authorize({ action, resource })`                                          |
| `Auth.can(userId, resource, action)`                  | `Authorizer.check({ action, resource })`                                              |
| `Auth.requireAllPermissions` / `requireAnyPermission` | `Effect.forEach` / `Effect.firstSuccessOf` over `authorize`                           |
| `Auth.allowAll` / `Auth.denyAll`                      | `Policy.permit({ id })` / `Policy.forbid({ id })`                                     |
| `Auth.fromPredicate`                                  | `Policy.custom({ id, predicate })`                                                    |
| `Auth.anyOf`                                          | several permits in one policy set (permits already OR)                                |
| `Auth.not`                                            | a `Policy.forbid` (forbid overrides permit)                                           |
| `Auth.allOf`                                          | one policy whose `when` is a `Condition.and(...)`, or `Policy.custom`                 |
| `Sql.makeRoleStore` / `Sql.RoleStoreLayer`            | `Sql.makeRbacEntityResolver` / `Sql.RbacEntityResolverLayer` + `Sql.readRbacPolicies` |

`Errors.PermissionDeniedError` still exists for application use, but nothing in the library raises
it any more — a kernel denial is `Policy.AuthorizationDeniedError`, which carries the full
`Decision` trace.

## The shortest migration

If you were building a `RoleStore` from the in-memory builder, your configuration object is
unchanged — only what you do with it changes. (Hand-written `RoleStore` implementations map the
same way: `getUserRoles` becomes `userRoles`, `getRolePermissions` becomes `rolePermissions`.)

**Before:**

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
// `Rbac.make` was never re-exported from the barrel; `Auth.Rbac` now is.
const store = Rbac.make({
  userRoles: { "user-1": ["editor"] },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "update" }],
    admin: [{ resource: "*", action: "*" }],
  },
  roleHierarchy: { editor: ["viewer"] },
});

const layer = Auth.AuthorizationPolicy.layer().pipe(
  Layer.provide(Layer.succeed(Auth.RoleStore)(store)),
);

const program = Effect.gen(function* () {
  const policy = yield* Auth.AuthorizationPolicy;
  const canRead = yield* policy.checkPermission("user-1", "posts", "read");
});
```

**After:**

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const layer = Auth.Rbac.layer({
  userRoles: { "user-1": ["editor"] },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "update" }],
    admin: [{ resource: "*", action: "*" }],
  },
  roleHierarchy: { editor: ["viewer"] },
});

const program = Effect.gen(function* () {
  const authorizer = yield* Auth.Authorizer;
  const canRead = yield* authorizer.check({
    action: "read",
    resource: Auth.Entity.ref("posts", "post-1"),
  });
}).pipe(Auth.CurrentPrincipal.provide(Auth.Entity.ref("User", "user-1")));
```

## The three shape changes to expect

**1. The principal moves from an argument to context.** `checkPermission` took a `userId: string`.
The kernel reads `Auth.CurrentPrincipal` — an `Entity.EntityRef` — so a user id becomes
`Entity.ref("User", userId)`. Provide it once per request (`CurrentPrincipal.provide(...)`, or via
the HTTP session middleware) instead of threading it through every call site.

**2. Resources are instances, not type names.** `checkPermission(u, "posts", "read")` named a
resource _type_. A kernel request names a concrete resource — `Entity.ref("posts", postId)` — and
the generated policy is scoped `resource is posts`, so a type-level question is asked by supplying
any id of that type. This is the change that makes read scopes possible: a policy that talks about
a resource can be partially evaluated against an unbound one.

**3. Denials carry a trace.** `checkPermission` returned `boolean` with a `never` error channel.
`Authorizer.check` returns a boolean too, but `Authorizer.authorize` fails with
`Policy.AuthorizationDeniedError` carrying a `Decision` — `allowed`, `reason`
(`"forbid"` / `"permit"` / `"default-deny"`), the determining policies and every policy's outcome.
Audit hooks and spans should read that instead of re-deriving why.

## Wildcards

`"*"` semantics are unchanged and covered by tests. `{ resource: "*", action: "*" }` compiles to a
permit with both slots unscoped (superadmin); `{ resource: "posts", action: "*" }` leaves the
action unscoped within the `posts` type.

## Role inheritance

`roleHierarchy` still means "this role inherits its parents' permissions", but the mechanism
changed: instead of pre-expanding a flattened permission set per role, `Rbac.entities` emits a
`Role -> Role` edge and the kernel's `in` check walks it. Cycles are still tolerated. The visible
difference is in the trace — an inherited grant is determined by the _parent's_ policy id
(`rbac:viewer:posts:read`), not by a copy under the child's name.

## Composing with your own policies and entities

`Rbac.layer` is the batteries-included path: it derives the policies, the model and an in-memory
entity resolver, and ignores any `PolicyStore` in context. When RBAC is only part of the picture,
compose the pieces yourself:

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const rbac = {
  userRoles: { "user-1": ["editor"] },
  rolePermissions: { editor: [{ resource: "posts", action: "update" }] },
} satisfies Auth.Rbac.RbacConfig;

const ownerMayEdit = Auth.Policy.permit({
  id: "posts:owner-may-edit",
  action: Auth.Policy.eq(Auth.Entity.ref("Action", "update")),
  resource: Auth.Policy.isType("posts"),
  // `resource.ownerId` is stored as an entity value (`{ __entity: User::"..." }`),
  // and the `principal` slot resolves to the same shape.
  when: Auth.Condition.eq(Auth.Condition.attr("resource", "ownerId"), Auth.Condition.principal),
});

const authorizer = Auth.Authorizer.layer({
  policies: [...Auth.Rbac.policies(rbac), ownerMayEdit],
});
```

Your `EntityResolver` must then return the RBAC entities _and_ your domain entities — merge
`Auth.Rbac.entities(rbac)` into whatever your resolver produces, since a single `EntityResolver`
fills one slot.

## SQL deployments

`auth_user_roles` and `auth_role_permissions` are unchanged. The adapter split in two, along the
same seam:

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Sql from "@thomasfosterau/effect-auth-sql";

const authorizer = Layer.unwrap(
  Effect.map(Sql.readRbacPolicies, (policies) =>
    Auth.Authorizer.layer({ policies, useStore: false }),
  ),
).pipe(Layer.provideMerge(Sql.RbacEntityResolverLayer));
```

Two behavioural notes. `Sql.RbacEntityResolverLayer` is **not** part of `Sql.layer`: an
`EntityResolver` is a slot an application composes (its own entities, the organization bridge,
this one), not a store to bundle. And `readRbacPolicies` reads `auth_role_permissions` once, where
the old `RoleStore` read it per check — if tenant edits must apply without a restart, put the
policies behind a `PolicyStore` instead, which `Authorizer` re-reads per decision.
