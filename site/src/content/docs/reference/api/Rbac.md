---
title: "Rbac"
description: "API reference for the Rbac module."
---

## Rbac overview

In-memory {@link RoleStore} builder for role-based access control (RBAC).

This removes the boilerplate of hand-rolling a `RoleStore` from `Map`s and
adds optional role inheritance: a role can declare parent roles whose
permissions it inherits (resolved transitively, guarding against cycles).

Pair the resulting store with {@link makeRoleBasedPolicy} (which understands
`"*"` wildcard permissions) for a complete RBAC setup.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [InMemoryRoleStoreConfig (interface)](#inmemoryrolestoreconfig-interface)
  - [makeInMemoryRoleStore](#makeinmemoryrolestore)

---

# utils

## InMemoryRoleStoreConfig (interface)

Configuration for {@link makeInMemoryRoleStore}.

**Signature**

```ts
export interface InMemoryRoleStoreConfig {
  /** Map of `userId` to the roles assigned to that user. */
  readonly userRoles: StringKeyed<readonly string[]>;
  /** Map of role name to the permissions directly granted by that role. */
  readonly rolePermissions: StringKeyed<readonly PermissionRef[]>;
  /**
   * Optional map of role name to parent roles. A role inherits all permissions
   * of its parents (transitively). Cycles are tolerated and resolved safely.
   */
  readonly roleHierarchy?: StringKeyed<readonly string[]>;
}
```

## makeInMemoryRoleStore

Create an in-memory {@link RoleStore} from static configuration.

The returned store is synchronous (its methods wrap results in
`Effect.succeed`). When `roleHierarchy` is provided, `getRolePermissions`
returns the union of a role's own permissions and those of all ancestor
roles, de-duplicated by `"resource:action"`.

**Signature**

```ts
export declare const makeInMemoryRoleStore: (config: InMemoryRoleStoreConfig) => RoleStore;
```

**Example**

```ts
import { makeInMemoryRoleStore } from "effect-auth";

const store = makeInMemoryRoleStore({
  userRoles: { "user-1": ["editor"] },
  rolePermissions: {
    viewer: [{ resource: "posts", action: "read" }],
    editor: [{ resource: "posts", action: "update" }],
  },
  roleHierarchy: { editor: ["viewer"] }, // editor also gets viewer's permissions
});
```
