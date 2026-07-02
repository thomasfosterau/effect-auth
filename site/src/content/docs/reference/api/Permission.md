---
title: "Permission"
description: "API reference for the Permission module."
---

## Permission overview

Permission value helpers.

A {@link PermissionRef} is a `{ resource, action }` pair describing either a
granted permission or a requested one. The `"*"` wildcard is supported in the
`resource` and/or `action` of a _granted_ permission to match anything.

These helpers are pure (no Effect, no dependencies) so they can be used in
stores, policies, tests, or plain application code.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [PermissionRef (interface)](#permissionref-interface)
  - [formatPermission](#formatpermission)
  - [makePermission](#makepermission)
  - [parsePermission](#parsepermission)
  - [permissionMatches](#permissionmatches)

---

# utils

## PermissionRef (interface)

A permission reference: a resource paired with an action.

In a granted permission, `"*"` matches any resource or action. For example
`{ resource: "posts", action: "*" }` grants every action on `posts`, and
`{ resource: "*", action: "*" }` grants everything (superadmin).

**Signature**

```ts
export interface PermissionRef {
  readonly resource: string;
  readonly action: string;
}
```

## formatPermission

Format a {@link PermissionRef} as a `"resource:action"` string.

**Signature**

```ts
export declare const formatPermission: (permission: PermissionRef) => string;
```

## makePermission

Construct a {@link PermissionRef}.

**Signature**

```ts
export declare const makePermission: (resource: string, action: string) => PermissionRef;
```

## parsePermission

Parse a `"resource:action"` string into a {@link PermissionRef}.

The string is split on the first `:`. If there is no `:`, the whole string is
treated as the resource and the action defaults to `"*"`. Surrounding
whitespace is trimmed.

**Signature**

```ts
export declare const parsePermission: (input: string) => PermissionRef;
```

**Example**

```ts
import { parsePermission } from "effect-auth";

parsePermission("posts:read"); // { resource: "posts", action: "read" }
parsePermission("posts:*"); // { resource: "posts", action: "*" }
parsePermission("posts"); // { resource: "posts", action: "*" }
```

## permissionMatches

Check whether a `granted` permission satisfies a `requested` one.

A `"*"` wildcard in the granted resource or action matches anything. The
requested permission is matched literally — wildcards there are not expanded.

**Signature**

```ts
export declare const permissionMatches: (
  granted: PermissionRef,
  requested: PermissionRef,
) => boolean;
```

**Example**

```ts
import { permissionMatches } from "effect-auth";

permissionMatches({ resource: "posts", action: "*" }, { resource: "posts", action: "read" }); // true
permissionMatches({ resource: "*", action: "*" }, { resource: "users", action: "delete" }); // true
permissionMatches({ resource: "posts", action: "read" }, { resource: "posts", action: "delete" }); // false
```
