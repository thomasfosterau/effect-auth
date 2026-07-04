---
title: "Authorization"
description: "API reference for the Authorization module."
---

## Authorization overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthorizationPolicy (class)](#authorizationpolicy-class)
  - [AuthorizationPolicyShape (interface)](#authorizationpolicyshape-interface)
  - [RoleStore (class)](#rolestore-class)
  - [RoleStoreShape (interface)](#rolestoreshape-interface)
  - [allOf](#allof)
  - [allowAll](#allowall)
  - [anyOf](#anyof)
  - [can](#can)
  - [denyAll](#denyall)
  - [fromPredicate](#frompredicate)
  - [makeRoleBasedPolicy](#makerolebasedpolicy)
  - [not](#not)
  - [requireAllPermissions](#requireallpermissions)
  - [requireAnyPermission](#requireanypermission)
  - [requirePermission](#requirepermission)

---

# utils

## AuthorizationPolicy (class)

Tag for AuthorizationPolicy service

**Signature**

```ts
export declare class AuthorizationPolicy
```

## AuthorizationPolicyShape (interface)

Authorization policy interface
Users should implement this to define their authorization rules

**Signature**

```ts
export interface AuthorizationPolicyShape {
  /**
   * Check if a user has permission to perform an action on a resource
   */
  readonly checkPermission: (
    userId: string,
    resource: string,
    action: string,
  ) => Effect.Effect<boolean, never>;
}
```

## RoleStore (class)

Tag for RoleStore service

**Signature**

```ts
export declare class RoleStore
```

## RoleStoreShape (interface)

Simple role-based authorization policy
This is a basic implementation that users can extend or replace

**Signature**

```ts
export interface RoleStoreShape {
  /**
   * Get roles for a user
   */
  readonly getUserRoles: (userId: string) => Effect.Effect<readonly string[], never>;

  /**
   * Get permissions for a role
   */
  readonly getRolePermissions: (
    role: string,
  ) => Effect.Effect<readonly { resource: string; action: string }[], never>;
}
```

## allOf

Combine policies with logical AND: permission is granted only if _every_
policy grants it. Evaluation short-circuits on the first denial. With no
policies, grants (vacuously true).

**Signature**

```ts
export declare const allOf: (
  ...policies: readonly AuthorizationPolicyShape[]
) => AuthorizationPolicyShape;
```

## allowAll

A policy that grants every permission.

**Signature**

```ts
export declare const allowAll: AuthorizationPolicyShape;
```

## anyOf

Combine policies with logical OR: permission is granted if _any_ policy grants
it. Evaluation short-circuits on the first grant. With no policies, denies.

**Signature**

```ts
export declare const anyOf: (
  ...policies: readonly AuthorizationPolicyShape[]
) => AuthorizationPolicyShape;
```

## can

Check a permission against the {@link AuthorizationPolicyShape} in context,
returning a boolean instead of failing.

**Signature**

```ts
export declare const can: (
  userId: string,
  resource: string,
  action: string,
) => Effect.Effect<boolean, never, AuthorizationPolicy>;
```

## denyAll

A policy that denies every permission.

**Signature**

```ts
export declare const denyAll: AuthorizationPolicyShape;
```

## fromPredicate

Build a policy from an arbitrary predicate.

This is the building block for attribute-based (ABAC) rules: the predicate can
close over any data needed to make a decision. Note the predicate operates on
`(userId, resource, action)` with no extra context — per-instance/ownership
checks that need to load a specific record are best done at the call site and
composed here with {@link allOf} / {@link anyOf}.

**Signature**

```ts
export declare const fromPredicate: (
  check: (userId: string, resource: string, action: string) => Effect.Effect<boolean, never>,
) => AuthorizationPolicyShape;
```

## makeRoleBasedPolicy

Create a simple role-based authorization policy

**Signature**

```ts
export declare const makeRoleBasedPolicy: () => Effect.Effect<
  AuthorizationPolicyShape,
  never,
  RoleStore
>;
```

## not

Negate a policy: grants what the wrapped policy denies and vice versa.

**Signature**

```ts
export declare const not: (policy: AuthorizationPolicyShape) => AuthorizationPolicyShape;
```

## requireAllPermissions

Require that the user has _all_ of the given permissions. Fails with
`PermissionDeniedError` for the first permission that is not granted.

**Signature**

```ts
export declare const requireAllPermissions: (
  userId: string,
  permissions: readonly PermissionRef[],
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy>;
```

## requireAnyPermission

Require that the user has _at least one_ of the given permissions. Fails with
`PermissionDeniedError` only if none are granted.

**Signature**

```ts
export declare const requireAnyPermission: (
  userId: string,
  permissions: readonly PermissionRef[],
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy>;
```

## requirePermission

Utility function to require permission
Throws PermissionDeniedError if permission is not granted

**Signature**

```ts
export declare const requirePermission: (
  userId: string,
  resource: string,
  action: string,
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy>;
```
