---
title: "Authorization"
description: "API reference for the Authorization module."
---

## Authorization overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthorizationPolicy](#authorizationpolicy)
  - [AuthorizationPolicy (interface)](#authorizationpolicy-interface)
  - [AuthorizationPolicyLayer](#authorizationpolicylayer)
  - [AuthorizationPolicyTag (class)](#authorizationpolicytag-class)
  - [RoleStore](#rolestore)
  - [RoleStore (interface)](#rolestore-interface)
  - [RoleStoreTag (class)](#rolestoretag-class)
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

## AuthorizationPolicy

**Signature**

```ts
export declare const AuthorizationPolicy: typeof AuthorizationPolicyTag;
```

## AuthorizationPolicy (interface)

Authorization policy interface
Users should implement this to define their authorization rules

**Signature**

```ts
export interface AuthorizationPolicy {
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

## AuthorizationPolicyLayer

**Signature**

```ts
export declare const AuthorizationPolicyLayer: () => Layer.Layer<
  AuthorizationPolicyTag,
  never,
  RoleStoreTag
>;
```

## AuthorizationPolicyTag (class)

Tag for AuthorizationPolicy service

**Signature**

```ts
export declare class AuthorizationPolicyTag
```

## RoleStore

**Signature**

```ts
export declare const RoleStore: typeof RoleStoreTag;
```

## RoleStore (interface)

Simple role-based authorization policy
This is a basic implementation that users can extend or replace

**Signature**

```ts
export interface RoleStore {
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

## RoleStoreTag (class)

Tag for RoleStore service

**Signature**

```ts
export declare class RoleStoreTag
```

## allOf

Combine policies with logical AND: permission is granted only if _every_
policy grants it. Evaluation short-circuits on the first denial. With no
policies, grants (vacuously true).

**Signature**

```ts
export declare const allOf: (...policies: readonly AuthorizationPolicy[]) => AuthorizationPolicy;
```

## allowAll

A policy that grants every permission.

**Signature**

```ts
export declare const allowAll: AuthorizationPolicy;
```

## anyOf

Combine policies with logical OR: permission is granted if _any_ policy grants
it. Evaluation short-circuits on the first grant. With no policies, denies.

**Signature**

```ts
export declare const anyOf: (...policies: readonly AuthorizationPolicy[]) => AuthorizationPolicy;
```

## can

Check a permission against the {@link AuthorizationPolicy} in context,
returning a boolean instead of failing.

**Signature**

```ts
export declare const can: (
  userId: string,
  resource: string,
  action: string,
) => Effect.Effect<boolean, never, AuthorizationPolicyTag>;
```

## denyAll

A policy that denies every permission.

**Signature**

```ts
export declare const denyAll: AuthorizationPolicy;
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
) => AuthorizationPolicy;
```

## makeRoleBasedPolicy

Create a simple role-based authorization policy

**Signature**

```ts
export declare const makeRoleBasedPolicy: () => Effect.Effect<
  AuthorizationPolicy,
  never,
  RoleStoreTag
>;
```

## not

Negate a policy: grants what the wrapped policy denies and vice versa.

**Signature**

```ts
export declare const not: (policy: AuthorizationPolicy) => AuthorizationPolicy;
```

## requireAllPermissions

Require that the user has _all_ of the given permissions. Fails with
`PermissionDeniedError` for the first permission that is not granted.

**Signature**

```ts
export declare const requireAllPermissions: (
  userId: string,
  permissions: readonly PermissionRef[],
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicyTag>;
```

## requireAnyPermission

Require that the user has _at least one_ of the given permissions. Fails with
`PermissionDeniedError` only if none are granted.

**Signature**

```ts
export declare const requireAnyPermission: (
  userId: string,
  permissions: readonly PermissionRef[],
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicyTag>;
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
) => Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicyTag>;
```
