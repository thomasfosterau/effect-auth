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
  - [makeRoleBasedPolicy](#makerolebasedpolicy)
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
