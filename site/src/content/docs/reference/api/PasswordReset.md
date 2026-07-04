---
title: "PasswordReset"
description: "API reference for the PasswordReset module."
---

## PasswordReset overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [PasswordResetConfig (interface)](#passwordresetconfig-interface)
  - [PasswordResetResult (interface)](#passwordresetresult-interface)
  - [PasswordResetService (class)](#passwordresetservice-class)
  - [PasswordResetServiceShape (interface)](#passwordresetserviceshape-interface)
  - [PasswordResetStore (class)](#passwordresetstore-class)
  - [PasswordResetStoreShape (interface)](#passwordresetstoreshape-interface)
  - [PasswordResetToken (interface)](#passwordresettoken-interface)
  - [PasswordResetUserStore (class)](#passwordresetuserstore-class)
  - [PasswordResetUserStoreShape (interface)](#passwordresetuserstoreshape-interface)
  - [makePasswordResetService](#makepasswordresetservice)

---

# utils

## PasswordResetConfig (interface)

**Signature**

```ts
export interface PasswordResetConfig {
  readonly expiresIn?: number;
  readonly minPasswordLength?: number;
  readonly maxPasswordLength?: number;
  /**
   * Revoke all of the user's sessions when their password is reset. Default
   * `true` (a password reset is a credential-change event; attacker sessions
   * must not survive the victim's reset). Set to `false` to opt out.
   */
  readonly revokeSessionsOnPasswordReset?: boolean;
  readonly sendResetPassword: (
    email: string,
    token: string,
  ) => Effect.Effect<void, Errors.PasswordResetError>;
}
```

## PasswordResetResult (interface)

**Signature**

```ts
export interface PasswordResetResult {
  readonly userId: string;
  readonly email: string;
  readonly reset: true;
}
```

## PasswordResetService (class)

**Signature**

```ts
export declare class PasswordResetService
```

## PasswordResetServiceShape (interface)

**Signature**

```ts
export interface PasswordResetServiceShape {
  readonly requestPasswordReset: (
    email: string,
  ) => Effect.Effect<
    void,
    Errors.AuthError | Errors.PasswordResetError | HookError,
    PasswordResetStore | PasswordResetUserStore | Hooks
  >;

  readonly resetPassword: (
    token: string,
    newPassword: string,
  ) => Effect.Effect<
    PasswordResetResult,
    Errors.AuthError | Errors.PasswordResetError | Errors.HashingError | HookError,
    PasswordResetStore | PasswordResetUserStore | PasswordHasher | SessionManager | Hooks
  >;
}
```

## PasswordResetStore (class)

**Signature**

```ts
export declare class PasswordResetStore
```

## PasswordResetStoreShape (interface)

**Signature**

```ts
export interface PasswordResetStoreShape {
  readonly create: (
    reset: PasswordResetToken,
  ) => Effect.Effect<PasswordResetToken, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<PasswordResetToken | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## PasswordResetToken (interface)

**Signature**

```ts
export interface PasswordResetToken {
  readonly token: string;
  readonly userId: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## PasswordResetUserStore (class)

**Signature**

```ts
export declare class PasswordResetUserStore
```

## PasswordResetUserStoreShape (interface)

**Signature**

```ts
export interface PasswordResetUserStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## makePasswordResetService

**Signature**

```ts
export declare const makePasswordResetService: (
  config: PasswordResetConfig,
) => Effect.Effect<PasswordResetServiceShape, never>;
```
