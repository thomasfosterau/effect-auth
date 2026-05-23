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
  - [PasswordResetService](#passwordresetservice)
  - [PasswordResetService (interface)](#passwordresetservice-interface)
  - [PasswordResetServiceLayer](#passwordresetservicelayer)
  - [PasswordResetServiceTag (class)](#passwordresetservicetag-class)
  - [PasswordResetStore](#passwordresetstore)
  - [PasswordResetStore (interface)](#passwordresetstore-interface)
  - [PasswordResetStoreTag (class)](#passwordresetstoretag-class)
  - [PasswordResetToken (interface)](#passwordresettoken-interface)
  - [PasswordResetUserStore](#passwordresetuserstore)
  - [PasswordResetUserStore (interface)](#passwordresetuserstore-interface)
  - [PasswordResetUserStoreTag (class)](#passwordresetuserstoretag-class)
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

## PasswordResetService

**Signature**

```ts
export declare const PasswordResetService: typeof PasswordResetServiceTag;
```

## PasswordResetService (interface)

**Signature**

```ts
export interface PasswordResetService {
  readonly requestPasswordReset: (
    email: string,
  ) => Effect.Effect<
    void,
    Errors.AuthError | Errors.PasswordResetError,
    PasswordResetStoreTag | PasswordResetUserStoreTag
  >;

  readonly resetPassword: (
    token: string,
    newPassword: string,
  ) => Effect.Effect<
    PasswordResetResult,
    Errors.AuthError | Errors.PasswordResetError | Errors.HashingError,
    PasswordResetStoreTag | PasswordResetUserStoreTag | PasswordHasherTag | SessionManagerTag
  >;
}
```

## PasswordResetServiceLayer

**Signature**

```ts
export declare const PasswordResetServiceLayer: (
  config: PasswordResetConfig,
) => Layer.Layer<PasswordResetServiceTag, never, never>;
```

## PasswordResetServiceTag (class)

**Signature**

```ts
export declare class PasswordResetServiceTag
```

## PasswordResetStore

**Signature**

```ts
export declare const PasswordResetStore: typeof PasswordResetStoreTag;
```

## PasswordResetStore (interface)

**Signature**

```ts
export interface PasswordResetStore {
  readonly create: (
    reset: PasswordResetToken,
  ) => Effect.Effect<PasswordResetToken, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<PasswordResetToken | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## PasswordResetStoreTag (class)

**Signature**

```ts
export declare class PasswordResetStoreTag
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

## PasswordResetUserStore

**Signature**

```ts
export declare const PasswordResetUserStore: typeof PasswordResetUserStoreTag;
```

## PasswordResetUserStore (interface)

**Signature**

```ts
export interface PasswordResetUserStore {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## PasswordResetUserStoreTag (class)

**Signature**

```ts
export declare class PasswordResetUserStoreTag
```

## makePasswordResetService

**Signature**

```ts
export declare const makePasswordResetService: (
  config: PasswordResetConfig,
) => Effect.Effect<PasswordResetService, never>;
```
