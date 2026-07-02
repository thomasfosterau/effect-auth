---
title: "User"
description: "API reference for the User module."
---

## User overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [UpdateUserInput (interface)](#updateuserinput-interface)
  - [UserService](#userservice)
  - [UserService (interface)](#userservice-interface)
  - [UserServiceLayer](#userservicelayer)
  - [UserServiceStore](#userservicestore)
  - [UserServiceStore (interface)](#userservicestore-interface)
  - [UserServiceStoreTag (class)](#userservicestoretag-class)
  - [UserServiceTag (class)](#userservicetag-class)
  - [makeUserService](#makeuserservice)

---

# utils

## UpdateUserInput (interface)

Partial update of a user's first-class profile fields.

**Signature**

```ts
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}
```

## UserService

**Signature**

```ts
export declare const UserService: typeof UserServiceTag;
```

## UserService (interface)

**Signature**

```ts
export interface UserService {
  readonly getUser: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly getUserByEmail: (
    email: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly updateUserAttributes: (
    userId: string,
    attributes: Record<string, unknown>,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly updateUser: (
    userId: string,
    updates: UpdateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly markEmailVerified: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly deleteUser: (
    userId: string,
  ) => Effect.Effect<void, Errors.AuthError, UserServiceStoreTag>;
}
```

## UserServiceLayer

**Signature**

```ts
export declare const UserServiceLayer: () => Layer.Layer<UserServiceTag, never, never>;
```

## UserServiceStore

**Signature**

```ts
export declare const UserServiceStore: typeof UserServiceStoreTag;
```

## UserServiceStore (interface)

**Signature**

```ts
export interface UserServiceStore {
  readonly get: (userId: string) => Effect.Effect<Types.User, Errors.UserNotFoundError>;

  readonly getByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## UserServiceStoreTag (class)

**Signature**

```ts
export declare class UserServiceStoreTag
```

## UserServiceTag (class)

**Signature**

```ts
export declare class UserServiceTag
```

## makeUserService

**Signature**

```ts
export declare const makeUserService: () => Effect.Effect<UserService, never>;
```
