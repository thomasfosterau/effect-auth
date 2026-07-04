---
title: "User"
description: "API reference for the User module."
---

## User overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [UpdateUserInput (interface)](#updateuserinput-interface)
  - [UserService (class)](#userservice-class)
  - [UserServiceShape (interface)](#userserviceshape-interface)
  - [UserServiceStore (class)](#userservicestore-class)
  - [UserServiceStoreShape (interface)](#userservicestoreshape-interface)
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

## UserService (class)

**Signature**

```ts
export declare class UserService
```

## UserServiceShape (interface)

**Signature**

```ts
export interface UserServiceShape {
  readonly getUser: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly getUserByEmail: (
    email: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly updateUserAttributes: (
    userId: string,
    attributes: Record<string, unknown>,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly updateUser: (
    userId: string,
    updates: UpdateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly markEmailVerified: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError, UserServiceStore>;
}
```

## UserServiceStore (class)

**Signature**

```ts
export declare class UserServiceStore
```

## UserServiceStoreShape (interface)

**Signature**

```ts
export interface UserServiceStoreShape {
  /** Get a user by ID, or `null` when no such user exists. */
  readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly getByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## makeUserService

**Signature**

```ts
export declare const makeUserService: () => Effect.Effect<UserServiceShape, never>;
```
