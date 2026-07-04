---
title: "Username"
description: "API reference for the Username module."
---

## Username overview

Username authentication: sign in with a username + password instead of an
email.

Username is a first-class _lookup key_ but not a first-class `User` field —
implementers store it in `attributes.username` (normalized lowercase for
case-insensitive uniqueness). Sign-up validates + reserves the username then
delegates credential creation to {@link EmailPasswordService}; sign-in
resolves the user by username and verifies the password with the same
anti-enumeration error and the same `SecondFactorGate` seam as email/password
sign-in.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [UsernameConfig (interface)](#usernameconfig-interface)
  - [UsernameError (class)](#usernameerror-class)
  - [UsernameService (class)](#usernameservice-class)
  - [UsernameServiceShape (interface)](#usernameserviceshape-interface)
  - [UsernameSignInInput (interface)](#usernamesignininput-interface)
  - [UsernameSignUpInput (interface)](#usernamesignupinput-interface)
  - [UsernameStore (class)](#usernamestore-class)
  - [UsernameStoreShape (interface)](#usernamestoreshape-interface)
  - [makeUsernameService](#makeusernameservice)

---

# utils

## UsernameConfig (interface)

**Signature**

```ts
export interface UsernameConfig {
  /** Minimum username length. Default 3. */
  readonly minUsernameLength?: number;
  /** Maximum username length. Default 30. */
  readonly maxUsernameLength?: number;
  /**
   * Extra validation beyond the default charset (`[a-zA-Z0-9_.]`) and length.
   * Runs on the raw (pre-normalized) username.
   */
  readonly usernameValidator?: (username: string) => Effect.Effect<void, UsernameError>;
}
```

## UsernameError (class)

Raised for invalid or already-taken usernames.

**Signature**

```ts
export declare class UsernameError
```

## UsernameService (class)

**Signature**

```ts
export declare class UsernameService
```

## UsernameServiceShape (interface)

**Signature**

```ts
export interface UsernameServiceShape {
  readonly signUp: (
    input: UsernameSignUpInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailNotVerifiedError
    | HookError,
    | UsernameStore
    | EmailPasswordService
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | Hooks
  >;

  readonly signIn: (
    input: UsernameSignInInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | HookError,
    UsernameStore | EmailPasswordStore | PasswordHasher | SessionManager | Hooks
  >;

  readonly updateUsername: (
    userId: string,
    username: string,
  ) => Effect.Effect<void, UsernameError | Errors.AuthError, UsernameStore>;
}
```

## UsernameSignInInput (interface)

**Signature**

```ts
export interface UsernameSignInInput {
  readonly username: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## UsernameSignUpInput (interface)

**Signature**

```ts
export interface UsernameSignUpInput {
  readonly username: string;
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## UsernameStore (class)

**Signature**

```ts
export declare class UsernameStore
```

## UsernameStoreShape (interface)

Username lookup / reservation. Keys are the normalized (trimmed, lowercased)
username; implementers persist it in `attributes.username`.

**Signature**

```ts
export interface UsernameStoreShape {
  readonly getUserByUsername: (
    username: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly isUsernameTaken: (username: string) => Effect.Effect<boolean, Errors.AuthError>;
  readonly setUsername: (userId: string, username: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## makeUsernameService

**Signature**

```ts
export declare const makeUsernameService: (
  config?: UsernameConfig,
) => Effect.Effect<UsernameServiceShape, never>;
```
