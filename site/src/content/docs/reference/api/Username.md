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
delegates credential creation to {@link EmailPasswordServiceTag}; sign-in
resolves the user by username and verifies the password with the same
anti-enumeration error and the same `SecondFactorGate` seam as email/password
sign-in.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [UsernameConfig (interface)](#usernameconfig-interface)
  - [UsernameError (class)](#usernameerror-class)
  - [UsernameService](#usernameservice)
  - [UsernameService (interface)](#usernameservice-interface)
  - [UsernameServiceLayer](#usernameservicelayer)
  - [UsernameServiceTag (class)](#usernameservicetag-class)
  - [UsernameSignInInput (interface)](#usernamesignininput-interface)
  - [UsernameSignUpInput (interface)](#usernamesignupinput-interface)
  - [UsernameStore](#usernamestore)
  - [UsernameStore (interface)](#usernamestore-interface)
  - [UsernameStoreTag (class)](#usernamestoretag-class)
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

## UsernameService

**Signature**

```ts
export declare const UsernameService: typeof UsernameServiceTag;
```

## UsernameService (interface)

**Signature**

```ts
export interface UsernameService {
  readonly signUp: (
    input: UsernameSignUpInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.AuthError
    | Errors.HashingError
    | Errors.EmailNotVerifiedError
    | HookError,
    | UsernameStoreTag
    | EmailPasswordServiceTag
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
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
    UsernameStoreTag | EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag | Hooks
  >;

  readonly updateUsername: (
    userId: string,
    username: string,
  ) => Effect.Effect<void, UsernameError | Errors.AuthError, UsernameStoreTag>;
}
```

## UsernameServiceLayer

**Signature**

```ts
export declare const UsernameServiceLayer: (
  config?: UsernameConfig,
) => Layer.Layer<UsernameServiceTag, never, never>;
```

## UsernameServiceTag (class)

**Signature**

```ts
export declare class UsernameServiceTag
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

## UsernameStore

**Signature**

```ts
export declare const UsernameStore: typeof UsernameStoreTag;
```

## UsernameStore (interface)

Username lookup / reservation. Keys are the normalized (trimmed, lowercased)
username; implementers persist it in `attributes.username`.

**Signature**

```ts
export interface UsernameStore {
  readonly getUserByUsername: (
    username: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly isUsernameTaken: (username: string) => Effect.Effect<boolean, Errors.AuthError>;
  readonly setUsername: (userId: string, username: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## UsernameStoreTag (class)

**Signature**

```ts
export declare class UsernameStoreTag
```

## makeUsernameService

**Signature**

```ts
export declare const makeUsernameService: (
  config?: UsernameConfig,
) => Effect.Effect<UsernameService, never>;
```
