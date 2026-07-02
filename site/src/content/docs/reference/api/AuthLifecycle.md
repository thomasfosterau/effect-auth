---
title: "AuthLifecycle"
description: "API reference for the AuthLifecycle module."
---

## AuthLifecycle overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthLifecycleConfig (interface)](#authlifecycleconfig-interface)
  - [AuthLifecycleResult (interface)](#authlifecycleresult-interface)
  - [AuthLifecycleService](#authlifecycleservice)
  - [AuthLifecycleService (interface)](#authlifecycleservice-interface)
  - [AuthLifecycleServiceLayer](#authlifecycleservicelayer)
  - [AuthLifecycleServiceTag (class)](#authlifecycleservicetag-class)
  - [VerifyEmailInput (interface)](#verifyemailinput-interface)
  - [makeAuthLifecycleService](#makeauthlifecycleservice)

---

# utils

## AuthLifecycleConfig (interface)

**Signature**

```ts
export interface AuthLifecycleConfig {
  readonly requireEmailVerification?: boolean;
  readonly sendOnSignUp?: boolean;
  readonly sendOnSignIn?: boolean;
  readonly autoSignInAfterVerification?: boolean;
}
```

## AuthLifecycleResult (interface)

**Signature**

```ts
export interface AuthLifecycleResult {
  readonly user: Types.User;
  readonly session?: Types.Session;
  readonly needsEmailVerification: boolean;
  /** Present when a second factor is required to complete sign-in. */
  readonly secondFactor?: SecondFactorChallenge;
}
```

## AuthLifecycleService

**Signature**

```ts
export declare const AuthLifecycleService: typeof AuthLifecycleServiceTag;
```

## AuthLifecycleService (interface)

**Signature**

```ts
export interface AuthLifecycleService {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.HashingError
    | Errors.EmailVerificationError
    | Errors.EmailNotVerifiedError
    | HookError,
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
    | Hooks
  >;

  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.HashingError
    | Errors.InvalidCredentialsError
    | Errors.EmailVerificationError
    | HookError,
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
    | Hooks
  >;

  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError,
    | UserServiceTag
    | UserServiceStoreTag
    | SessionManagerTag
    | EmailVerificationServiceTag
    | EmailVerificationStoreTag
    | Hooks
  >;
}
```

## AuthLifecycleServiceLayer

**Signature**

```ts
export declare const AuthLifecycleServiceLayer: (
  config?: AuthLifecycleConfig,
) => Layer.Layer<AuthLifecycleServiceTag, never, never>;
```

## AuthLifecycleServiceTag (class)

**Signature**

```ts
export declare class AuthLifecycleServiceTag
```

## VerifyEmailInput (interface)

**Signature**

```ts
export interface VerifyEmailInput {
  readonly token: string;
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## makeAuthLifecycleService

**Signature**

```ts
export declare const makeAuthLifecycleService: (
  config?: AuthLifecycleConfig,
) => Effect.Effect<AuthLifecycleService, never>;
```
