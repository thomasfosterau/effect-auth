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
  - [AuthLifecycleService (class)](#authlifecycleservice-class)
  - [AuthLifecycleServiceShape (interface)](#authlifecycleserviceshape-interface)
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

## AuthLifecycleService (class)

**Signature**

```ts
export declare class AuthLifecycleService
```

## AuthLifecycleServiceShape (interface)

**Signature**

```ts
export interface AuthLifecycleServiceShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailVerificationError
    | Errors.EmailNotVerifiedError
    | HookError,
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
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
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
    | Hooks
  >;

  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    AuthLifecycleResult,
    Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError,
    | UserService
    | UserServiceStore
    | SessionManager
    | EmailVerificationService
    | EmailVerificationStore
    | Hooks
  >;
}
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
) => Effect.Effect<AuthLifecycleServiceShape, never>;
```
