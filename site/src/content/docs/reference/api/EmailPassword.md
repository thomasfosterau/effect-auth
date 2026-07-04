---
title: "EmailPassword"
description: "API reference for the EmailPassword module."
---

## EmailPassword overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthResult (interface)](#authresult-interface)
  - [ChangePasswordInput (interface)](#changepasswordinput-interface)
  - [CreateUserInput (interface)](#createuserinput-interface)
  - [EmailPasswordConfig (interface)](#emailpasswordconfig-interface)
  - [EmailPasswordService (class)](#emailpasswordservice-class)
  - [EmailPasswordServiceShape (interface)](#emailpasswordserviceshape-interface)
  - [EmailPasswordStore (class)](#emailpasswordstore-class)
  - [EmailPasswordStoreShape (interface)](#emailpasswordstoreshape-interface)
  - [SecondFactorChallenge (interface)](#secondfactorchallenge-interface)
  - [SecondFactorGate (class)](#secondfactorgate-class)
  - [SecondFactorGateShape (interface)](#secondfactorgateshape-interface)
  - [SignInInput (interface)](#signininput-interface)
  - [SignUpInput (interface)](#signupinput-interface)
  - [makeEmailPasswordService](#makeemailpasswordservice)

---

# utils

## AuthResult (interface)

**Signature**

```ts
export interface AuthResult {
  readonly user: Types.User;
  readonly session?: Types.Session;
  /** Present when a second factor is required to complete sign-in. */
  readonly secondFactor?: SecondFactorChallenge;
  /**
   * Sign-in method discriminator (`"email-password"`, `"username"`,
   * `"magic-link"`, ...) for hooks like the last-login-method plugin.
   */
  readonly method?: string;
}
```

## ChangePasswordInput (interface)

**Signature**

```ts
export interface ChangePasswordInput {
  readonly userId: string;
  readonly currentPassword: string;
  readonly newPassword: string;
  /** Revoke the user's other sessions after the change (keeps `currentSessionId`). */
  readonly revokeOtherSessions?: boolean;
  /** The session to keep when `revokeOtherSessions` is set; omit to revoke all. */
  readonly currentSessionId?: string;
}
```

## CreateUserInput (interface)

**Signature**

```ts
export interface CreateUserInput {
  readonly email: string;
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Record<string, unknown>;
}
```

## EmailPasswordConfig (interface)

**Signature**

```ts
export interface EmailPasswordConfig {
  readonly disableSignUp?: boolean;
  readonly requireEmailVerification?: boolean;
  readonly minPasswordLength?: number;
  readonly maxPasswordLength?: number;
  readonly autoSignIn?: boolean;
}
```

## EmailPasswordService (class)

**Signature**

```ts
export declare class EmailPasswordService
```

## EmailPasswordServiceShape (interface)

**Signature**

```ts
export interface EmailPasswordServiceShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthResult,
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailNotVerifiedError
    | HookError,
    EmailPasswordStore | PasswordHasher | SessionManager | Hooks
  >;

  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    AuthResult,
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | Errors.EmailNotVerifiedError
    | HookError,
    EmailPasswordStore | PasswordHasher | SessionManager | Hooks
  >;

  /**
   * Change the password of a user that already has one, verifying the current
   * password first. Optionally revokes the user's other sessions.
   */
  readonly changePassword: (
    input: ChangePasswordInput,
  ) => Effect.Effect<
    void,
    Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
    EmailPasswordStore | PasswordHasher | SessionManager
  >;

  /**
   * Set a password for a user that does not have one yet (e.g. an account
   * created via OAuth). Fails if a password is already set.
   */
  readonly setPassword: (
    userId: string,
    newPassword: string,
  ) => Effect.Effect<
    void,
    Errors.HashingError | Errors.AuthError,
    EmailPasswordStore | PasswordHasher
  >;
}
```

## EmailPasswordStore (class)

**Signature**

```ts
export declare class EmailPasswordStore
```

## EmailPasswordStoreShape (interface)

**Signature**

```ts
export interface EmailPasswordStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly createUser: (input: CreateUserInput) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## SecondFactorChallenge (interface)

A pending second-factor challenge issued during sign-in. The client must
redeem the token with the second factor (e.g. a TOTP code) to obtain a
session.

**Signature**

```ts
export interface SecondFactorChallenge {
  readonly token: string;
  readonly expiresAt: number;
}
```

## SecondFactorGate (class)

**Signature**

```ts
export declare class SecondFactorGate
```

## SecondFactorGateShape (interface)

Optional seam consulted by password sign-in after the first factor
succeeds. When present in context (see `TwoFactorGateLayer` in the
TwoFactor module) and `required` reports true, sign-in returns a
{@link SecondFactorChallenge} instead of a session.

**Signature**

```ts
export interface SecondFactorGateShape {
  readonly required: (user: Types.User) => Effect.Effect<boolean, Errors.AuthError>;
  readonly begin: (user: Types.User) => Effect.Effect<SecondFactorChallenge, Errors.AuthError>;
}
```

## SignInInput (interface)

**Signature**

```ts
export interface SignInInput {
  readonly email: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignIn` hook. */
  readonly captchaToken?: string;
}
```

## SignUpInput (interface)

**Signature**

```ts
export interface SignUpInput {
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignUp` hook. */
  readonly captchaToken?: string;
}
```

## makeEmailPasswordService

**Signature**

```ts
export declare const makeEmailPasswordService: (
  config?: EmailPasswordConfig,
) => Effect.Effect<EmailPasswordServiceShape, never>;
```
