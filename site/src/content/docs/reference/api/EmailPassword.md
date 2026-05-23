---
title: "EmailPassword"
description: "API reference for the EmailPassword module."
---

## EmailPassword overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthResult (interface)](#authresult-interface)
  - [CreateUserInput (interface)](#createuserinput-interface)
  - [EmailPasswordConfig (interface)](#emailpasswordconfig-interface)
  - [EmailPasswordService](#emailpasswordservice)
  - [EmailPasswordService (interface)](#emailpasswordservice-interface)
  - [EmailPasswordServiceLayer](#emailpasswordservicelayer)
  - [EmailPasswordServiceTag (class)](#emailpasswordservicetag-class)
  - [EmailPasswordStore](#emailpasswordstore)
  - [EmailPasswordStore (interface)](#emailpasswordstore-interface)
  - [EmailPasswordStoreTag (class)](#emailpasswordstoretag-class)
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
}
```

## CreateUserInput (interface)

**Signature**

```ts
export interface CreateUserInput {
  readonly email: string;
  readonly name?: string;
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

## EmailPasswordService

**Signature**

```ts
export declare const EmailPasswordService: typeof EmailPasswordServiceTag;
```

## EmailPasswordService (interface)

**Signature**

```ts
export interface EmailPasswordService {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthResult,
    Errors.AuthError | Errors.HashingError | Errors.EmailNotVerifiedError,
    EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag
  >;

  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    AuthResult,
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | Errors.EmailNotVerifiedError,
    EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag
  >;
}
```

## EmailPasswordServiceLayer

**Signature**

```ts
export declare const EmailPasswordServiceLayer: (
  config?: EmailPasswordConfig,
) => Layer.Layer<EmailPasswordServiceTag, never, never>;
```

## EmailPasswordServiceTag (class)

**Signature**

```ts
export declare class EmailPasswordServiceTag
```

## EmailPasswordStore

**Signature**

```ts
export declare const EmailPasswordStore: typeof EmailPasswordStoreTag;
```

## EmailPasswordStore (interface)

**Signature**

```ts
export interface EmailPasswordStore {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly createUser: (input: CreateUserInput) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## EmailPasswordStoreTag (class)

**Signature**

```ts
export declare class EmailPasswordStoreTag
```

## SignInInput (interface)

**Signature**

```ts
export interface SignInInput {
  readonly email: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
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
}
```

## makeEmailPasswordService

**Signature**

```ts
export declare const makeEmailPasswordService: (
  config?: EmailPasswordConfig,
) => Effect.Effect<EmailPasswordService, never>;
```
