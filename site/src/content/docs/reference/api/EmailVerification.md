---
title: "EmailVerification"
description: "API reference for the EmailVerification module."
---

## EmailVerification overview

Email verification types for effect-auth

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [EmailVerification (interface)](#emailverification-interface)
  - [EmailVerificationConfig (interface)](#emailverificationconfig-interface)
  - [EmailVerificationResult (interface)](#emailverificationresult-interface)
  - [EmailVerificationService](#emailverificationservice)
  - [EmailVerificationService (interface)](#emailverificationservice-interface)
  - [EmailVerificationServiceLayer](#emailverificationservicelayer)
  - [EmailVerificationServiceTag (class)](#emailverificationservicetag-class)
  - [EmailVerificationStore](#emailverificationstore)
  - [EmailVerificationStore (interface)](#emailverificationstore-interface)
  - [EmailVerificationStoreTag (class)](#emailverificationstoretag-class)
  - [generateVerificationToken](#generateverificationtoken)
  - [makeEmailVerificationService](#makeemailverificationservice)

---

# utils

## EmailVerification (interface)

Email verification token

**Signature**

```ts
export interface EmailVerification {
  readonly token: string;
  readonly userId: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## EmailVerificationConfig (interface)

Email verification service configuration

**Signature**

```ts
export interface EmailVerificationConfig {
  readonly expiresIn?: number; // Default: 24 hours
  readonly sendEmail: (to: string, token: string) => Effect.Effect<void, EmailVerificationError>;
}
```

## EmailVerificationResult (interface)

Email verification result

**Signature**

```ts
export interface EmailVerificationResult {
  readonly userId: string;
  readonly email: string;
  readonly verified: boolean;
}
```

## EmailVerificationService

**Signature**

```ts
export declare const EmailVerificationService: typeof EmailVerificationServiceTag;
```

## EmailVerificationService (interface)

Email verification service

**Signature**

```ts
export interface EmailVerificationService {
  readonly createVerification: (
    userId: string,
    email: string,
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | EmailVerificationError,
    EmailVerificationStoreTag
  >;

  readonly verifyToken: (
    token: string,
  ) => Effect.Effect<
    EmailVerificationResult,
    EmailVerificationError | AuthError,
    EmailVerificationStoreTag
  >;

  readonly resendVerification: (
    userId: string,
  ) => Effect.Effect<
    void,
    AuthError | RateLimitError | EmailVerificationError,
    EmailVerificationStoreTag
  >;
}
```

## EmailVerificationServiceLayer

**Signature**

```ts
export declare const EmailVerificationServiceLayer: (
  config: EmailVerificationConfig,
) => Layer.Layer<EmailVerificationServiceTag, never, never>;
```

## EmailVerificationServiceTag (class)

**Signature**

```ts
export declare class EmailVerificationServiceTag
```

## EmailVerificationStore

**Signature**

```ts
export declare const EmailVerificationStore: typeof EmailVerificationStoreTag;
```

## EmailVerificationStore (interface)

Storage interface for email verifications

**Signature**

```ts
export interface EmailVerificationStore {
  readonly create: (verification: EmailVerification) => Effect.Effect<EmailVerification, AuthError>;
  readonly get: (token: string) => Effect.Effect<EmailVerification | null, AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>;
}
```

## EmailVerificationStoreTag (class)

Email verification store context tag

**Signature**

```ts
export declare class EmailVerificationStoreTag
```

## generateVerificationToken

Generate a cryptographically secure verification token

**Signature**

```ts
export declare const generateVerificationToken: () => Effect.Effect<string, AuthError>;
```

## makeEmailVerificationService

Create an email verification service

**Signature**

```ts
export declare const makeEmailVerificationService: (
  config: EmailVerificationConfig,
) => Effect.Effect<EmailVerificationService, never>;
```
