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
  - [EmailVerificationService (class)](#emailverificationservice-class)
  - [EmailVerificationServiceShape (interface)](#emailverificationserviceshape-interface)
  - [EmailVerificationStore (class)](#emailverificationstore-class)
  - [EmailVerificationStoreShape (interface)](#emailverificationstoreshape-interface)
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

## EmailVerificationService (class)

**Signature**

```ts
export declare class EmailVerificationService
```

## EmailVerificationServiceShape (interface)

Email verification service

**Signature**

```ts
export interface EmailVerificationServiceShape {
  readonly createVerification: (
    userId: string,
    email: string,
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | EmailVerificationError | HookError,
    EmailVerificationStore | Hooks
  >;

  readonly verifyToken: (
    token: string,
  ) => Effect.Effect<
    EmailVerificationResult,
    EmailVerificationError | AuthError | HookError,
    EmailVerificationStore | Hooks
  >;

  /**
   * Invalidate any outstanding verification tokens for the user and send a
   * fresh one. Combine with the rate-limiter (e.g.
   * `RateLimitPresets.emailVerification`) to prevent abuse.
   */
  readonly resendVerification: (
    userId: string,
    email: string,
  ) => Effect.Effect<
    { token: string; expiresAt: number },
    AuthError | RateLimitError | EmailVerificationError | HookError,
    EmailVerificationStore | Hooks
  >;
}
```

## EmailVerificationStore (class)

Email verification store context tag

**Signature**

```ts
export declare class EmailVerificationStore
```

## EmailVerificationStoreShape (interface)

Storage interface for email verifications

**Signature**

```ts
export interface EmailVerificationStoreShape {
  readonly create: (verification: EmailVerification) => Effect.Effect<EmailVerification, AuthError>;
  readonly get: (token: string) => Effect.Effect<EmailVerification | null, AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>;
}
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
) => Effect.Effect<EmailVerificationServiceShape, never>;
```
