---
title: "Errors"
description: "API reference for the Errors module."
---

## Errors overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthError (class)](#autherror-class)
  - [ChallengeExpiredError (class)](#challengeexpirederror-class)
  - [ChallengeNotFoundError (class)](#challengenotfounderror-class)
  - [CredentialNotFoundError (class)](#credentialnotfounderror-class)
  - [EmailInUseError (class)](#emailinuseerror-class)
  - [EmailNotVerifiedError (class)](#emailnotverifiederror-class)
  - [EmailVerificationError (class)](#emailverificationerror-class)
  - [HashingError (class)](#hashingerror-class)
  - [InsufficientScopeError (class)](#insufficientscopeerror-class)
  - [InvalidCredentialsError (class)](#invalidcredentialserror-class)
  - [MagicLinkError (class)](#magiclinkerror-class)
  - [OAuthProviderError (class)](#oauthprovidererror-class)
  - [OAuthStateExpiredError (class)](#oauthstateexpirederror-class)
  - [OAuthStateNotFoundError (class)](#oauthstatenotfounderror-class)
  - [PasswordResetError (class)](#passwordreseterror-class)
  - [PermissionDeniedError (class)](#permissiondeniederror-class)
  - [RateLimitError (class)](#ratelimiterror-class)
  - [SessionExpiredError (class)](#sessionexpirederror-class)
  - [SessionNotFoundError (class)](#sessionnotfounderror-class)
  - [UserNotFoundError (class)](#usernotfounderror-class)
  - [WebAuthnVerificationError (class)](#webauthnverificationerror-class)

---

# utils

## AuthError (class)

Base authentication error

**Signature**

```ts
export declare class AuthError
```

## ChallengeExpiredError (class)

WebAuthn challenge expired error

**Signature**

```ts
export declare class ChallengeExpiredError
```

## ChallengeNotFoundError (class)

WebAuthn challenge not found error

**Signature**

```ts
export declare class ChallengeNotFoundError
```

## CredentialNotFoundError (class)

WebAuthn credential not found error

**Signature**

```ts
export declare class CredentialNotFoundError
```

## EmailInUseError (class)

Raised when an email address is already associated with another account
(sign-up with an existing email, or a change-email request targeting a
taken address).

**Signature**

```ts
export declare class EmailInUseError
```

## EmailNotVerifiedError (class)

Email not verified error

**Signature**

```ts
export declare class EmailNotVerifiedError
```

## EmailVerificationError (class)

Email verification error

**Signature**

```ts
export declare class EmailVerificationError
```

## HashingError (class)

Hashing error

**Signature**

```ts
export declare class HashingError
```

## InsufficientScopeError (class)

Insufficient scope error (OAuth-style scope authorization)

**Signature**

```ts
export declare class InsufficientScopeError
```

## InvalidCredentialsError (class)

Invalid credentials error

**Signature**

```ts
export declare class InvalidCredentialsError
```

## MagicLinkError (class)

Magic link error

**Signature**

```ts
export declare class MagicLinkError
```

## OAuthProviderError (class)

OAuth provider error

**Signature**

```ts
export declare class OAuthProviderError
```

## OAuthStateExpiredError (class)

OAuth state expired error

**Signature**

```ts
export declare class OAuthStateExpiredError
```

## OAuthStateNotFoundError (class)

OAuth state not found error

**Signature**

```ts
export declare class OAuthStateNotFoundError
```

## PasswordResetError (class)

Password reset error

**Signature**

```ts
export declare class PasswordResetError
```

## PermissionDeniedError (class)

Permission denied error

**Signature**

```ts
export declare class PermissionDeniedError
```

## RateLimitError (class)

Rate limit exceeded error

**Signature**

```ts
export declare class RateLimitError
```

## SessionExpiredError (class)

Session expired error

**Signature**

```ts
export declare class SessionExpiredError
```

## SessionNotFoundError (class)

Session not found error

**Signature**

```ts
export declare class SessionNotFoundError
```

## UserNotFoundError (class)

User not found error

**Signature**

```ts
export declare class UserNotFoundError
```

## WebAuthnVerificationError (class)

WebAuthn verification error

**Signature**

```ts
export declare class WebAuthnVerificationError
```
