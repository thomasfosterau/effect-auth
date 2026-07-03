---
title: "Resolvers"
description: "API reference for the Resolvers module."
---

## Resolvers overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [~~makeCreateSessionResolver~~](#makecreatesessionresolver)
  - [~~makeDeleteUserResolver~~](#makedeleteuserresolver)
  - [~~makeGetUserByEmailResolver~~](#makegetuserbyemailresolver)
  - [~~makeGetUserResolver~~](#makegetuserresolver)
  - [~~makeHashPasswordResolver~~](#makehashpasswordresolver)
  - [~~makeInvalidateSessionResolver~~](#makeinvalidatesessionresolver)
  - [~~makeInvalidateUserSessionsResolver~~](#makeinvalidateusersessionsresolver)
  - [~~makeMarkEmailVerifiedResolver~~](#makemarkemailverifiedresolver)
  - [~~makeRequestPasswordResetResolver~~](#makerequestpasswordresetresolver)
  - [~~makeResetPasswordResolver~~](#makeresetpasswordresolver)
  - [~~makeUpdateUserAttributesResolver~~](#makeupdateuserattributesresolver)
  - [~~makeValidateSessionResolver~~](#makevalidatesessionresolver)
  - [~~makeVerifyCredentialsResolver~~](#makeverifycredentialsresolver)
  - [~~makeVerifyPasswordResolver~~](#makeverifypasswordresolver)
  - [~~signInEmailResolver~~](#signinemailresolver)
  - [~~signUpEmailResolver~~](#signupemailresolver)
  - [~~verifyEmailResolver~~](#verifyemailresolver)

---

# utils

## ~~makeCreateSessionResolver~~

Create a resolver for session creation

**Signature**

```ts
export declare const makeCreateSessionResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.CreateSessionRequest>,
  never,
  SessionManagerTag | Hooks
>;
```

## ~~makeDeleteUserResolver~~

Resolver for DeleteUserRequest

**Signature**

```ts
export declare const makeDeleteUserResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.DeleteUserRequest>,
  never,
  UserServiceTag | UserServiceStoreTag
>;
```

## ~~makeGetUserByEmailResolver~~

Resolver for GetUserByEmailRequest

**Signature**

```ts
export declare const makeGetUserByEmailResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.GetUserByEmailRequest>,
  never,
  UserServiceTag | UserServiceStoreTag
>;
```

## ~~makeGetUserResolver~~

Resolver for GetUserRequest

**Signature**

```ts
export declare const makeGetUserResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.GetUserRequest>,
  never,
  UserServiceTag | UserServiceStoreTag
>;
```

## ~~makeHashPasswordResolver~~

Create a resolver for password hashing

**Signature**

```ts
export declare const makeHashPasswordResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.HashPasswordRequest>,
  never,
  PasswordHasherTag
>;
```

## ~~makeInvalidateSessionResolver~~

Create a resolver for session invalidation

**Signature**

```ts
export declare const makeInvalidateSessionResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.InvalidateSessionRequest>,
  never,
  SessionManagerTag | Hooks
>;
```

## ~~makeInvalidateUserSessionsResolver~~

Create a resolver for invalidating all user sessions

**Signature**

```ts
export declare const makeInvalidateUserSessionsResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.InvalidateUserSessionsRequest>,
  never,
  SessionManagerTag
>;
```

## ~~makeMarkEmailVerifiedResolver~~

Resolver for MarkEmailVerifiedRequest

**Signature**

```ts
export declare const makeMarkEmailVerifiedResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.MarkEmailVerifiedRequest>,
  never,
  UserServiceTag | UserServiceStoreTag
>;
```

## ~~makeRequestPasswordResetResolver~~

Resolver for RequestPasswordResetRequest

**Signature**

```ts
export declare const makeRequestPasswordResetResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.RequestPasswordResetRequest>,
  never,
  Hooks | PasswordResetServiceTag | PasswordResetStoreTag | PasswordResetUserStoreTag
>;
```

## ~~makeResetPasswordResolver~~

Resolver for ResetPasswordRequest

**Signature**

```ts
export declare const makeResetPasswordResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.ResetPasswordRequest>,
  never,
  | SessionManagerTag
  | Hooks
  | PasswordHasherTag
  | PasswordResetServiceTag
  | PasswordResetStoreTag
  | PasswordResetUserStoreTag
>;
```

## ~~makeUpdateUserAttributesResolver~~

Resolver for UpdateUserAttributesRequest

**Signature**

```ts
export declare const makeUpdateUserAttributesResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.UpdateUserAttributesRequest>,
  never,
  UserServiceTag | UserServiceStoreTag
>;
```

## ~~makeValidateSessionResolver~~

Create a resolver for session validation

**Signature**

```ts
export declare const makeValidateSessionResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.ValidateSessionRequest>,
  never,
  SessionManagerTag | Hooks
>;
```

## ~~makeVerifyCredentialsResolver~~

Create a resolver for credential verification

**Signature**

```ts
export declare const makeVerifyCredentialsResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.VerifyCredentialsRequest>,
  never,
  UserStoreTag | PasswordHasherTag
>;
```

## ~~makeVerifyPasswordResolver~~

Create a resolver for password verification

**Signature**

```ts
export declare const makeVerifyPasswordResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.VerifyPasswordRequest>,
  never,
  PasswordHasherTag
>;
```

## ~~signInEmailResolver~~

Resolver for SignInEmailRequest

**Signature**

```ts
export declare const signInEmailResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.SignInEmailRequest>,
  never,
  | SessionManagerTag
  | Hooks
  | PasswordHasherTag
  | AuthLifecycleServiceTag
  | EmailPasswordStoreTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```

## ~~signUpEmailResolver~~

Resolver for SignUpEmailRequest

**Signature**

```ts
export declare const signUpEmailResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.SignUpEmailRequest>,
  never,
  | SessionManagerTag
  | Hooks
  | PasswordHasherTag
  | AuthLifecycleServiceTag
  | EmailPasswordStoreTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```

## ~~verifyEmailResolver~~

Resolver for VerifyEmailRequest

**Signature**

```ts
export declare const verifyEmailResolver: Effect.Effect<
  RequestResolver.RequestResolver<Requests.VerifyEmailRequest>,
  never,
  | UserServiceTag
  | UserServiceStoreTag
  | SessionManagerTag
  | Hooks
  | AuthLifecycleServiceTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```
