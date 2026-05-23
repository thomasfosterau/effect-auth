---
title: "Resolvers"
description: "API reference for the Resolvers module."
---

## Resolvers overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [makeCreateSessionResolver](#makecreatesessionresolver)
  - [makeDeleteUserResolver](#makedeleteuserresolver)
  - [makeGetUserByEmailResolver](#makegetuserbyemailresolver)
  - [makeGetUserResolver](#makegetuserresolver)
  - [makeHashPasswordResolver](#makehashpasswordresolver)
  - [makeInvalidateSessionResolver](#makeinvalidatesessionresolver)
  - [makeInvalidateUserSessionsResolver](#makeinvalidateusersessionsresolver)
  - [makeMarkEmailVerifiedResolver](#makemarkemailverifiedresolver)
  - [makeRequestPasswordResetResolver](#makerequestpasswordresetresolver)
  - [makeResetPasswordResolver](#makeresetpasswordresolver)
  - [makeUpdateUserAttributesResolver](#makeupdateuserattributesresolver)
  - [makeValidateSessionResolver](#makevalidatesessionresolver)
  - [makeVerifyCredentialsResolver](#makeverifycredentialsresolver)
  - [makeVerifyPasswordResolver](#makeverifypasswordresolver)
  - [signInEmailResolver](#signinemailresolver)
  - [signUpEmailResolver](#signupemailresolver)
  - [verifyEmailResolver](#verifyemailresolver)

---

# utils

## makeCreateSessionResolver

Create a resolver for session creation

**Signature**

```ts
export declare const makeCreateSessionResolver: RequestResolver.RequestResolver<
  Requests.CreateSessionRequest,
  SessionManagerTag
>;
```

## makeDeleteUserResolver

Resolver for DeleteUserRequest

**Signature**

```ts
export declare const makeDeleteUserResolver: RequestResolver.RequestResolver<
  Requests.DeleteUserRequest,
  UserServiceTag | UserServiceStoreTag
>;
```

## makeGetUserByEmailResolver

Resolver for GetUserByEmailRequest

**Signature**

```ts
export declare const makeGetUserByEmailResolver: RequestResolver.RequestResolver<
  Requests.GetUserByEmailRequest,
  UserServiceTag | UserServiceStoreTag
>;
```

## makeGetUserResolver

Resolver for GetUserRequest

**Signature**

```ts
export declare const makeGetUserResolver: RequestResolver.RequestResolver<
  Requests.GetUserRequest,
  UserServiceTag | UserServiceStoreTag
>;
```

## makeHashPasswordResolver

Create a resolver for password hashing

**Signature**

```ts
export declare const makeHashPasswordResolver: RequestResolver.RequestResolver<
  Requests.HashPasswordRequest,
  PasswordHasherTag
>;
```

## makeInvalidateSessionResolver

Create a resolver for session invalidation

**Signature**

```ts
export declare const makeInvalidateSessionResolver: RequestResolver.RequestResolver<
  Requests.InvalidateSessionRequest,
  SessionManagerTag
>;
```

## makeInvalidateUserSessionsResolver

Create a resolver for invalidating all user sessions

**Signature**

```ts
export declare const makeInvalidateUserSessionsResolver: RequestResolver.RequestResolver<
  Requests.InvalidateUserSessionsRequest,
  SessionManagerTag
>;
```

## makeMarkEmailVerifiedResolver

Resolver for MarkEmailVerifiedRequest

**Signature**

```ts
export declare const makeMarkEmailVerifiedResolver: RequestResolver.RequestResolver<
  Requests.MarkEmailVerifiedRequest,
  UserServiceTag | UserServiceStoreTag
>;
```

## makeRequestPasswordResetResolver

Resolver for RequestPasswordResetRequest

**Signature**

```ts
export declare const makeRequestPasswordResetResolver: RequestResolver.RequestResolver<
  Requests.RequestPasswordResetRequest,
  PasswordResetServiceTag | PasswordResetStoreTag | PasswordResetUserStoreTag
>;
```

## makeResetPasswordResolver

Resolver for ResetPasswordRequest

**Signature**

```ts
export declare const makeResetPasswordResolver: RequestResolver.RequestResolver<
  Requests.ResetPasswordRequest,
  | SessionManagerTag
  | PasswordHasherTag
  | PasswordResetServiceTag
  | PasswordResetStoreTag
  | PasswordResetUserStoreTag
>;
```

## makeUpdateUserAttributesResolver

Resolver for UpdateUserAttributesRequest

**Signature**

```ts
export declare const makeUpdateUserAttributesResolver: RequestResolver.RequestResolver<
  Requests.UpdateUserAttributesRequest,
  UserServiceTag | UserServiceStoreTag
>;
```

## makeValidateSessionResolver

Create a resolver for session validation

**Signature**

```ts
export declare const makeValidateSessionResolver: RequestResolver.RequestResolver<
  Requests.ValidateSessionRequest,
  SessionManagerTag
>;
```

## makeVerifyCredentialsResolver

Create a resolver for credential verification

**Signature**

```ts
export declare const makeVerifyCredentialsResolver: RequestResolver.RequestResolver<
  Requests.VerifyCredentialsRequest,
  UserStoreTag | PasswordHasherTag
>;
```

## makeVerifyPasswordResolver

Create a resolver for password verification

**Signature**

```ts
export declare const makeVerifyPasswordResolver: RequestResolver.RequestResolver<
  Requests.VerifyPasswordRequest,
  PasswordHasherTag
>;
```

## signInEmailResolver

Resolver for SignInEmailRequest

**Signature**

```ts
export declare const signInEmailResolver: RequestResolver.RequestResolver<
  Requests.SignInEmailRequest,
  | SessionManagerTag
  | PasswordHasherTag
  | AuthLifecycleServiceTag
  | EmailPasswordStoreTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```

## signUpEmailResolver

Resolver for SignUpEmailRequest

**Signature**

```ts
export declare const signUpEmailResolver: RequestResolver.RequestResolver<
  Requests.SignUpEmailRequest,
  | SessionManagerTag
  | PasswordHasherTag
  | AuthLifecycleServiceTag
  | EmailPasswordStoreTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```

## verifyEmailResolver

Resolver for VerifyEmailRequest

**Signature**

```ts
export declare const verifyEmailResolver: RequestResolver.RequestResolver<
  Requests.VerifyEmailRequest,
  | UserServiceTag
  | UserServiceStoreTag
  | SessionManagerTag
  | AuthLifecycleServiceTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
>;
```
