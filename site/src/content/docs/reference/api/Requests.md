---
title: "Requests"
description: "API reference for the Requests module."
---

## Requests overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [~~CheckPermissionRequest~~](#checkpermissionrequest)
  - [~~CheckPermissionRequest~~ (interface)](#checkpermissionrequest-interface)
  - [~~CreateSessionRequest~~](#createsessionrequest)
  - [~~CreateSessionRequest~~ (interface)](#createsessionrequest-interface)
  - [~~DeleteUserRequest~~](#deleteuserrequest)
  - [~~DeleteUserRequest~~ (interface)](#deleteuserrequest-interface)
  - [~~GetUserByEmailRequest~~](#getuserbyemailrequest)
  - [~~GetUserByEmailRequest~~ (interface)](#getuserbyemailrequest-interface)
  - [~~GetUserRequest~~](#getuserrequest)
  - [~~GetUserRequest~~ (interface)](#getuserrequest-interface)
  - [~~HashPasswordRequest~~](#hashpasswordrequest)
  - [~~HashPasswordRequest~~ (interface)](#hashpasswordrequest-interface)
  - [~~InvalidateSessionRequest~~](#invalidatesessionrequest)
  - [~~InvalidateSessionRequest~~ (interface)](#invalidatesessionrequest-interface)
  - [~~InvalidateUserSessionsRequest~~](#invalidateusersessionsrequest)
  - [~~InvalidateUserSessionsRequest~~ (interface)](#invalidateusersessionsrequest-interface)
  - [~~MarkEmailVerifiedRequest~~](#markemailverifiedrequest)
  - [~~MarkEmailVerifiedRequest~~ (interface)](#markemailverifiedrequest-interface)
  - [~~RequestPasswordResetRequest~~](#requestpasswordresetrequest)
  - [~~RequestPasswordResetRequest~~ (interface)](#requestpasswordresetrequest-interface)
  - [~~ResetPasswordRequest~~](#resetpasswordrequest)
  - [~~ResetPasswordRequest~~ (interface)](#resetpasswordrequest-interface)
  - [~~SignInEmailRequest~~](#signinemailrequest)
  - [~~SignInEmailRequest~~ (interface)](#signinemailrequest-interface)
  - [~~SignUpEmailRequest~~](#signupemailrequest)
  - [~~SignUpEmailRequest~~ (interface)](#signupemailrequest-interface)
  - [~~UpdateUserAttributesRequest~~](#updateuserattributesrequest)
  - [~~UpdateUserAttributesRequest~~ (interface)](#updateuserattributesrequest-interface)
  - [~~ValidateSessionRequest~~](#validatesessionrequest)
  - [~~ValidateSessionRequest~~ (interface)](#validatesessionrequest-interface)
  - [~~VerifyCredentialsRequest~~](#verifycredentialsrequest)
  - [~~VerifyCredentialsRequest~~ (interface)](#verifycredentialsrequest-interface)
  - [~~VerifyEmailRequest~~](#verifyemailrequest)
  - [~~VerifyEmailRequest~~ (interface)](#verifyemailrequest-interface)
  - [~~VerifyPasswordRequest~~](#verifypasswordrequest)
  - [~~VerifyPasswordRequest~~ (interface)](#verifypasswordrequest-interface)

---

# utils

## ~~CheckPermissionRequest~~

**Signature**

```ts
export declare const CheckPermissionRequest: Request.Constructor<CheckPermissionRequest, "_tag">;
```

## ~~CheckPermissionRequest~~ (interface)

Request to check if a user has permission for an action

**Signature**

```ts
export interface CheckPermissionRequest extends Request.Request<
  boolean,
  Errors.PermissionDeniedError
> {
  readonly _tag: "CheckPermissionRequest";
  readonly userId: string;
  readonly resource: string;
  readonly action: string;
}
```

## ~~CreateSessionRequest~~

**Signature**

```ts
export declare const CreateSessionRequest: Request.Constructor<CreateSessionRequest, "_tag">;
```

## ~~CreateSessionRequest~~ (interface)

Request to create a new session for a user

**Signature**

```ts
export interface CreateSessionRequest extends Request.Request<
  Types.Session,
  Errors.AuthError | HookError
> {
  readonly _tag: "CreateSessionRequest";
  readonly userId: string;
  readonly attributes?: Record<string, unknown>;
}
```

## ~~DeleteUserRequest~~

**Signature**

```ts
export declare const DeleteUserRequest: Request.Constructor<DeleteUserRequest, "_tag">;
```

## ~~DeleteUserRequest~~ (interface)

Request to delete a user

**Signature**

```ts
export interface DeleteUserRequest extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "DeleteUserRequest";
  readonly userId: string;
}
```

## ~~GetUserByEmailRequest~~

**Signature**

```ts
export declare const GetUserByEmailRequest: Request.Constructor<GetUserByEmailRequest, "_tag">;
```

## ~~GetUserByEmailRequest~~ (interface)

Request to fetch a user by email

**Signature**

```ts
export interface GetUserByEmailRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "GetUserByEmailRequest";
  readonly email: string;
}
```

## ~~GetUserRequest~~

**Signature**

```ts
export declare const GetUserRequest: Request.Constructor<GetUserRequest, "_tag">;
```

## ~~GetUserRequest~~ (interface)

Request to fetch a user by ID

**Signature**

```ts
export interface GetUserRequest extends Request.Request<Types.User, Errors.UserNotFoundError> {
  readonly _tag: "GetUserRequest";
  readonly userId: string;
}
```

## ~~HashPasswordRequest~~

**Signature**

```ts
export declare const HashPasswordRequest: Request.Constructor<HashPasswordRequest, "_tag">;
```

## ~~HashPasswordRequest~~ (interface)

Request to hash a password

**Signature**

```ts
export interface HashPasswordRequest extends Request.Request<
  Types.HashedPassword,
  Errors.HashingError
> {
  readonly _tag: "HashPasswordRequest";
  readonly password: string;
}
```

## ~~InvalidateSessionRequest~~

**Signature**

```ts
export declare const InvalidateSessionRequest: Request.Constructor<
  InvalidateSessionRequest,
  "_tag"
>;
```

## ~~InvalidateSessionRequest~~ (interface)

Request to invalidate/delete a session

**Signature**

```ts
export interface InvalidateSessionRequest extends Request.Request<
  void,
  Errors.AuthError | HookError
> {
  readonly _tag: "InvalidateSessionRequest";
  readonly sessionId: string;
}
```

## ~~InvalidateUserSessionsRequest~~

**Signature**

```ts
export declare const InvalidateUserSessionsRequest: Request.Constructor<
  InvalidateUserSessionsRequest,
  "_tag"
>;
```

## ~~InvalidateUserSessionsRequest~~ (interface)

Request to invalidate all sessions for a user

**Signature**

```ts
export interface InvalidateUserSessionsRequest extends Request.Request<void, Errors.AuthError> {
  readonly _tag: "InvalidateUserSessionsRequest";
  readonly userId: string;
}
```

## ~~MarkEmailVerifiedRequest~~

**Signature**

```ts
export declare const MarkEmailVerifiedRequest: Request.Constructor<
  MarkEmailVerifiedRequest,
  "_tag"
>;
```

## ~~MarkEmailVerifiedRequest~~ (interface)

Request to mark a user's email as verified

**Signature**

```ts
export interface MarkEmailVerifiedRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "MarkEmailVerifiedRequest";
  readonly userId: string;
}
```

## ~~RequestPasswordResetRequest~~

**Signature**

```ts
export declare const RequestPasswordResetRequest: Request.Constructor<
  RequestPasswordResetRequest,
  "_tag"
>;
```

## ~~RequestPasswordResetRequest~~ (interface)

Request to initiate password reset for an email

**Signature**

```ts
export interface RequestPasswordResetRequest extends Request.Request<
  void,
  Errors.AuthError | Errors.PasswordResetError | HookError
> {
  readonly _tag: "RequestPasswordResetRequest";
  readonly email: string;
}
```

## ~~ResetPasswordRequest~~

**Signature**

```ts
export declare const ResetPasswordRequest: Request.Constructor<ResetPasswordRequest, "_tag">;
```

## ~~ResetPasswordRequest~~ (interface)

Request to reset password with a token

**Signature**

```ts
export interface ResetPasswordRequest extends Request.Request<
  PasswordReset.PasswordResetResult,
  Errors.AuthError | Errors.PasswordResetError | Errors.HashingError | HookError
> {
  readonly _tag: "ResetPasswordRequest";
  readonly token: string;
  readonly newPassword: string;
}
```

## ~~SignInEmailRequest~~

**Signature**

```ts
export declare const SignInEmailRequest: Request.Constructor<SignInEmailRequest, "_tag">;
```

## ~~SignInEmailRequest~~ (interface)

Request to sign in with email and password through lifecycle service

**Signature**

```ts
export interface SignInEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  | Errors.AuthError
  | Errors.HashingError
  | Errors.InvalidCredentialsError
  | Errors.EmailVerificationError
  | HookError
> {
  readonly _tag: "SignInEmailRequest";
  readonly input: {
    readonly email: string;
    readonly password: string;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}
```

## ~~SignUpEmailRequest~~

**Signature**

```ts
export declare const SignUpEmailRequest: Request.Constructor<SignUpEmailRequest, "_tag">;
```

## ~~SignUpEmailRequest~~ (interface)

Request to sign up with email and password through lifecycle service

**Signature**

```ts
export interface SignUpEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  | Errors.AuthError
  | Errors.HashingError
  | Errors.EmailVerificationError
  | Errors.EmailNotVerifiedError
  | HookError
> {
  readonly _tag: "SignUpEmailRequest";
  readonly input: {
    readonly email: string;
    readonly password: string;
    readonly name?: string;
    readonly attributes?: Record<string, unknown>;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}
```

## ~~UpdateUserAttributesRequest~~

**Signature**

```ts
export declare const UpdateUserAttributesRequest: Request.Constructor<
  UpdateUserAttributesRequest,
  "_tag"
>;
```

## ~~UpdateUserAttributesRequest~~ (interface)

Request to merge attributes onto a user

**Signature**

```ts
export interface UpdateUserAttributesRequest extends Request.Request<
  Types.User,
  Errors.AuthError | Errors.UserNotFoundError
> {
  readonly _tag: "UpdateUserAttributesRequest";
  readonly userId: string;
  readonly attributes: Record<string, unknown>;
}
```

## ~~ValidateSessionRequest~~

**Signature**

```ts
export declare const ValidateSessionRequest: Request.Constructor<ValidateSessionRequest, "_tag">;
```

## ~~ValidateSessionRequest~~ (interface)

Request to validate and retrieve a session

**Signature**

```ts
export interface ValidateSessionRequest extends Request.Request<
  Types.SessionWithUser,
  Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError | HookError
> {
  readonly _tag: "ValidateSessionRequest";
  readonly sessionId: string;
}
```

## ~~VerifyCredentialsRequest~~

**Signature**

```ts
export declare const VerifyCredentialsRequest: Request.Constructor<
  VerifyCredentialsRequest,
  "_tag"
>;
```

## ~~VerifyCredentialsRequest~~ (interface)

Request to verify credentials and authenticate a user

**Signature**

```ts
export interface VerifyCredentialsRequest extends Request.Request<
  Types.User,
  Errors.InvalidCredentialsError | Errors.UserNotFoundError | Errors.HashingError
> {
  readonly _tag: "VerifyCredentialsRequest";
  readonly userId: string;
  readonly password: string;
}
```

## ~~VerifyEmailRequest~~

**Signature**

```ts
export declare const VerifyEmailRequest: Request.Constructor<VerifyEmailRequest, "_tag">;
```

## ~~VerifyEmailRequest~~ (interface)

Request to verify email token through lifecycle service

**Signature**

```ts
export interface VerifyEmailRequest extends Request.Request<
  AuthLifecycle.AuthLifecycleResult,
  Errors.AuthError | Errors.EmailVerificationError | Errors.UserNotFoundError | HookError
> {
  readonly _tag: "VerifyEmailRequest";
  readonly input: {
    readonly token: string;
    readonly sessionAttributes?: Record<string, unknown>;
  };
}
```

## ~~VerifyPasswordRequest~~

**Signature**

```ts
export declare const VerifyPasswordRequest: Request.Constructor<VerifyPasswordRequest, "_tag">;
```

## ~~VerifyPasswordRequest~~ (interface)

Request to verify a password against a hash

**Signature**

```ts
export interface VerifyPasswordRequest extends Request.Request<boolean, Errors.HashingError> {
  readonly _tag: "VerifyPasswordRequest";
  readonly password: string;
  readonly hash: string;
}
```
