---
title: "AccountManagement"
description: "API reference for the AccountManagement module."
---

## AccountManagement overview

Account management flows: verification-gated email change and self-service
account deletion.

Both flows issue a single-use, expiring token bound to the acting user (the
email-change token additionally carries the target email). The token is
delivered out-of-band via the configured `send*` callback; confirming the
token applies the change. This mirrors `EmailVerification`/`MagicLink`: a
store interface + `Context.Service` tag + `make*` factory + `*ServiceLayer`.

House conventions followed: epoch-ms timestamps, timing-safe token lookup by
value (tokens are high-entropy random), anti-enumeration at the HTTP layer
(see `HttpServer.ts`), and session invalidation on sensitive changes.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AccountManagementConfig (interface)](#accountmanagementconfig-interface)
  - [AccountManagementService](#accountmanagementservice)
  - [AccountManagementService (interface)](#accountmanagementservice-interface)
  - [AccountManagementServiceLayer](#accountmanagementservicelayer)
  - [AccountManagementServiceTag (class)](#accountmanagementservicetag-class)
  - [AccountManagementStore](#accountmanagementstore)
  - [AccountManagementStore (interface)](#accountmanagementstore-interface)
  - [AccountManagementStoreTag (class)](#accountmanagementstoretag-class)
  - [AccountToken (interface)](#accounttoken-interface)
  - [AccountTokenError (class)](#accounttokenerror-class)
  - [AccountTokenPurpose (type alias)](#accounttokenpurpose-type-alias)
  - [EmailChangeResult (interface)](#emailchangeresult-interface)
  - [EmailInUseError (class)](#emailinuseerror-class)
  - [makeAccountManagementService](#makeaccountmanagementservice)

---

# utils

## AccountManagementConfig (interface)

**Signature**

```ts
export interface AccountManagementConfig {
  /** Lifetime of a change-email token in ms. Default 1 hour. */
  readonly changeEmailExpiresIn?: number;
  /** Lifetime of a delete-account token in ms. Default 1 hour. */
  readonly deleteAccountExpiresIn?: number;
  /** Deliver the change-email confirmation token to the NEW address. */
  readonly sendChangeEmailVerification: (params: {
    readonly user: Types.User;
    readonly newEmail: string;
    readonly token: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /** Deliver the account-deletion confirmation token to the user's address. */
  readonly sendDeleteAccountVerification: (params: {
    readonly user: Types.User;
    readonly token: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /** Optional notice to the OLD address once an email change is confirmed. */
  readonly notifyEmailChanged?: (params: {
    readonly user: Types.User;
    readonly oldEmail: string;
    readonly newEmail: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Optional app-data cleanup run just before the user record is deleted (the
   * user still exists at this point so related rows can be resolved). A failure
   * here aborts the deletion.
   */
  readonly beforeDelete?: (user: Types.User) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Revoke all of the user's other sessions when their email changes. Default
   * `true` (an email change is a credential-adjacent event).
   */
  readonly revokeSessionsOnEmailChange?: boolean;
}
```

## AccountManagementService

**Signature**

```ts
export declare const AccountManagementService: typeof AccountManagementServiceTag;
```

## AccountManagementService (interface)

**Signature**

```ts
export interface AccountManagementService {
  /**
   * Begin an email change: validate the new address is free, then issue a
   * token delivered to the new address. Returns the token (for the caller to
   * decide delivery/anti-enumeration; the HTTP layer answers `{ status: true }`).
   */
  readonly requestEmailChange: (
    userId: string,
    newEmail: string,
  ) => Effect.Effect<
    { readonly token: string; readonly expiresAt: number },
    Errors.AuthError | Errors.UserNotFoundError | EmailInUseError,
    AccountManagementStoreTag | UserServiceStoreTag
  >;

  /** Confirm an email change by token: swaps the email and marks it verified. */
  readonly confirmEmailChange: (
    token: string,
  ) => Effect.Effect<
    EmailChangeResult,
    Errors.AuthError | Errors.UserNotFoundError | AccountTokenError,
    AccountManagementStoreTag | UserServiceStoreTag | SessionManagerTag
  >;

  /** Begin account deletion: issue a token delivered to the user's address. */
  readonly requestAccountDeletion: (
    userId: string,
  ) => Effect.Effect<
    { readonly token: string; readonly expiresAt: number },
    Errors.AuthError | Errors.UserNotFoundError,
    AccountManagementStoreTag | UserServiceStoreTag
  >;

  /** Confirm deletion by token: runs cleanup, revokes sessions, deletes user. */
  readonly confirmAccountDeletion: (
    token: string,
  ) => Effect.Effect<
    { readonly userId: string },
    Errors.AuthError | Errors.UserNotFoundError | AccountTokenError,
    AccountManagementStoreTag | UserServiceStoreTag | SessionManagerTag
  >;
}
```

## AccountManagementServiceLayer

**Signature**

```ts
export declare const AccountManagementServiceLayer: (
  config: AccountManagementConfig,
) => Layer.Layer<AccountManagementServiceTag, never, never>;
```

## AccountManagementServiceTag (class)

**Signature**

```ts
export declare class AccountManagementServiceTag
```

## AccountManagementStore

**Signature**

```ts
export declare const AccountManagementStore: typeof AccountManagementStoreTag;
```

## AccountManagementStore (interface)

Persistence for pending account-management tokens. Implement over your
database; keys are the opaque token strings.

**Signature**

```ts
export interface AccountManagementStore {
  readonly create: (token: AccountToken) => Effect.Effect<AccountToken, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<AccountToken | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## AccountManagementStoreTag (class)

**Signature**

```ts
export declare class AccountManagementStoreTag
```

## AccountToken (interface)

A pending, single-use account-management token. `newEmail` is only present
for `change-email` tokens.

**Signature**

```ts
export interface AccountToken {
  readonly token: string;
  readonly userId: string;
  readonly purpose: AccountTokenPurpose;
  readonly newEmail?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## AccountTokenError (class)

Raised when a confirm token is missing, expired, or of the wrong purpose.

**Signature**

```ts
export declare class AccountTokenError
```

## AccountTokenPurpose (type alias)

Which flow a pending token belongs to.

**Signature**

```ts
export type AccountTokenPurpose = "change-email" | "delete-account";
```

## EmailChangeResult (interface)

Result of confirming an email change.

**Signature**

```ts
export interface EmailChangeResult {
  readonly user: Types.User;
}
```

## EmailInUseError (class)

Raised by `requestEmailChange` when the target email is already in use.

**Signature**

```ts
export declare class EmailInUseError
```

## makeAccountManagementService

**Signature**

```ts
export declare const makeAccountManagementService: (
  config: AccountManagementConfig,
) => Effect.Effect<AccountManagementService, never>;
```
