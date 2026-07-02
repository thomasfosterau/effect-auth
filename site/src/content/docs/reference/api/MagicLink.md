---
title: "MagicLink"
description: "API reference for the MagicLink module."
---

## MagicLink overview

Magic link sign-in for effect-auth.

Implements passwordless sign-in via single-use, expiring tokens delivered by
email (better-auth "magic link" parity). Requesting a link never reveals
whether an account exists; verifying a link proves ownership of the email,
so newly created users are marked `emailVerified: true`.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [MagicLinkConfig (interface)](#magiclinkconfig-interface)
  - [MagicLinkCreateUserInput (interface)](#magiclinkcreateuserinput-interface)
  - [MagicLinkResult (interface)](#magiclinkresult-interface)
  - [MagicLinkService](#magiclinkservice)
  - [MagicLinkService (interface)](#magiclinkservice-interface)
  - [MagicLinkServiceLayer](#magiclinkservicelayer)
  - [MagicLinkServiceTag (class)](#magiclinkservicetag-class)
  - [MagicLinkStore](#magiclinkstore)
  - [MagicLinkStore (interface)](#magiclinkstore-interface)
  - [MagicLinkStoreTag (class)](#magiclinkstoretag-class)
  - [MagicLinkToken (interface)](#magiclinktoken-interface)
  - [MagicLinkUserStore](#magiclinkuserstore)
  - [MagicLinkUserStore (interface)](#magiclinkuserstore-interface)
  - [MagicLinkUserStoreTag (class)](#magiclinkuserstoretag-class)
  - [MagicLinkVerifyOptions (interface)](#magiclinkverifyoptions-interface)
  - [generateMagicLinkToken](#generatemagiclinktoken)
  - [makeMagicLinkService](#makemagiclinkservice)

---

# utils

## MagicLinkConfig (interface)

Magic link service configuration

**Signature**

```ts
export interface MagicLinkConfig {
  readonly expiresIn?: number; // Default: 5 minutes
  readonly disableSignUp?: boolean; // Default: false
  readonly sendMagicLink: (
    email: string,
    token: string,
  ) => Effect.Effect<void, Errors.MagicLinkError>;
}
```

## MagicLinkCreateUserInput (interface)

Input for creating a user during magic link verification

**Signature**

```ts
export interface MagicLinkCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
}
```

## MagicLinkResult (interface)

Result of a successful magic link verification

**Signature**

```ts
export interface MagicLinkResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}
```

## MagicLinkService

**Signature**

```ts
export declare const MagicLinkService: typeof MagicLinkServiceTag;
```

## MagicLinkService (interface)

Magic link service

**Signature**

```ts
export interface MagicLinkService {
  /**
   * Request a magic link for the given email. Outstanding tokens for the
   * email are invalidated first so only the latest link is usable.
   *
   * Anti-enumeration: when sign-up is enabled the link is always sent (the
   * user is created at verification time); when sign-up is disabled and no
   * user exists this succeeds silently without sending anything.
   */
  readonly send: (
    email: string,
  ) => Effect.Effect<
    void,
    Errors.AuthError | Errors.MagicLinkError,
    MagicLinkStoreTag | MagicLinkUserStoreTag
  >;

  /**
   * Verify a magic link token (single use) and sign the user in. A
   * successfully verified link proves ownership of the email, so users
   * created here are marked `emailVerified: true`.
   */
  readonly verify: (
    token: string,
    options?: MagicLinkVerifyOptions,
  ) => Effect.Effect<
    MagicLinkResult,
    Errors.MagicLinkError | Errors.AuthError | HookError,
    MagicLinkStoreTag | MagicLinkUserStoreTag | SessionManagerTag | Hooks
  >;
}
```

## MagicLinkServiceLayer

**Signature**

```ts
export declare const MagicLinkServiceLayer: (
  config: MagicLinkConfig,
) => Layer.Layer<MagicLinkServiceTag, never, never>;
```

## MagicLinkServiceTag (class)

**Signature**

```ts
export declare class MagicLinkServiceTag
```

## MagicLinkStore

**Signature**

```ts
export declare const MagicLinkStore: typeof MagicLinkStoreTag;
```

## MagicLinkStore (interface)

Storage interface for magic link tokens

**Signature**

```ts
export interface MagicLinkStore {
  readonly create: (token: MagicLinkToken) => Effect.Effect<MagicLinkToken, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<MagicLinkToken | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  readonly deleteByEmail: (email: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## MagicLinkStoreTag (class)

Magic link store context tag

**Signature**

```ts
export declare class MagicLinkStoreTag
```

## MagicLinkToken (interface)

Magic link token record

**Signature**

```ts
export interface MagicLinkToken {
  readonly token: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
```

## MagicLinkUserStore

**Signature**

```ts
export declare const MagicLinkUserStore: typeof MagicLinkUserStoreTag;
```

## MagicLinkUserStore (interface)

User store interface for magic link sign-in

**Signature**

```ts
export interface MagicLinkUserStore {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: MagicLinkCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
}
```

## MagicLinkUserStoreTag (class)

Magic link user store context tag

**Signature**

```ts
export declare class MagicLinkUserStoreTag
```

## MagicLinkVerifyOptions (interface)

Options for verifying a magic link token

**Signature**

```ts
export interface MagicLinkVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}
```

## generateMagicLinkToken

Generate a cryptographically secure magic link token

**Signature**

```ts
export declare const generateMagicLinkToken: () => Effect.Effect<string, Errors.AuthError>;
```

## makeMagicLinkService

Create a magic link service

**Signature**

```ts
export declare const makeMagicLinkService: (
  config: MagicLinkConfig,
) => Effect.Effect<MagicLinkService, never>;
```
