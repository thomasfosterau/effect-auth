---
title: "Anonymous"
description: "API reference for the Anonymous module."
---

## Anonymous overview

Anonymous (guest) authentication.

Lets a visitor obtain a real user + session without credentials, then link
that identity to a full account on sign-up. Follows the house module pattern
(store tag + `Context.Service` tag + `make*` + `*ServiceLayer`), closely
mirroring `MagicLink.ts`.

Convention: anonymous users carry `attributes.isAnonymous === true` and a
placeholder email (e.g. `anon-<id>@anonymous.local`) chosen by the store
implementer. Use {@link isAnonymousUser} to detect them.

Account linking is triggered explicitly by the app/HTTP layer (hooks operate
on input values and cannot see the current session): after a guest signs up
for a real account, call {@link AnonymousService.linkAccount} with the
anonymous user and the freshly-created user; the `linkAccount` config
callback migrates any data, then the anonymous user is deleted.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AnonymousConfig (interface)](#anonymousconfig-interface)
  - [AnonymousResult (interface)](#anonymousresult-interface)
  - [AnonymousService](#anonymousservice)
  - [AnonymousService (interface)](#anonymousservice-interface)
  - [AnonymousServiceLayer](#anonymousservicelayer)
  - [AnonymousServiceTag (class)](#anonymousservicetag-class)
  - [AnonymousUserStore](#anonymoususerstore)
  - [AnonymousUserStore (interface)](#anonymoususerstore-interface)
  - [AnonymousUserStoreTag (class)](#anonymoususerstoretag-class)
  - [isAnonymousUser](#isanonymoususer)
  - [makeAnonymousService](#makeanonymousservice)

---

# utils

## AnonymousConfig (interface)

**Signature**

```ts
export interface AnonymousConfig {
  /**
   * Migrate data from the anonymous user to the newly-created real user during
   * {@link AnonymousService.linkAccount}. Runs before the anonymous user is
   * deleted, so related rows can still be resolved.
   */
  readonly linkAccount?: (params: {
    readonly anonymousUser: Types.User;
    readonly newUser: Types.User;
  }) => Effect.Effect<void, Errors.AuthError>;
}
```

## AnonymousResult (interface)

**Signature**

```ts
export interface AnonymousResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}
```

## AnonymousService

**Signature**

```ts
export declare const AnonymousService: typeof AnonymousServiceTag;
```

## AnonymousService (interface)

**Signature**

```ts
export interface AnonymousService {
  /** Create an anonymous user and an authenticated session for them. */
  readonly signInAnonymous: (
    sessionAttributes?: Record<string, unknown>,
  ) => Effect.Effect<
    AnonymousResult,
    Errors.AuthError | HookError,
    AnonymousUserStoreTag | SessionManagerTag | Hooks
  >;

  /**
   * Link an anonymous identity to a real account: run the `linkAccount`
   * callback (app data migration), then delete the anonymous user.
   */
  readonly linkAccount: (
    anonymousUser: Types.User,
    newUser: Types.User,
  ) => Effect.Effect<void, Errors.AuthError, AnonymousUserStoreTag>;
}
```

## AnonymousServiceLayer

**Signature**

```ts
export declare const AnonymousServiceLayer: (
  config?: AnonymousConfig,
) => Layer.Layer<AnonymousServiceTag, never, never>;
```

## AnonymousServiceTag (class)

**Signature**

```ts
export declare class AnonymousServiceTag
```

## AnonymousUserStore

**Signature**

```ts
export declare const AnonymousUserStore: typeof AnonymousUserStoreTag;
```

## AnonymousUserStore (interface)

Persistence for anonymous users. The implementer generates an id and a
placeholder email, and sets `attributes.isAnonymous: true`.

**Signature**

```ts
export interface AnonymousUserStore {
  readonly createAnonymousUser: () => Effect.Effect<Types.User, Errors.AuthError>;
  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## AnonymousUserStoreTag (class)

**Signature**

```ts
export declare class AnonymousUserStoreTag
```

## isAnonymousUser

Whether a user is an anonymous (guest) user.

**Signature**

```ts
export declare const isAnonymousUser: (user: Types.User) => boolean;
```

## makeAnonymousService

**Signature**

```ts
export declare const makeAnonymousService: (
  config?: AnonymousConfig,
) => Effect.Effect<AnonymousService, never>;
```
