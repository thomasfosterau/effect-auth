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
for a real account, call {@link AnonymousServiceShape.linkAccount} with the
anonymous user and the freshly-created user; the `linkAccount` config
callback migrates any data, then the anonymous user is deleted.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AnonymousConfig (interface)](#anonymousconfig-interface)
  - [AnonymousResult (interface)](#anonymousresult-interface)
  - [AnonymousService (class)](#anonymousservice-class)
  - [AnonymousServiceShape (interface)](#anonymousserviceshape-interface)
  - [AnonymousUserStore (class)](#anonymoususerstore-class)
  - [AnonymousUserStoreShape (interface)](#anonymoususerstoreshape-interface)
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
   * {@link AnonymousServiceShape.linkAccount}. Runs before the anonymous user is
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

## AnonymousService (class)

**Signature**

```ts
export declare class AnonymousService
```

## AnonymousServiceShape (interface)

**Signature**

```ts
export interface AnonymousServiceShape {
  /** Create an anonymous user and an authenticated session for them. */
  readonly signInAnonymous: (
    sessionAttributes?: Record<string, unknown>,
  ) => Effect.Effect<
    AnonymousResult,
    Errors.AuthError | HookError,
    AnonymousUserStore | SessionManager | Hooks
  >;

  /**
   * Link an anonymous identity to a real account: run the `linkAccount`
   * callback (app data migration), then delete the anonymous user.
   */
  readonly linkAccount: (
    anonymousUser: Types.User,
    newUser: Types.User,
  ) => Effect.Effect<void, Errors.AuthError, AnonymousUserStore>;
}
```

## AnonymousUserStore (class)

**Signature**

```ts
export declare class AnonymousUserStore
```

## AnonymousUserStoreShape (interface)

Persistence for anonymous users. The implementer generates an id and a
placeholder email, and sets `attributes.isAnonymous: true`.

**Signature**

```ts
export interface AnonymousUserStoreShape {
  readonly createAnonymousUser: () => Effect.Effect<Types.User, Errors.AuthError>;
  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
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
) => Effect.Effect<AnonymousServiceShape, never>;
```
