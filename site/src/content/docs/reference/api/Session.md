---
title: "Session"
description: "API reference for the Session module."
---

## Session overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [SessionManager (class)](#sessionmanager-class)
  - [SessionManagerShape (interface)](#sessionmanagershape-interface)
  - [SessionStore (class)](#sessionstore-class)
  - [SessionStoreShape (interface)](#sessionstoreshape-interface)
  - [UserStore (class)](#userstore-class)
  - [UserStoreShape (interface)](#userstoreshape-interface)
  - [makeSessionManager](#makesessionmanager)

---

# utils

## SessionManager (class)

Tag for SessionManager service

**Signature**

```ts
export declare class SessionManager
```

## SessionManagerShape (interface)

Session manager service

**Signature**

```ts
export interface SessionManagerShape {
  /**
   * Create a new session for a user
   */
  readonly createSession: (
    userId: string,
    attributes?: Record<string, unknown>,
  ) => Effect.Effect<Types.Session, Errors.AuthError | HookError, Hooks>;

  /**
   * Validate a session and return it with the user
   */
  readonly validateSession: (
    sessionId: string,
  ) => Effect.Effect<
    Types.SessionWithUser,
    Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError | HookError,
    Hooks
  >;

  /**
   * Invalidate a session
   */
  readonly invalidateSession: (
    sessionId: string,
  ) => Effect.Effect<void, Errors.AuthError | HookError, Hooks>;

  /**
   * Invalidate all sessions for a user
   */
  readonly invalidateUserSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>;

  /**
   * List a user's sessions that have not yet expired.
   */
  readonly listSessions: (
    userId: string,
  ) => Effect.Effect<ReadonlyArray<Types.Session>, Errors.AuthError>;

  /**
   * Invalidate every session for a user except the given one (e.g. keep the
   * current device signed in while revoking all others).
   */
  readonly revokeOtherSessions: (
    userId: string,
    currentSessionId: string,
  ) => Effect.Effect<void, Errors.AuthError>;

  /**
   * Merge `attributes` into a session's stored attributes (e.g. record the
   * `activeOrganizationId`). Existing keys are overwritten; others are kept.
   * Returns the updated session.
   */
  readonly setSessionAttributes: (
    sessionId: string,
    attributes: Record<string, unknown>,
  ) => Effect.Effect<Types.Session, Errors.SessionNotFoundError | Errors.AuthError>;
}
```

## SessionStore (class)

Tag for SessionStore service

**Signature**

```ts
export declare class SessionStore
```

## SessionStoreShape (interface)

Session store interface for managing session persistence
Users should implement this interface with their preferred storage backend
(e.g., Redis, PostgreSQL, MongoDB, etc.)

**Signature**

```ts
export interface SessionStoreShape {
  /**
   * Create a new session
   */
  readonly create: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Get a session by ID, or `null` when no such session exists.
   */
  readonly get: (sessionId: string) => Effect.Effect<Types.Session | null, Errors.AuthError>;

  /**
   * Update a session
   */
  readonly update: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Delete a session
   */
  readonly delete: (sessionId: string) => Effect.Effect<void, Errors.AuthError>;

  /**
   * Delete all sessions for a user
   */
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;

  /**
   * List all sessions for a user
   */
  readonly listByUserId: (
    userId: string,
  ) => Effect.Effect<ReadonlyArray<Types.Session>, Errors.AuthError>;
}
```

## UserStore (class)

Tag for UserStore service

**Signature**

```ts
export declare class UserStore
```

## UserStoreShape (interface)

User store interface for managing user persistence
Users should implement this interface with their preferred storage backend

**Signature**

```ts
export interface UserStoreShape {
  /**
   * Get a user by ID, or `null` when no such user exists.
   */
  readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  /**
   * Get user credentials (hashed password), or `null` when the user does not
   * exist or has no password set.
   */
  readonly getCredentials: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;
}
```

## makeSessionManager

Create a SessionManager implementation

**Signature**

```ts
export declare const makeSessionManager: (
  config: Types.SessionConfig,
) => Effect.Effect<SessionManagerShape, never, SessionStore | UserStore>;
```
