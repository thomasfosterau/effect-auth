---
title: "Session"
description: "API reference for the Session module."
---

## Session overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [SessionManager](#sessionmanager)
  - [SessionManager (interface)](#sessionmanager-interface)
  - [SessionManagerLayer](#sessionmanagerlayer)
  - [SessionManagerTag (class)](#sessionmanagertag-class)
  - [SessionStore](#sessionstore)
  - [SessionStore (interface)](#sessionstore-interface)
  - [SessionStoreTag (class)](#sessionstoretag-class)
  - [UserStore](#userstore)
  - [UserStore (interface)](#userstore-interface)
  - [UserStoreTag (class)](#userstoretag-class)
  - [makeSessionManager](#makesessionmanager)

---

# utils

## SessionManager

**Signature**

```ts
export declare const SessionManager: typeof SessionManagerTag;
```

## SessionManager (interface)

Session manager service

**Signature**

```ts
export interface SessionManager {
  /**
   * Create a new session for a user
   */
  readonly createSession: (
    userId: string,
    attributes?: Record<string, unknown>,
  ) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Validate a session and return it with the user
   */
  readonly validateSession: (
    sessionId: string,
  ) => Effect.Effect<
    Types.SessionWithUser,
    Errors.SessionNotFoundError | Errors.SessionExpiredError | Errors.UserNotFoundError
  >;

  /**
   * Invalidate a session
   */
  readonly invalidateSession: (sessionId: string) => Effect.Effect<void, Errors.AuthError>;

  /**
   * Invalidate all sessions for a user
   */
  readonly invalidateUserSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}
```

## SessionManagerLayer

**Signature**

```ts
export declare const SessionManagerLayer: (
  config: Types.SessionConfig,
) => Layer.Layer<SessionManagerTag, never, SessionStoreTag | UserStoreTag>;
```

## SessionManagerTag (class)

Tag for SessionManager service

**Signature**

```ts
export declare class SessionManagerTag
```

## SessionStore

**Signature**

```ts
export declare const SessionStore: typeof SessionStoreTag;
```

## SessionStore (interface)

Session store interface for managing session persistence
Users should implement this interface with their preferred storage backend
(e.g., Redis, PostgreSQL, MongoDB, etc.)

**Signature**

```ts
export interface SessionStore {
  /**
   * Create a new session
   */
  readonly create: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

  /**
   * Get a session by ID
   */
  readonly get: (sessionId: string) => Effect.Effect<Types.Session, Errors.SessionNotFoundError>;

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
}
```

## SessionStoreTag (class)

Tag for SessionStore service

**Signature**

```ts
export declare class SessionStoreTag
```

## UserStore

**Signature**

```ts
export declare const UserStore: typeof UserStoreTag;
```

## UserStore (interface)

User store interface for managing user persistence
Users should implement this interface with their preferred storage backend

**Signature**

```ts
export interface UserStore {
  /**
   * Get a user by ID
   */
  readonly get: (userId: string) => Effect.Effect<Types.User, Errors.UserNotFoundError>;

  /**
   * Get user credentials (hashed password)
   */
  readonly getCredentials: (userId: string) => Effect.Effect<string, Errors.UserNotFoundError>;
}
```

## UserStoreTag (class)

Tag for UserStore service

**Signature**

```ts
export declare class UserStoreTag
```

## makeSessionManager

Create a SessionManager implementation

**Signature**

```ts
export declare const makeSessionManager: (
  config: Types.SessionConfig,
) => Effect.Effect<SessionManager, never, SessionStoreTag | UserStoreTag>;
```
