---
title: "Types"
description: "API reference for the Types module."
---

## Types overview

Core types for the Effect Auth library

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [Credentials (interface)](#credentials-interface)
  - [HashedPassword (interface)](#hashedpassword-interface)
  - [Permission (interface)](#permission-interface)
  - [Session (interface)](#session-interface)
  - [SessionConfig (interface)](#sessionconfig-interface)
  - [SessionWithUser (interface)](#sessionwithuser-interface)
  - [User (interface)](#user-interface)

---

# utils

## Credentials (interface)

Represents credentials for authentication

**Signature**

```ts
export interface Credentials {
  readonly userId: string;
  readonly password: string;
}
```

## HashedPassword (interface)

Represents a hashed password with salt

**Signature**

```ts
export interface HashedPassword {
  readonly hash: string;
  readonly algorithm: string;
}
```

## Permission (interface)

Permission check result

**Signature**

```ts
export interface Permission {
  readonly resource: string;
  readonly action: string;
  readonly granted: boolean;
}
```

## Session (interface)

Represents an active session

**Signature**

```ts
export interface Session {
  readonly id: string;
  readonly userId: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly lastActivityAt: Date;
  readonly attributes: Record<string, unknown>;
}
```

## SessionConfig (interface)

Configuration for session management

**Signature**

```ts
export interface SessionConfig {
  readonly sessionExpiresIn: {
    readonly activePeriod: number; // milliseconds
    readonly idlePeriod: number; // milliseconds
  };
}
```

## SessionWithUser (interface)

Represents a session with its associated user

**Signature**

```ts
export interface SessionWithUser {
  readonly session: Session;
  readonly user: User;
}
```

## User (interface)

Represents a user in the authentication system

**Signature**

```ts
export interface User {
  readonly id: string;
  readonly attributes: Record<string, unknown>;
}
```
