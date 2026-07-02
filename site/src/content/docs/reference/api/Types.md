---
title: "Types"
description: "API reference for the Types module."
---

## Types overview

Core types for the Effect Auth library.

The central domain records (`User`, `Session`, `SessionWithUser`) are
defined as `Schema` structs so a single definition provides the TypeScript
type, runtime validation, and JSON serialization used by stores and the
HTTP protocol layer. Configuration shapes remain plain interfaces.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [Attributes](#attributes)
  - [Attributes (type alias)](#attributes-type-alias)
  - [Credentials (interface)](#credentials-interface)
  - [HashedPassword (interface)](#hashedpassword-interface)
  - [Permission (interface)](#permission-interface)
  - [Session](#session)
  - [Session (type alias)](#session-type-alias)
  - [SessionConfig (interface)](#sessionconfig-interface)
  - [SessionWithUser](#sessionwithuser)
  - [SessionWithUser (type alias)](#sessionwithuser-type-alias)
  - [User](#user)
  - [User (type alias)](#user-type-alias)

---

# utils

## Attributes

Arbitrary attribute bag for custom fields on users and sessions.
Core fields (email, name, ...) are first-class; anything app-specific
lives here.

**Signature**

```ts
export declare const Attributes: Schema.$Record<Schema.String, Schema.Unknown>;
```

## Attributes (type alias)

**Signature**

```ts
export type Attributes = typeof Attributes.Type;
```

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

## Session

Represents an active session.

**Signature**

```ts
export declare const Session: Schema.Struct<{
  readonly id: Schema.String;
  readonly userId: Schema.String;
  readonly expiresAt: Schema.Date;
  readonly createdAt: Schema.Date;
  readonly lastActivityAt: Schema.Date;
  readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
}>;
```

## Session (type alias)

**Signature**

```ts
export type Session = typeof Session.Type;
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

## SessionWithUser

Represents a session with its associated user.

**Signature**

```ts
export declare const SessionWithUser: Schema.Struct<{
  readonly session: Schema.Struct<{
    readonly id: Schema.String;
    readonly userId: Schema.String;
    readonly expiresAt: Schema.Date;
    readonly createdAt: Schema.Date;
    readonly lastActivityAt: Schema.Date;
    readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
  }>;
  readonly user: Schema.Struct<{
    readonly id: Schema.String;
    readonly email: Schema.String;
    readonly emailVerified: Schema.Boolean;
    readonly name: Schema.optional<Schema.String>;
    readonly image: Schema.optional<Schema.String>;
    readonly createdAt: Schema.Date;
    readonly updatedAt: Schema.Date;
    readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
  }>;
}>;
```

## SessionWithUser (type alias)

**Signature**

```ts
export type SessionWithUser = typeof SessionWithUser.Type;
```

## User

Represents a user in the authentication system.

Core identity fields are first-class (mirroring the common auth data
model): `email` (unique, normalized lowercase), `emailVerified`, optional
`name` and `image`, plus `createdAt`/`updatedAt` timestamps. App-specific
fields go in `attributes`.

**Signature**

```ts
export declare const User: Schema.Struct<{
  readonly id: Schema.String;
  readonly email: Schema.String;
  readonly emailVerified: Schema.Boolean;
  readonly name: Schema.optional<Schema.String>;
  readonly image: Schema.optional<Schema.String>;
  readonly createdAt: Schema.Date;
  readonly updatedAt: Schema.Date;
  readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
}>;
```

## User (type alias)

**Signature**

```ts
export type User = typeof User.Type;
```
