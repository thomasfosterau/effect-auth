---
title: "Admin"
description: "API reference for the Admin module."
---

## Admin overview

Administration for effect-auth.

Mirrors better-auth's admin plugin: administrators can list users, change
roles, ban/unban users (revoking their sessions), delete users, revoke
sessions, and impersonate users.

**Conventions:** admin status and ban state live on the user record:

- a user is an admin when `user.attributes.role` is one of
  {@link AdminConfig.adminRoles} (default `["admin"]`) or their id is in
  {@link AdminConfig.adminUserIds};
- a ban is stored as `attributes.banned: true` with optional
  `attributes.banReason` (string) and `attributes.banExpires` (epoch ms;
  absent means permanent). A `banExpires` in the past means the ban has
  lapsed - see {@link isBanned}.

Wire {@link BannedUserPlugin} into your hooks stack to block banned users
from validating sessions.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AdminConfig (interface)](#adminconfig-interface)
  - [AdminError (class)](#adminerror-class)
  - [AdminService](#adminservice)
  - [AdminService (interface)](#adminservice-interface)
  - [AdminServiceLayer](#adminservicelayer)
  - [AdminServiceTag (class)](#adminservicetag-class)
  - [AdminUserStore](#adminuserstore)
  - [AdminUserStore (interface)](#adminuserstore-interface)
  - [AdminUserStoreTag (class)](#adminuserstoretag-class)
  - [BanUserOptions (interface)](#banuseroptions-interface)
  - [BannedUserPlugin](#banneduserplugin)
  - [ListUsersQuery (interface)](#listusersquery-interface)
  - [ListUsersResult (interface)](#listusersresult-interface)
  - [isAdmin](#isadmin)
  - [isBanned](#isbanned)
  - [makeAdminService](#makeadminservice)

---

# utils

## AdminConfig (interface)

Admin service configuration

**Signature**

```ts
export interface AdminConfig {
  /** `attributes.role` values that grant admin status (default: ["admin"]) */
  readonly adminRoles?: ReadonlyArray<string>;
  /** User ids that are always admins, regardless of role (default: []) */
  readonly adminUserIds?: ReadonlyArray<string>;
  /** Ban reason used when none is provided (default: "No reason") */
  readonly defaultBanReason?: string;
  /** Default ban duration in milliseconds; undefined = permanent */
  readonly defaultBanExpiresIn?: number;
  /**
   * Advisory lifetime of impersonation sessions in milliseconds (default:
   * 1 hour). Recorded on the session as `attributes.impersonationExpiresAt`;
   * see {@link AdminService.impersonateUser}.
   */
  readonly impersonationSessionDuration?: number;
}
```

## AdminError (class)

Admin error

**Signature**

```ts
export declare class AdminError
```

## AdminService

**Signature**

```ts
export declare const AdminService: typeof AdminServiceTag;
```

## AdminService (interface)

Admin service. Every method takes the acting (already authenticated) user
as its first argument and fails with `AdminError` unless
{@link isAdmin | `isAdmin(actor, config)`} holds.

**Signature**

```ts
export interface AdminService {
  /**
   * List users with pagination and optional email search.
   */
  readonly listUsers: (
    actor: Types.User,
    query?: ListUsersQuery,
  ) => Effect.Effect<ListUsersResult, AdminError | Errors.AuthError, AdminUserStoreTag>;

  /**
   * Set a user's role (written to `attributes.role`).
   */
  readonly setRole: (
    actor: Types.User,
    userId: string,
    role: string,
  ) => Effect.Effect<
    Types.User,
    AdminError | Errors.AuthError | Errors.UserNotFoundError,
    UserServiceStoreTag
  >;

  /**
   * Ban a user: sets `attributes.banned`/`banReason`/`banExpires` and revokes
   * all of the user's sessions. Admins cannot ban themselves or other admins.
   */
  readonly banUser: (
    actor: Types.User,
    userId: string,
    options?: BanUserOptions,
  ) => Effect.Effect<
    Types.User,
    AdminError | Errors.AuthError | Errors.UserNotFoundError,
    UserServiceStoreTag | SessionManagerTag
  >;

  /**
   * Lift a user's ban (clears the ban attributes).
   */
  readonly unbanUser: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<
    Types.User,
    AdminError | Errors.AuthError | Errors.UserNotFoundError,
    UserServiceStoreTag
  >;

  /**
   * Delete a user and revoke all of their sessions. Admins cannot remove
   * themselves.
   */
  readonly removeUser: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<void, AdminError | Errors.AuthError, UserServiceStoreTag | SessionManagerTag>;

  /**
   * Revoke all sessions of a user.
   */
  readonly revokeUserSessions: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<void, AdminError | Errors.AuthError, SessionManagerTag>;

  /**
   * Create a session for the target user marked with
   * `attributes.impersonatedBy = actor.id` and
   * `attributes.impersonationExpiresAt = now + impersonationSessionDuration`.
   *
   * Note: `SessionManager.createSession` does not accept a custom expiry, so
   * the session's actual lifetime follows the session configuration; the
   * `impersonationExpiresAt` attribute is advisory and can be enforced by the
   * application (e.g. via an `afterValidateSession` hook).
   */
  readonly impersonateUser: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<
    Types.Session,
    AdminError | Errors.AuthError | Errors.UserNotFoundError | HookError,
    UserServiceStoreTag | SessionManagerTag | Hooks
  >;
}
```

## AdminServiceLayer

**Signature**

```ts
export declare const AdminServiceLayer: (
  config?: AdminConfig,
) => Layer.Layer<AdminServiceTag, never, never>;
```

## AdminServiceTag (class)

**Signature**

```ts
export declare class AdminServiceTag
```

## AdminUserStore

**Signature**

```ts
export declare const AdminUserStore: typeof AdminUserStoreTag;
```

## AdminUserStore (interface)

Storage interface for admin-only user queries. The regular
`UserServiceStore` (get/update/delete) is reused for everything else;
this store only adds listing, which per-user stores cannot express.

**Signature**

```ts
export interface AdminUserStore {
  readonly listUsers: (query: ListUsersQuery) => Effect.Effect<ListUsersResult, Errors.AuthError>;
}
```

## AdminUserStoreTag (class)

**Signature**

```ts
export declare class AdminUserStoreTag
```

## BanUserOptions (interface)

Options for banning a user

**Signature**

```ts
export interface BanUserOptions {
  /** Reason recorded on the user (default: `defaultBanReason`) */
  readonly reason?: string;
  /** Ban duration in milliseconds from now (default: `defaultBanExpiresIn`;
   * undefined = permanent) */
  readonly expiresIn?: number;
}
```

## BannedUserPlugin

Hooks plugin that blocks banned users at session validation.

Fails `afterValidateSession` with `AuthError("User is banned")` when the
validated user {@link isBanned | is currently banned}, short-circuiting
`SessionManager.validateSession`. Lapsed bans (`banExpires` in the past)
pass through.

Zero-dependency: compose it with the rest of your stack, e.g.
`composePlugins([BannedUserPlugin]).pipe(Layer.provide(Hooks.Default))` or
`BannedUserPlugin.pipe(Layer.provide(Hooks.Default))`.

**Signature**

```ts
export declare const BannedUserPlugin: Layer.Layer<Hooks, never, Hooks>;
```

## ListUsersQuery (interface)

Query for listing users

**Signature**

```ts
export interface ListUsersQuery {
  /** Maximum number of users to return */
  readonly limit?: number;
  /** Number of users to skip (for pagination) */
  readonly offset?: number;
  /** Case-insensitive substring filter on email */
  readonly searchEmail?: string;
}
```

## ListUsersResult (interface)

A page of users plus the total (pre-pagination) count

**Signature**

```ts
export interface ListUsersResult {
  readonly users: ReadonlyArray<Types.User>;
  readonly total: number;
}
```

## isAdmin

Whether a user is an administrator under the given config: either their id
is in `adminUserIds` or their `attributes.role` is one of `adminRoles`.

**Signature**

```ts
export declare const isAdmin: (user: Types.User, config?: AdminConfig) => boolean;
```

## isBanned

Whether a user is currently banned. A ban with `attributes.banExpires` in
the past has lapsed and no longer counts.

**Signature**

```ts
export declare const isBanned: (user: Types.User) => boolean;
```

## makeAdminService

Create an admin service

**Signature**

```ts
export declare const makeAdminService: (config?: AdminConfig) => Effect.Effect<AdminService, never>;
```
