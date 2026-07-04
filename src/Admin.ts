/**
 * Administration for effect-auth.
 *
 * Mirrors better-auth's admin plugin: administrators can list users, change
 * roles, ban/unban users (revoking their sessions), delete users, revoke
 * sessions, and impersonate users.
 *
 * **Conventions:** admin status and ban state live on the user record:
 *
 * - a user is an admin when `user.attributes.role` is one of
 *   {@link AdminConfig.adminRoles} (default `["admin"]`) or their id is in
 *   {@link AdminConfig.adminUserIds};
 * - a ban is stored as `attributes.banned: true` with optional
 *   `attributes.banReason` (string) and `attributes.banExpires` (epoch ms;
 *   absent means permanent). A `banExpires` in the past means the ban has
 *   lapsed - see {@link isBanned}.
 *
 * Wire {@link BannedUserPlugin} into your hooks stack to block banned users
 * from validating sessions.
 *
 * @module admin
 */

import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import { Hooks, makePlugin, type HookError } from "./Hooks.ts";
import { IdentifierStore, type IdentifierType } from "./Identifier.ts";
import { PasswordHasher } from "./Password.ts";
import { SessionManager } from "./Session.ts";
import type * as Types from "./Types.ts";
import { UserServiceStore } from "./User.ts";

/**
 * Admin error
 */
export class AdminError extends Data.TaggedError("AdminError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Query for listing users
 */
export interface ListUsersQuery {
  /** Maximum number of users to return */
  readonly limit?: number;
  /** Number of users to skip (for pagination) */
  readonly offset?: number;
  /** Case-insensitive substring filter on email */
  readonly searchEmail?: string;
}

/**
 * A page of users plus the total (pre-pagination) count
 */
export interface ListUsersResult {
  readonly users: ReadonlyArray<Types.User>;
  readonly total: number;
}

/**
 * Storage interface for admin-only user queries. The regular
 * `UserServiceStore` (get/update/delete) is reused for everything else;
 * this store adds listing and admin-initiated creation / credential management.
 */
export interface AdminUserStoreShape {
  readonly listUsers: (query: ListUsersQuery) => Effect.Effect<ListUsersResult, Errors.AuthError>;

  /** Create a new user record. The store is responsible for assigning `id` and timestamps. */
  readonly createUser: (input: {
    readonly email: string;
    readonly name?: string;
    readonly image?: string;
    readonly attributes?: Record<string, unknown>;
  }) => Effect.Effect<Types.User, Errors.AuthError>;

  /** Persist a hashed password for an existing user (admin reset; no current-password check). */
  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Input for admin-initiated user creation.
 */
export interface AdminCreateUserInput {
  /** Primary email address — also written to `User.email`. */
  readonly email: string;
  readonly name?: string;
  readonly image?: string;
  /** Plain-text password; hashed via `PasswordHasher` before storage. */
  readonly password?: string;
  /** Written to `attributes.role`. */
  readonly role?: string;
  readonly attributes?: Record<string, unknown>;
  /**
   * Additional identifier records created via `IdentifierStore` (email,
   * username, or phone). These complement the `User.email` field and are
   * the foundation for multi-identifier sign-in (Phase 1 identifier model).
   */
  readonly identifiers?: ReadonlyArray<{
    readonly type: IdentifierType;
    readonly value: string;
    readonly verified?: boolean;
  }>;
}

export class AdminUserStore extends Context.Service<AdminUserStore, AdminUserStoreShape>()(
  "@effect-auth/AdminUserStore",
) {}

/**
 * Admin service configuration
 */
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
   * see {@link AdminServiceShape.impersonateUser}.
   */
  readonly impersonationSessionDuration?: number;
}

/**
 * Whether a user is an administrator under the given config: either their id
 * is in `adminUserIds` or their `attributes.role` is one of `adminRoles`.
 */
export const isAdmin = (user: Types.User, config: AdminConfig = {}): boolean => {
  const adminRoles = config?.adminRoles ?? ["admin"];
  const adminUserIds = config?.adminUserIds ?? [];
  if (adminUserIds.includes(user.id)) {
    return true;
  }
  const role = user.attributes["role"];
  return typeof role === "string" && adminRoles.includes(role);
};

/**
 * Whether a user is currently banned. A ban with `attributes.banExpires` in
 * the past has lapsed and no longer counts.
 */
export const isBanned = (user: Types.User): boolean => {
  if (user.attributes["banned"] !== true) {
    return false;
  }
  const banExpires = user.attributes["banExpires"];
  if (typeof banExpires === "number" && banExpires <= Date.now()) {
    return false;
  }
  return true;
};

/**
 * Options for banning a user
 */
export interface BanUserOptions {
  /** Reason recorded on the user (default: `defaultBanReason`) */
  readonly reason?: string;
  /** Ban duration in milliseconds from now (default: `defaultBanExpiresIn`;
   * undefined = permanent) */
  readonly expiresIn?: number;
}

/**
 * Admin service. Every method takes the acting (already authenticated) user
 * as its first argument and fails with `AdminError` unless
 * {@link isAdmin | `isAdmin(actor, config)`} holds.
 */
export interface AdminServiceShape {
  /**
   * List users with pagination and optional email search.
   */
  readonly listUsers: (
    actor: Types.User,
    query?: ListUsersQuery,
  ) => Effect.Effect<ListUsersResult, AdminError | Errors.AuthError, AdminUserStore>;

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
    UserServiceStore
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
    UserServiceStore | SessionManager
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
    UserServiceStore
  >;

  /**
   * Delete a user and revoke all of their sessions. Admins cannot remove
   * themselves.
   */
  readonly removeUser: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<void, AdminError | Errors.AuthError, UserServiceStore | SessionManager>;

  /**
   * Revoke all sessions of a user.
   */
  readonly revokeUserSessions: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<void, AdminError | Errors.AuthError, SessionManager>;

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
    UserServiceStore | SessionManager | Hooks
  >;

  /**
   * Create a new user, optionally with initial identifier records (email,
   * username, or phone via `IdentifierStore`), a hashed initial password, and
   * a role. The `email` field is required and populates `User.email`; any
   * additional entries in `identifiers` are persisted via `IdentifierStore`.
   */
  readonly createUser: (
    actor: Types.User,
    input: AdminCreateUserInput,
  ) => Effect.Effect<
    Types.User,
    AdminError | Errors.AuthError | Errors.HashingError,
    AdminUserStore | IdentifierStore | PasswordHasher
  >;

  /**
   * Set (reset) a user's password without requiring their current password.
   * Optionally revokes all of the user's existing sessions after the reset.
   */
  readonly setUserPassword: (
    actor: Types.User,
    userId: string,
    newPassword: string,
    options?: { readonly revokeOtherSessions?: boolean },
  ) => Effect.Effect<
    void,
    AdminError | Errors.AuthError | Errors.HashingError | Errors.UserNotFoundError,
    UserServiceStore | AdminUserStore | PasswordHasher | SessionManager
  >;

  /**
   * List a user's non-expired sessions (the same view used by
   * `SessionManager.listSessions`). Useful for an admin "see where this user
   * is signed in" view before deciding whether to call `revokeUserSessions`.
   */
  readonly listUserSessions: (
    actor: Types.User,
    userId: string,
  ) => Effect.Effect<ReadonlyArray<Types.Session>, AdminError | Errors.AuthError, SessionManager>;
}

export class AdminService extends Context.Service<AdminService, AdminServiceShape>()(
  "@effect-auth/AdminService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: AdminConfig = {}) =>
    Layer.effect(AdminService, makeAdminService(config));
}

/**
 * Create an admin service
 */
export const makeAdminService = (
  config: AdminConfig = {},
): Effect.Effect<AdminServiceShape, never> => {
  const defaultBanReason = config.defaultBanReason ?? "No reason";
  const impersonationSessionDuration = config.impersonationSessionDuration ?? 60 * 60 * 1000; // 1 hour

  /** Fail with AdminError unless the actor is an administrator. */
  const requireAdmin = (actor: Types.User): Effect.Effect<void, AdminError> =>
    isAdmin(actor, config)
      ? Effect.void
      : Effect.fail(new AdminError({ message: "Forbidden: administrator privileges required" }));

  return Effect.sync(
    (): AdminServiceShape => ({
      listUsers: (actor, query = {}) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);
          const store = yield* AdminUserStore;
          return yield* store.listUsers(query);
        }),

      setRole: (actor, userId, role) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          const userStore = yield* UserServiceStore;
          const user = yield* userStore.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          return yield* userStore.update({
            ...user,
            updatedAt: new Date(),
            attributes: { ...user.attributes, role },
          });
        }),

      banUser: (actor, userId, options = {}) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          if (userId === actor.id) {
            return yield* Effect.fail(new AdminError({ message: "You cannot ban yourself" }));
          }

          const userStore = yield* UserServiceStore;
          const user = yield* userStore.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          if (isAdmin(user, config)) {
            return yield* Effect.fail(
              new AdminError({ message: "Administrators cannot be banned" }),
            );
          }

          const expiresIn = options.expiresIn ?? config.defaultBanExpiresIn;

          // Rebuild ban attributes from scratch so a stale `banExpires` from a
          // previous (temporary) ban cannot leak into a new permanent ban.
          const attributes: Record<string, unknown> = {};
          for (const [key, value] of Object.entries(user.attributes)) {
            if (key !== "banned" && key !== "banReason" && key !== "banExpires") {
              attributes[key] = value;
            }
          }
          attributes["banned"] = true;
          attributes["banReason"] = options.reason ?? defaultBanReason;
          if (expiresIn !== undefined) {
            attributes["banExpires"] = Date.now() + expiresIn;
          }

          const banned = yield* userStore.update({
            ...user,
            updatedAt: new Date(),
            attributes,
          });

          const sessionManager = yield* SessionManager;
          yield* sessionManager.invalidateUserSessions(userId);

          return banned;
        }),

      unbanUser: (actor, userId) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          const userStore = yield* UserServiceStore;
          const user = yield* userStore.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          const attributes: Record<string, unknown> = {};
          for (const [key, value] of Object.entries(user.attributes)) {
            if (key !== "banned" && key !== "banReason" && key !== "banExpires") {
              attributes[key] = value;
            }
          }
          attributes["banned"] = false;

          return yield* userStore.update({
            ...user,
            updatedAt: new Date(),
            attributes,
          });
        }),

      removeUser: (actor, userId) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          if (userId === actor.id) {
            return yield* Effect.fail(new AdminError({ message: "You cannot remove yourself" }));
          }

          const userStore = yield* UserServiceStore;
          const sessionManager = yield* SessionManager;

          yield* sessionManager.invalidateUserSessions(userId);
          yield* userStore.delete(userId);
        }),

      revokeUserSessions: (actor, userId) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);
          const sessionManager = yield* SessionManager;
          yield* sessionManager.invalidateUserSessions(userId);
        }),

      impersonateUser: (actor, userId) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          const userStore = yield* UserServiceStore;
          const target = yield* userStore.get(userId);
          if (target === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          const sessionManager = yield* SessionManager;
          return yield* sessionManager.createSession(target.id, {
            impersonatedBy: actor.id,
            impersonationExpiresAt: Date.now() + impersonationSessionDuration,
          });
        }),

      createUser: (actor, input) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          const adminStore = yield* AdminUserStore;

          const attributes: Record<string, unknown> = { ...input.attributes };
          if (input.role !== undefined) {
            attributes["role"] = input.role;
          }

          const createInput: {
            email: string;
            name?: string;
            image?: string;
            attributes?: Record<string, unknown>;
          } = { email: input.email, attributes };
          if (input.name !== undefined) createInput.name = input.name;
          if (input.image !== undefined) createInput.image = input.image;

          const user = yield* adminStore.createUser(createInput);

          if (input.identifiers && input.identifiers.length > 0) {
            const identifierStore = yield* IdentifierStore;
            const now = new Date();
            for (const ident of input.identifiers) {
              yield* identifierStore.create({
                id: crypto.randomUUID(),
                userId: user.id,
                type: ident.type,
                value: ident.value,
                verified: ident.verified ?? false,
                verifiedAt: ident.verified ? now : undefined,
                createdAt: now,
              });
            }
          }

          if (input.password !== undefined) {
            const hasher = yield* PasswordHasher;
            const hashed = yield* hasher.hash(input.password);
            yield* adminStore.setPasswordHash(user.id, hashed.hash);
          }

          return user;
        }),

      setUserPassword: (actor, userId, newPassword, options = {}) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);

          const userStore = yield* UserServiceStore;
          const user = yield* userStore.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          const hasher = yield* PasswordHasher;
          const hashed = yield* hasher.hash(newPassword);

          const adminStore = yield* AdminUserStore;
          yield* adminStore.setPasswordHash(userId, hashed.hash);

          if (options.revokeOtherSessions) {
            const sessionManager = yield* SessionManager;
            yield* sessionManager.invalidateUserSessions(userId);
          }
        }),

      listUserSessions: (actor, userId) =>
        Effect.gen(function* () {
          yield* requireAdmin(actor);
          const sessionManager = yield* SessionManager;
          return yield* sessionManager.listSessions(userId);
        }),
    }),
  );
};

/**
 * Hooks plugin that blocks banned users at session validation.
 *
 * Fails `afterValidateSession` with `AuthError("User is banned")` when the
 * validated user {@link isBanned | is currently banned}, short-circuiting
 * `SessionManager.validateSession`. Lapsed bans (`banExpires` in the past)
 * pass through.
 *
 * Zero-dependency: compose it with the rest of your stack, e.g.
 * `composePlugins([BannedUserPlugin]).pipe(Layer.provide(Hooks.Default))` or
 * `BannedUserPlugin.pipe(Layer.provide(Hooks.Default))`.
 */
export const BannedUserPlugin: Layer.Layer<Hooks, never, Hooks> = makePlugin({
  afterValidateSession: (sessionWithUser: Types.SessionWithUser) =>
    isBanned(sessionWithUser.user)
      ? Effect.fail(new Errors.UserBannedError({ message: "Your account has been suspended" }))
      : Effect.succeed(sessionWithUser),
});
