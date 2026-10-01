import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";

/** The user-store contract {@link UserService} reads, updates and deletes users through. */
export class UserServiceStore extends Context.Service<
  UserServiceStore,
  {
    /** Get a user by ID, or `null` when no such user exists. */
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

    readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

    readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/UserServiceStore") {}

/**
 * `UserService` configuration.
 *
 * @since 1.0.0
 * @category models
 */
export interface UserServiceConfig {
  /**
   * Attribute keys `updateUserAttributes` refuses to write, whoever calls it
   * (default `["role"]`). These are the attributes that carry authority — the
   * rung the guards read above all — so a profile-update path built on
   * `updateUserAttributes` cannot let a user set their own role. Change them
   * through their privileged door instead (`AdminService.setRole` for `role`).
   * Pass `[]` to opt out.
   */
  readonly serverOnlyAttributes?: ReadonlyArray<string>;
}

/** Partial update of a user's first-class profile fields. */
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}

/**
 * Reads and updates users: profile fields and the attribute bag, refusing writes to {@link UserServiceConfig.serverOnlyAttributes}.
 *
 * Requires `UserServiceStore`.
 */
export class UserService extends Context.Service<
  UserService,
  {
    readonly getUser: (
      userId: string,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    /**
     * Merge `attributes` into the user's attribute bag. Fails with
     * `InvalidInputError` — writing nothing — when any key is one of
     * {@link UserServiceConfig.serverOnlyAttributes}.
     */
    readonly updateUserAttributes: (
      userId: string,
      attributes: Record<string, unknown>,
    ) => Effect.Effect<
      Types.User,
      Errors.AuthError | Errors.UserNotFoundError | Errors.InvalidInputError
    >;

    readonly updateUser: (
      userId: string,
      updates: UpdateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/UserService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config?: UserServiceConfig) => Layer.effect(UserService, make(config));
}

/** Fetch a user from the store, failing with `UserNotFoundError` on a miss. */
const getUserOrFail = (
  store: typeof UserServiceStore.Service,
  userId: string,
): Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError> =>
  Effect.flatMap(store.get(userId), (user) =>
    user === null
      ? Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId }))
      : Effect.succeed(user),
  );

export const make = (
  config?: UserServiceConfig,
): Effect.Effect<typeof UserService.Service, never, UserServiceStore> =>
  Effect.gen(function* () {
    const store = yield* UserServiceStore;
    const serverOnly = new Set(config?.serverOnlyAttributes ?? ["role"]);

    return {
      getUser: Effect.fn("UserService.getUser")((userId: string) => getUserOrFail(store, userId)),

      updateUserAttributes: Effect.fn("UserService.updateUserAttributes")(function* (
        userId: string,
        attributes: Record<string, unknown>,
      ) {
        const refused = Object.keys(attributes).find((key) => serverOnly.has(key));
        if (refused !== undefined) {
          return yield* new Errors.InvalidInputError({
            message: `"${refused}" is a server-only attribute and cannot be set here`,
            field: refused,
          });
        }
        const existing = yield* getUserOrFail(store, userId);

        const updated: Types.User = {
          ...existing,
          updatedAt: new Date(),
          attributes: {
            ...existing.attributes,
            ...attributes,
          },
        };

        return yield* store.update(updated);
      }),

      updateUser: Effect.fn("UserService.updateUser")(function* (
        userId: string,
        updates: UpdateUserInput,
      ) {
        const existing = yield* getUserOrFail(store, userId);

        const updated: Types.User = {
          ...existing,
          ...(updates.name !== undefined && { name: updates.name }),
          ...(updates.image !== undefined && { image: updates.image }),
          updatedAt: new Date(),
        };

        return yield* store.update(updated);
      }),

      deleteUser: Effect.fn("UserService.deleteUser")((userId: string) => store.delete(userId)),
    };
  });
