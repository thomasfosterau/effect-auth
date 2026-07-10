import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import { normalizeEmail } from "./utils.ts";

export class UserServiceStore extends Context.Service<
  UserServiceStore,
  {
    /** Get a user by ID, or `null` when no such user exists. */
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

    readonly getByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

    readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

    readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/UserServiceStore") {}

/** Partial update of a user's first-class profile fields. */
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}

export class UserService extends Context.Service<
  UserService,
  {
    readonly getUser: (
      userId: string,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly getUserByEmail: (
      email: string,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly updateUserAttributes: (
      userId: string,
      attributes: Record<string, unknown>,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly updateUser: (
      userId: string,
      updates: UpdateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly markEmailVerified: (
      userId: string,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/UserService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = () => Layer.effect(UserService, makeUserService());
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

export const makeUserService = (): Effect.Effect<
  typeof UserService.Service,
  never,
  UserServiceStore
> =>
  Effect.gen(function* () {
    const store = yield* UserServiceStore;

    return {
      getUser: Effect.fn("UserService.getUser")((userId: string) => getUserOrFail(store, userId)),

      getUserByEmail: Effect.fn("UserService.getUserByEmail")(function* (email: string) {
        const normalizedEmail = normalizeEmail(email);

        if (!normalizedEmail) {
          return yield* Effect.fail(
            new Errors.UserNotFoundError({
              message: "User not found",
              userId: "",
            }),
          );
        }

        const user = yield* store.getByEmail(normalizedEmail);
        if (!user) {
          return yield* Effect.fail(
            new Errors.UserNotFoundError({
              message: "User not found",
              userId: normalizedEmail,
            }),
          );
        }

        return user;
      }),

      updateUserAttributes: Effect.fn("UserService.updateUserAttributes")(function* (
        userId: string,
        attributes: Record<string, unknown>,
      ) {
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

      markEmailVerified: Effect.fn("UserService.markEmailVerified")(function* (userId: string) {
        const existing = yield* getUserOrFail(store, userId);

        const updated: Types.User = {
          ...existing,
          emailVerified: true,
          updatedAt: new Date(),
        };

        return yield* store.update(updated);
      }),

      deleteUser: Effect.fn("UserService.deleteUser")((userId: string) => store.delete(userId)),
    };
  });
