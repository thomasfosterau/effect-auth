import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import { normalizeEmail } from "./utils.ts";

export interface UserServiceStoreShape {
  /** Get a user by ID, or `null` when no such user exists. */
  readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly getByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

export class UserServiceStore extends Context.Service<UserServiceStore, UserServiceStoreShape>()(
  "@effect-auth/UserServiceStore",
) {}

/** Partial update of a user's first-class profile fields. */
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}

export interface UserServiceShape {
  readonly getUser: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly getUserByEmail: (
    email: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly updateUserAttributes: (
    userId: string,
    attributes: Record<string, unknown>,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly updateUser: (
    userId: string,
    updates: UpdateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly markEmailVerified: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStore>;

  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError, UserServiceStore>;
}

export class UserService extends Context.Service<UserService, UserServiceShape>()(
  "@effect-auth/UserService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = () => Layer.effect(UserService, makeUserService());
}

/** Fetch a user from the store, failing with `UserNotFoundError` on a miss. */
const getUserOrFail = (
  store: UserServiceStoreShape,
  userId: string,
): Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError> =>
  Effect.flatMap(store.get(userId), (user) =>
    user === null
      ? Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId }))
      : Effect.succeed(user),
  );

export const makeUserService = (): Effect.Effect<UserServiceShape, never> =>
  Effect.sync(
    (): UserServiceShape => ({
      getUser: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
          return yield* getUserOrFail(store, userId);
        }),

      getUserByEmail: (email: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
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

      updateUserAttributes: (userId: string, attributes: Record<string, unknown>) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
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

      updateUser: (userId: string, updates: UpdateUserInput) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
          const existing = yield* getUserOrFail(store, userId);

          const updated: Types.User = {
            ...existing,
            ...(updates.name !== undefined && { name: updates.name }),
            ...(updates.image !== undefined && { image: updates.image }),
            updatedAt: new Date(),
          };

          return yield* store.update(updated);
        }),

      markEmailVerified: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
          const existing = yield* getUserOrFail(store, userId);

          const updated: Types.User = {
            ...existing,
            emailVerified: true,
            updatedAt: new Date(),
          };

          return yield* store.update(updated);
        }),

      deleteUser: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStore;
          yield* store.delete(userId);
        }),
    }),
  );
