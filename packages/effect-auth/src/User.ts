import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.js";
import type * as Types from "./Types.js";

export interface UserServiceStore {
  /** Get a user by ID, or `null` when no such user exists. */
  readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly getByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly update: (user: Types.User) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly delete: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

export class UserServiceStoreTag extends Context.Service<UserServiceStoreTag, UserServiceStore>()(
  "@effect-auth/UserServiceStore",
) {}

export const UserServiceStore = UserServiceStoreTag;

/** Partial update of a user's first-class profile fields. */
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}

export interface UserService {
  readonly getUser: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly getUserByEmail: (
    email: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly updateUserAttributes: (
    userId: string,
    attributes: Record<string, unknown>,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly updateUser: (
    userId: string,
    updates: UpdateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly markEmailVerified: (
    userId: string,
  ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError, UserServiceStoreTag>;

  readonly deleteUser: (
    userId: string,
  ) => Effect.Effect<void, Errors.AuthError, UserServiceStoreTag>;
}

export class UserServiceTag extends Context.Service<UserServiceTag, UserService>()(
  "@effect-auth/UserService",
) {
  /**
   * Construct a Layer providing this service — the canonical form of
   * {@link UserServiceLayer}.
   */
  static readonly layer = () => UserServiceLayer();
}

export const UserService = UserServiceTag;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

/** Fetch a user from the store, failing with `UserNotFoundError` on a miss. */
const getUserOrFail = (
  store: UserServiceStore,
  userId: string,
): Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError> =>
  Effect.flatMap(store.get(userId), (user) =>
    user === null
      ? Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId }))
      : Effect.succeed(user),
  );

export const makeUserService = (): Effect.Effect<UserService, never> =>
  Effect.sync(
    (): UserService => ({
      getUser: (userId: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStoreTag;
          return yield* getUserOrFail(store, userId);
        }),

      getUserByEmail: (email: string) =>
        Effect.gen(function* () {
          const store = yield* UserServiceStoreTag;
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
          const store = yield* UserServiceStoreTag;
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
          const store = yield* UserServiceStoreTag;
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
          const store = yield* UserServiceStoreTag;
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
          const store = yield* UserServiceStoreTag;
          yield* store.delete(userId);
        }),
    }),
  );

export const UserServiceLayer = () => Layer.effect(UserServiceTag, makeUserService());
