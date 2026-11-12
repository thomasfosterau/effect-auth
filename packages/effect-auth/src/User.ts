import { Context, DateTime, Effect, HashSet, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { AccountDeletion } from "./AccountDeletion.ts";
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
 * @since 0.1.0
 * @category models
 */
/**
 * The default {@link UserServiceConfig.serverOnlyAttributes}: `role`, the rung
 * the guards read.
 *
 * @since 0.1.0
 * @category constants
 */
export const DEFAULT_SERVER_ONLY_ATTRIBUTES: ReadonlyArray<string> = ["role"];

/**
 * The ban-state attribute keys `AdminService.banUser` / `unbanUser` write and
 * `isBanned` reads: `banned`, `banReason`, `banExpires`.
 *
 * @since 0.1.0
 * @category constants
 */
export const BAN_ATTRIBUTES: ReadonlyArray<string> = ["banned", "banReason", "banExpires"];

/**
 * Attribute keys a sign-up never takes from its input, on top of
 * {@link UserServiceConfig.serverOnlyAttributes}, whatever an HTTP
 * `signUpAttributes` allow-list names (#580): the ban state
 * ({@link BAN_ATTRIBUTES}), the SCIM provisioning keys (`scimUserName`,
 * `scimDeactivated`, `scimExternalId`, which `ScimService` alone writes) and
 * the anonymous-user marker (`isAnonymous`, which `AnonymousService` alone
 * writes). Each is state another, privileged flow owns, so a caller who could
 * preset it at sign-up could forge it.
 *
 * @since 0.1.0
 * @category constants
 */
export const SIGN_UP_PROTECTED_ATTRIBUTES: ReadonlyArray<string> = [
  ...BAN_ATTRIBUTES,
  "scimUserName",
  "scimDeactivated",
  "scimExternalId",
  "isAnonymous",
];

/**
 * A copy of `attributes` without the keys a sign-up never takes from its
 * input: `serverOnly` (the configured
 * {@link UserServiceConfig.serverOnlyAttributes}) and
 * {@link SIGN_UP_PROTECTED_ATTRIBUTES}. `EmailPasswordService.signUp` and
 * `AuthLifecycleService.signUp` apply it to every new user (#580).
 *
 * @since 0.1.0
 * @category utils
 */
export const withoutSignUpProtectedAttributes = (
  attributes: Types.Attributes,
  serverOnly: ReadonlyArray<string>,
): Types.Attributes =>
  R.filter(
    attributes,
    (_, key) => !serverOnly.includes(key) && !SIGN_UP_PROTECTED_ATTRIBUTES.includes(key),
  );

/**
 * The entries of `attributes` whose key `keys` names, or `undefined` when
 * none is: how `POST /users` applies its `signUpAttributes` allow-list (#580).
 *
 * @since 0.1.0
 * @category utils
 */
export const onlyAttributes = (
  attributes: Types.Attributes,
  keys: ReadonlyArray<string>,
): Types.Attributes | undefined => {
  const kept = R.filter(attributes, (_, key) => keys.includes(key));
  return R.isEmptyRecord(kept) ? undefined : kept;
};

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
 * Requires `UserServiceStore`; `deleteUser` also needs `AccountDeletion` (`accountDeletionLayer`) where the layer is built, and fails without it.
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
      attributes: Types.Attributes,
    ) => Effect.Effect<
      Types.User,
      Errors.AuthError | Errors.UserNotFoundError | Errors.InvalidInputError
    >;

    readonly updateUser: (
      userId: string,
      updates: UpdateUserInput,
    ) => Effect.Effect<Types.User, Errors.AuthError | Errors.UserNotFoundError>;

    /**
     * Delete the user and everything the account holds (#601), through the
     * `AccountDeletion` service in the context (`accountDeletionLayer`): the
     * user's credentials and tokens, the unspent magic links and one-time
     * codes sent to its addresses, its sessions, its identifiers, and the
     * user row last.
     *
     * Without an `AccountDeletion` where this layer is built it fails with
     * `AuthError` and deletes nothing: it never deletes the user row alone,
     * which would leave every credential naming a user who no longer exists.
     */
    readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * The attributes {@link UserServiceConfig.serverOnlyAttributes} declares
     * server-only: the authorization-bearing ones. The session cookie cache
     * never snapshots a user who holds one (see `SessionCookieCache`). An
     * implementation that leaves it unset is read as
     * {@link DEFAULT_SERVER_ONLY_ATTRIBUTES}.
     */
    readonly serverOnlyAttributes?: ReadonlyArray<string> | undefined;
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
    const accountDeletion = yield* Effect.serviceOption(AccountDeletion);
    const serverOnlyAttributes = config?.serverOnlyAttributes ?? DEFAULT_SERVER_ONLY_ATTRIBUTES;
    const serverOnly = HashSet.fromIterable(serverOnlyAttributes);

    return {
      serverOnlyAttributes,
      getUser: Effect.fn("UserService.getUser")((userId: string) => getUserOrFail(store, userId)),

      updateUserAttributes: Effect.fn("UserService.updateUserAttributes")(function* (
        userId: string,
        attributes: Types.Attributes,
      ) {
        const refused = Option.getOrUndefined(
          Arr.findFirst(R.keys<string, Types.Json>(attributes), (key) =>
            HashSet.has(serverOnly, key),
          ),
        );
        if (refused !== undefined) {
          return yield* new Errors.InvalidInputError({
            message: `"${refused}" is a server-only attribute and cannot be set here`,
            field: refused,
          });
        }
        const existing = yield* getUserOrFail(store, userId);

        const updated: Types.User = {
          ...existing,
          updatedAt: yield* DateTime.nowAsDate,
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
          updatedAt: yield* DateTime.nowAsDate,
        };

        return yield* store.update(updated);
      }),

      deleteUser: Effect.fn("UserService.deleteUser")((userId: string) =>
        Option.match(accountDeletion, {
          onNone: () =>
            Effect.fail(
              new Errors.AuthError({
                message:
                  "UserService.deleteUser deletes an account through AccountDeletion: provide accountDeletionLayer where UserService is built",
              }),
            ),
          onSome: (deletion) => deletion.deleteUser(userId),
        }),
      ),
    };
  });
