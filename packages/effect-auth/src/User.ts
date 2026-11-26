import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as HashSet from "effect/HashSet";
import * as Layer from "effect/Layer";
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
    readonly get: (userId: string) => Effect.Effect<Option.Option<Types.User>, Errors.AuthError>;

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
 * `signUpAttributes` allow-list names: the ban state
 * ({@link BAN_ATTRIBUTES}), the SCIM provisioning keys (`scimUserName`,
 * `scimDeactivated`, `scimExternalId`, which `ScimService` alone writes), the
 * managed-user stamp (`provisionedBy`, which SSO and SCIM write when they
 * create a user) and the anonymous-user marker (`isAnonymous`, which `AnonymousService` alone
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
  "provisionedBy",
  "isAnonymous",
];

/**
 * A copy of `attributes` without the keys a sign-up never takes from its
 * input: `serverOnly` (the configured
 * {@link UserServiceConfig.serverOnlyAttributes}) and
 * {@link SIGN_UP_PROTECTED_ATTRIBUTES}. `EmailPasswordService.signUp` and
 * `AuthLifecycleService.signUp` apply it to every new user.
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
 * none is: how `POST /users` applies its `signUpAttributes` allow-list.
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

/**
 * A copy of `attributes` without the keys `keys` names: how the HTTP tier
 * leaves its client-hidden attributes out of a user it answers with.
 *
 * @since 0.9.0
 * @category utils
 */
export const withoutAttributes = (
  attributes: Types.Attributes,
  keys: ReadonlyArray<string>,
): Types.Attributes => R.filter(attributes, (_, key) => !keys.includes(key));

export interface UserServiceConfig {
  /**
   * Attribute keys `updateUserAttributes` refuses to write, whoever calls it
   * (default `["role"]`). These are the attributes that carry authority — the
   * rung the guards read above all — so a profile-update path built on
   * `updateUserAttributes` cannot let a user set their own role. Change them
   * through their privileged door instead (`AdminService.setRole` for `role`).
   * Pass `[]` to opt out; {@link SIGN_UP_PROTECTED_ATTRIBUTES} stay refused.
   */
  readonly serverOnlyAttributes?: ReadonlyArray<string>;
}

/** Partial update of a user's first-class profile fields. */
export interface UpdateUserInput {
  readonly name?: string;
  readonly image?: string;
}

/**
 * Reads and updates users: profile fields and the attribute bag, refusing writes to {@link UserServiceConfig.serverOnlyAttributes} and {@link SIGN_UP_PROTECTED_ATTRIBUTES}.
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
     * {@link UserServiceConfig.serverOnlyAttributes} or of
     * {@link SIGN_UP_PROTECTED_ATTRIBUTES} (the ban, SCIM and anonymous-user
     * keys, which their own services write and no config opts out of).
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
     * Delete the user and everything the account holds, through the
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
    readonly serverOnlyAttributes?: ReadonlyArray<string>;
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
  Effect.flatMap(
    store.get(userId),
    Option.match({
      onNone: () =>
        Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId })),
      onSome: Effect.succeed,
    }),
  );

export const make = (
  config?: UserServiceConfig,
): Effect.Effect<typeof UserService.Service, never, UserServiceStore> =>
  Effect.gen(function* () {
    const store = yield* UserServiceStore;
    const accountDeletion = yield* Effect.serviceOption(AccountDeletion);
    const serverOnlyAttributes = config?.serverOnlyAttributes ?? DEFAULT_SERVER_ONLY_ATTRIBUTES;
    // The ban, SCIM and anonymous-user keys are refused whatever the config
    // says, as at sign-up: `AdminService`, `ScimService` and `AnonymousService`
    // write them through the store, never through this method.
    const refusedKeys = HashSet.fromIterable([
      ...serverOnlyAttributes,
      ...SIGN_UP_PROTECTED_ATTRIBUTES,
    ]);

    return {
      serverOnlyAttributes,
      getUser: Effect.fn("UserService.getUser")((userId: string) => getUserOrFail(store, userId)),

      updateUserAttributes: Effect.fn("UserService.updateUserAttributes")(function* (
        userId: string,
        attributes: Types.Attributes,
      ) {
        const refused = Option.getOrUndefined(
          Arr.findFirst(R.keys<string, Types.Json>(attributes), (key) =>
            HashSet.has(refusedKeys, key),
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
