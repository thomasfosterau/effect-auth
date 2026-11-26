/**
 * Users and identifiers over BetterAuth's `user` table: the core's
 * `UserStore`, `UserServiceStore`, `AccountDeletion` and a read-only
 * `IdentifierStore`.
 *
 * @since 0.1.0
 */
import { Effect, Layer } from "effect";
import * as Eq from "effect/Equal";
import * as HashSet from "effect/HashSet";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  adapterCall,
  columnsOf,
  type BetterAuthContext,
  BetterAuthInstance,
  type BetterAuthUser,
  type Columns,
} from "./BetterAuth.ts";
import { identifierId, identifiersOf, parseIdentifierId, toUser } from "./Convert.ts";

/**
 * User columns `UserServiceStore.update` never writes: the record's own
 * fields and the columns behind the derived identifiers, which change only
 * through BetterAuth's own flows (`changeEmail` and the plugins' verification).
 */
const PROTECTED_USER_COLUMNS = HashSet.make(
  "id",
  "createdAt",
  "updatedAt",
  "email",
  "emailVerified",
  "username",
  "displayUsername",
  "phoneNumber",
  "phoneNumberVerified",
);

const findUser = (context: BetterAuthContext, userId: string) =>
  adapterCall("findUserById", () => context.internalAdapter.findUserById(userId));

const hasColumn = (context: BetterAuthContext, column: string): boolean =>
  columnsOf(context, "user").includes(column);

/**
 * The core's `UserStore` over `internalAdapter.findUserById`.
 *
 * @since 0.1.0
 * @category layers
 */
export const userStoreLayer: Layer.Layer<Auth.UserStore, never, BetterAuthInstance> = Layer.effect(
  Auth.UserStore,
  Effect.map(Effect.service(BetterAuthInstance), ({ context }) => ({
    get: (userId: string) =>
      Effect.map(findUser(context, userId), (user) =>
        Option.map(Option.fromNullishOr(user), toUser),
      ),
  })),
);

/**
 * The fields of `next` that differ from `current`, as BetterAuth columns. A
 * changed attribute must be a column BetterAuth declares (the admin plugin's,
 * `additionalFields`) and not one it owns; anything else is `AuthError`.
 */
const changedColumns = (
  context: BetterAuthContext,
  current: Auth.User,
  next: Auth.User,
): Effect.Effect<Columns, Auth.AuthError> => {
  const changedAttributes = R.filter(
    next.attributes,
    (value, key) => !Eq.equals(value, current.attributes[key]),
  );
  const refused = Arr.findFirst(
    R.keys(changedAttributes),
    (key) => !hasColumn(context, key) || HashSet.has(PROTECTED_USER_COLUMNS, key),
  );
  if (Option.isSome(refused)) {
    return Effect.fail(
      new Auth.AuthError({
        message: `"${refused.value}" is not a user column BetterAuth declares, or is one it owns`,
      }),
    );
  }
  return Effect.succeed({
    ...changedAttributes,
    ...(next.name !== current.name && { name: next.name ?? null }),
    ...(next.image !== current.image && { image: next.image ?? null }),
  });
};

/**
 * The core's `UserServiceStore` over BetterAuth, so `Auth.UserService.layer()`
 * runs on top: `update` writes only the fields that changed, and only columns
 * BetterAuth declares; `delete` removes the user's sessions, then the user
 * (BetterAuth deletes its `account` rows with it).
 *
 * @since 0.1.0
 * @category layers
 */
export const userServiceStoreLayer: Layer.Layer<Auth.UserServiceStore, never, BetterAuthInstance> =
  Layer.effect(
    Auth.UserServiceStore,
    Effect.map(Effect.service(BetterAuthInstance), ({ context }) => ({
      get: (userId: string) =>
        Effect.map(findUser(context, userId), (user) =>
          Option.map(Option.fromNullishOr(user), toUser),
        ),
      update: Effect.fn("UserServiceStore.update")(function* (user: Auth.User) {
        const row = yield* findUser(context, user.id);
        if (row === null) {
          return yield* new Auth.AuthError({
            message: `No BetterAuth user ${user.id} to update`,
          });
        }
        const changes = yield* changedColumns(context, toUser(row), user);
        if (R.isEmptyRecord(changes)) return toUser(row);
        const updated = yield* adapterCall("updateUser", () =>
          context.internalAdapter.updateUser(user.id, { ...changes, updatedAt: user.updatedAt }),
        );
        if (updated === null) {
          return yield* new Auth.AuthError({
            message: `No BetterAuth user ${user.id} to update`,
          });
        }
        return toUser(updated);
      }),
      delete: (userId: string) => deleteUser(context, userId),
    })),
  );

const deleteUser = (context: BetterAuthContext, userId: string) =>
  Effect.gen(function* () {
    yield* adapterCall("deleteUserSessions", () =>
      context.internalAdapter.deleteUserSessions(userId),
    );
    yield* adapterCall("deleteUser", () => context.internalAdapter.deleteUser(userId));
  });

/**
 * The core's `AccountDeletion` over BetterAuth, which `UserService.deleteUser`
 * delegates to: the user's sessions, then the user and its `account` rows.
 * It skips `/delete-user`'s fresh-session and verification checks, so it is
 * for trusted server code. Rows BetterAuth's plugins keep elsewhere
 * (organization members, two-factor, passkeys) go only as far as BetterAuth's
 * own `deleteUser` takes them.
 *
 * @since 0.1.0
 * @category layers
 */
export const accountDeletionLayer: Layer.Layer<Auth.AccountDeletion, never, BetterAuthInstance> =
  Layer.effect(
    Auth.AccountDeletion,
    Effect.map(Effect.service(BetterAuthInstance), ({ context }) => ({
      deleteUser: (userId: string) => deleteUser(context, userId),
    })),
  );

const refusedWrite = (type: Auth.IdentifierType) =>
  new Auth.IdentifierRefusedError({
    message: `Identifiers are BetterAuth's columns: change a ${type} through BetterAuth's own flow, which verifies it`,
    identifierType: type,
  });

const refusedStoreWrite = (method: string) =>
  new Auth.AuthError({
    message: `IdentifierStore.${method} is refused over BetterAuth: identifiers change only through BetterAuth's own flows`,
  });

/** The column a by-value lookup reads for each identifier type. */
const VALUE_COLUMN = { email: "email", username: "username", phone: "phoneNumber" } as const;

/**
 * A read-only `IdentifierStore`. Identifiers are derived from the user row
 * (`email` and `emailVerified`; `username` from the `username()` plugin;
 * `phoneNumber` and `phoneNumberVerified` from the `phoneNumber()` plugin),
 * each with the id `${userId}:${type}`.
 *
 * Writes that would skip BetterAuth's checks are refused: `create` fails with
 * `IdentifierRefusedError`, and `replace`, `delete` and `deleteByUser` with
 * `AuthError`, because an email change that skips verification is an
 * account-takeover vector. `setVerified` marks the email (or phone) verified.
 *
 * @since 0.1.0
 * @category layers
 */
export const identifierStoreLayer: Layer.Layer<Auth.IdentifierStore, never, BetterAuthInstance> =
  Layer.effect(
    Auth.IdentifierStore,
    Effect.map(Effect.service(BetterAuthInstance), ({ context }) => {
      const identifierOf = (user: BetterAuthUser | null, type: Auth.IdentifierType) =>
        user === null
          ? Option.none()
          : Arr.findFirst(identifiersOf(user), (id) => id.type === type);

      const byValue = (type: Auth.IdentifierType, value: string) => {
        if (type === "email") {
          return Effect.map(
            adapterCall("findUserByEmail", () => context.internalAdapter.findUserByEmail(value)),
            (found) => found?.user ?? null,
          );
        }
        const column = VALUE_COLUMN[type];
        if (!hasColumn(context, column)) return Effect.succeed(null);
        return adapterCall(`findOne(user.${column})`, () =>
          context.adapter.findOne<BetterAuthUser>({
            model: "user",
            where: [{ field: column, value }],
          }),
        );
      };

      return {
        getByValue: (type: Auth.IdentifierType, value: string) =>
          Effect.map(byValue(type, value), (user) => identifierOf(user, type)),

        listByUser: (userId: string) =>
          Effect.map(findUser(context, userId), (user) =>
            user === null ? [] : identifiersOf(user),
          ),

        create: (identifier: Auth.Identifier) => Effect.fail(refusedWrite(identifier.type)),
        replace: () => Effect.fail(refusedStoreWrite("replace")),
        delete: () => Effect.fail(refusedStoreWrite("delete")),
        deleteByUser: () => Effect.fail(refusedStoreWrite("deleteByUser")),

        setVerified: Effect.fn("IdentifierStore.setVerified")(function* (id: string) {
          const parsed = parseIdentifierId(id);
          if (parsed === undefined) return Option.none();
          const user = yield* findUser(context, parsed.userId);
          const current = identifierOf(user, parsed.type);
          if (
            Option.isNone(current) ||
            current.value.id !== identifierId(parsed.userId, parsed.type)
          ) {
            return Option.none();
          }
          if (current.value.verified || parsed.type === "username") return current;
          const column = parsed.type === "email" ? "emailVerified" : "phoneNumberVerified";
          const updated = yield* adapterCall("updateUser", () =>
            context.internalAdapter.updateUser(parsed.userId, { [column]: true }),
          );
          return identifierOf(updated, parsed.type);
        }),
      };
    }),
  );

/**
 * Every layer in this file, plus `Auth.UserService` on top, over one
 * BetterAuth instance.
 *
 * @since 0.1.0
 * @category layers
 */
export const usersLayer = (config?: {
  readonly serverOnlyAttributes?: ReadonlyArray<string>;
}): Layer.Layer<
  | Auth.UserService
  | Auth.UserStore
  | Auth.UserServiceStore
  | Auth.AccountDeletion
  | Auth.IdentifierStore,
  never,
  BetterAuthInstance
> =>
  Auth.UserService.layer(config).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        userServiceStoreLayer,
        accountDeletionLayer,
        userStoreLayer,
        identifierStoreLayer,
      ),
    ),
  );
