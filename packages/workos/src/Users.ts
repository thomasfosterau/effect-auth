/**
 * Users and their one email identifier, read from WorkOS: the core's
 * `UserStore` and `IdentifierStore` over `/user_management/users`. WorkOS
 * holds one email per user and no identifier objects, so an identifier's id is
 * derived from the user's, and a second email, a username or a phone number is
 * refused.
 *
 * @since 0.1.0
 */
import * as Arr from "effect/Array";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Layer from "effect/Layer";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import * as Auth from "@thomasfosterau/effect-auth";
import { instant, List, WireUser } from "./Schemas.ts";
import { path, toAuthError, unsupported, WorkOSClient, type WorkOSError } from "./WorkOS.ts";

/**
 * The attribute keys this package writes on a `User`, under `workos.`.
 *
 * @since 0.1.0
 * @category constants
 */
export const UserAttribute = {
  email: "workos.email",
  emailVerified: "workos.emailVerified",
  externalId: "workos.externalId",
  metadata: "workos.metadata",
  lastSignInAt: "workos.lastSignInAt",
} as const;

/**
 * A WorkOS user as a core `User`.
 *
 * @since 0.1.0
 * @category mapping
 */
export const toUser = (user: WireUser): Auth.Types.User => {
  const name =
    user.name ?? ([user.first_name, user.last_name].filter(Boolean).join(" ") || undefined);
  return {
    id: user.id,
    ...(name !== undefined && { name }),
    ...(user.profile_picture_url != null && { image: user.profile_picture_url }),
    createdAt: instant(user.created_at),
    updatedAt: instant(user.updated_at),
    attributes: {
      [UserAttribute.email]: user.email,
      [UserAttribute.emailVerified]: user.email_verified,
      ...(user.external_id != null && { [UserAttribute.externalId]: user.external_id }),
      ...(user.metadata != null && { [UserAttribute.metadata]: { ...user.metadata } }),
      ...(user.last_sign_in_at != null && { [UserAttribute.lastSignInAt]: user.last_sign_in_at }),
    },
  };
};

const IDENTIFIER_PREFIX = "workos-email:";

/**
 * A WorkOS user's email as a core `Identifier`.
 *
 * @since 0.1.0
 * @category mapping
 */
export const toIdentifier = (user: WireUser): Auth.Identifier.Identifier => ({
  id: `${IDENTIFIER_PREFIX}${user.id}`,
  userId: user.id,
  type: "email",
  value: Auth.Normalize.normalizeEmail(user.email),
  verified: user.email_verified,
  createdAt: instant(user.created_at),
});

const userIdOf = (identifierId: string): Option.Option<string> =>
  identifierId.startsWith(IDENTIFIER_PREFIX)
    ? Option.some(identifierId.slice(IDENTIFIER_PREFIX.length))
    : Option.none();

/** `None` for a 404, so a store miss reads as one. */
const orNone = <A>(effect: Effect.Effect<A, WorkOSError>) =>
  effect.pipe(
    Effect.asSome,
    Effect.catchTag("WorkOSError", (error) =>
      error.status === 404 ? Effect.succeedNone : Effect.fail(toAuthError(error)),
    ),
  );

const found = (userId: string) => (user: Option.Option<WireUser>) =>
  Option.match(user, {
    onNone: () =>
      Effect.fail(new Auth.Errors.UserNotFoundError({ message: "User not found", userId })),
    onSome: (wire) => Effect.succeed(toUser(wire)),
  });

/**
 * Reads and writes of WorkOS users.
 *
 * @since 0.1.0
 * @category constructors
 */
export const makeUsers = Effect.fn("WorkOS.Users.make")(function* () {
  const workos = yield* WorkOSClient;
  const getWire = (userId: string) =>
    orNone(
      workos.request({
        method: "GET",
        path: path`/user_management/users/${userId}`,
        route: "/user_management/users/{id}",
        schema: WireUser,
      }),
    );
  const byEmail = (email: string) =>
    workos
      .request({
        method: "GET",
        path: "/user_management/users",
        route: "/user_management/users",
        query: { email, limit: "1" },
        schema: List(WireUser),
      })
      .pipe(
        Effect.map((page) => Arr.head(page.data)),
        Effect.mapError(toAuthError),
      );
  const update = (userId: string, body: Schema.JsonObject) =>
    orNone(
      workos.request({
        method: "PUT",
        path: path`/user_management/users/${userId}`,
        route: "/user_management/users/{id}",
        body,
        schema: WireUser,
      }),
    );
  return { getWire, byEmail, update };
});

/**
 * The core `UserStore` over WorkOS.
 *
 * @since 0.1.0
 * @category layers
 */
export const userStoreLayer: Layer.Layer<Auth.UserStore.UserStore, never, WorkOSClient> =
  Layer.effect(
    Auth.UserStore.UserStore,
    Effect.map(makeUsers(), ({ getWire }) => ({
      get: (userId: string) => Effect.map(getWire(userId), Option.map(toUser)),
    })),
  );

/**
 * The core `IdentifierStore` over WorkOS: each user's one email. Changing the
 * address (`replace`) and its verified flag (`setVerified`) write the user;
 * adding or removing an identifier is refused.
 *
 * @since 0.1.0
 * @category layers
 */
export const identifierStoreLayer: Layer.Layer<
  Auth.Identifier.IdentifierStore,
  never,
  WorkOSClient
> = Layer.effect(
  Auth.Identifier.IdentifierStore,
  Effect.map(makeUsers(), ({ getWire, byEmail, update }) => {
    const fromUserId = (userId: string) => Effect.map(getWire(userId), Option.map(toIdentifier));
    return Auth.Identifier.IdentifierStore.of({
      getByValue: (type, value) =>
        type !== "email"
          ? Effect.succeedNone
          : Effect.map(byEmail(value), Option.map(toIdentifier)),
      listByUser: (userId) => Effect.map(fromUserId(userId), Option.toArray),
      create: (identifier) =>
        Effect.fail(
          new Auth.Identifier.IdentifierRefusedError({
            message: "WorkOS holds one email per user; it cannot add another identifier",
            identifierType: identifier.type,
          }),
        ),
      replace: Effect.fn("WorkOS.IdentifierStore.replace")(function* (
        from: Auth.Identifier.Identifier,
        to: Auth.Identifier.Identifier,
      ) {
        const userId = userIdOf(from.id);
        if (Option.isNone(userId) || to.type !== "email") return Option.none();
        const user = yield* update(userId.value, {
          email: to.value,
          email_verified: to.verified,
        });
        return Option.map(user, toIdentifier);
      }),
      setVerified: Effect.fn("WorkOS.IdentifierStore.setVerified")(function* (id: string) {
        const userId = userIdOf(id);
        if (Option.isNone(userId)) return Option.none();
        const user = yield* update(userId.value, { email_verified: true });
        return Option.map(user, toIdentifier);
      }),
      delete: () => Effect.fail(unsupported("Removing a WorkOS user's email")),
      // Deleting the WorkOS user removes its email with it.
      deleteByUser: () => Effect.void,
    });
  }),
);

/**
 * The core `UserService` over WorkOS: `name` and `image` map to WorkOS's
 * `first_name` / `last_name` and are written there; WorkOS has no free-form
 * attribute bag, so `updateUserAttributes` writes string values to
 * `metadata` and refuses any other value. `deleteUser` deletes the WorkOS
 * user, which ends its sessions; core stores keyed by the user id (API keys
 * and the like) are the app's to clear, from the `user.deleted` event.
 *
 * @since 0.1.0
 * @category layers
 */
export const userServiceLayer: Layer.Layer<Auth.User.UserService, never, WorkOSClient> =
  Layer.effect(
    Auth.User.UserService,
    Effect.gen(function* () {
      const { getWire, update } = yield* makeUsers();
      const workos = yield* WorkOSClient;
      return Auth.User.UserService.of({
        getUser: (userId) => Effect.flatMap(getWire(userId), found(userId)),
        updateUser: (userId, updates) => {
          const [first, ...rest] = (updates.name ?? "").trim().split(/\s+/);
          return Effect.flatMap(
            update(userId, {
              ...(updates.name !== undefined && {
                first_name: first ?? "",
                last_name: rest.join(" "),
              }),
            }),
            found(userId),
          );
        },
        updateUserAttributes: Effect.fn("WorkOS.UserService.updateUserAttributes")(function* (
          userId: string,
          attributes: Auth.Types.Attributes,
        ) {
          const entries = R.toEntries(attributes);
          const invalid = entries.find(([, value]) => !P.isString(value));
          if (invalid !== undefined) {
            return yield* new Auth.Errors.InvalidInputError({
              message: "WorkOS user metadata holds only string values",
              field: invalid[0],
            });
          }
          const current = yield* getWire(userId);
          if (Option.isNone(current)) {
            return yield* new Auth.Errors.UserNotFoundError({ message: "User not found", userId });
          }
          return yield* Effect.flatMap(
            update(userId, {
              metadata: { ...current.value.metadata, ...R.filter(attributes, P.isString) },
            }),
            found(userId),
          );
        }),
        deleteUser: (userId) =>
          workos
            .request({
              method: "DELETE",
              path: path`/user_management/users/${userId}`,
              route: "/user_management/users/{id}",
            })
            .pipe(
              Effect.catchTag("WorkOSError", (error) =>
                error.status === 404 ? Effect.void : Effect.fail(toAuthError(error)),
              ),
            ),
      });
    }),
  );
