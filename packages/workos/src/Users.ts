/**
 * Users and their one email identifier, read from WorkOS: the core's
 * `UserStore` and `IdentifierStore` over `/user_management/users`. WorkOS
 * holds one email per user and no identifier objects, so an identifier's id is
 * derived from the user's, and a second email, a username or a phone number is
 * refused.
 *
 * @since 0.1.0
 */
import { Effect, Layer } from "effect";
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
export const toUser = (user: WireUser): Auth.User => {
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
export const toIdentifier = (user: WireUser): Auth.Identifier => ({
  id: `${IDENTIFIER_PREFIX}${user.id}`,
  userId: user.id,
  type: "email",
  value: Auth.normalizeEmail(user.email),
  verified: user.email_verified,
  createdAt: instant(user.created_at),
});

const userIdOf = (identifierId: string): string | undefined =>
  identifierId.startsWith(IDENTIFIER_PREFIX)
    ? identifierId.slice(IDENTIFIER_PREFIX.length)
    : undefined;

/** `null` for a 404, so a store miss reads as one. */
const orNull = <A>(effect: Effect.Effect<A, WorkOSError>) =>
  effect.pipe(
    Effect.catchTag("WorkOSError", (error) =>
      error.status === 404 ? Effect.succeed(null) : Effect.fail(toAuthError(error)),
    ),
  );

/**
 * Reads and writes of WorkOS users.
 *
 * @since 0.1.0
 * @category constructors
 */
export const makeUsers = Effect.fn("WorkOS.Users.make")(function* () {
  const workos = yield* WorkOSClient;
  const getWire = (userId: string) =>
    orNull(
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
        Effect.map((page) => page.data[0] ?? null),
        Effect.mapError(toAuthError),
      );
  const update = (userId: string, body: Schema.JsonObject) =>
    orNull(
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
export const userStoreLayer: Layer.Layer<Auth.UserStore, never, WorkOSClient> = Layer.effect(
  Auth.UserStore,
  Effect.map(makeUsers(), ({ getWire }) => ({
    get: (userId: string) =>
      Effect.map(getWire(userId), (user) => (user === null ? null : toUser(user))),
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
export const identifierStoreLayer: Layer.Layer<Auth.IdentifierStore, never, WorkOSClient> =
  Layer.effect(
    Auth.IdentifierStore,
    Effect.map(makeUsers(), ({ getWire, byEmail, update }) => {
      const fromUserId = (userId: string | undefined) =>
        userId === undefined
          ? Effect.succeed(null)
          : Effect.map(getWire(userId), (user) => (user === null ? null : toIdentifier(user)));
      return Auth.IdentifierStore.of({
        getByValue: (type, value) =>
          type !== "email"
            ? Effect.succeed(null)
            : Effect.map(byEmail(value), (user) => (user === null ? null : toIdentifier(user))),
        listByUser: (userId) =>
          Effect.map(fromUserId(userId), (identifier) => (identifier === null ? [] : [identifier])),
        create: (identifier) =>
          Effect.fail(
            new Auth.IdentifierRefusedError({
              message: "WorkOS holds one email per user; it cannot add another identifier",
              identifierType: identifier.type,
            }),
          ),
        replace: Effect.fn("WorkOS.IdentifierStore.replace")(function* (
          from: Auth.Identifier,
          to: Auth.Identifier,
        ) {
          const userId = userIdOf(from.id);
          if (userId === undefined || to.type !== "email") return null;
          const user = yield* update(userId, {
            email: to.value,
            email_verified: to.verified,
          });
          return user === null ? null : toIdentifier(user);
        }),
        setVerified: Effect.fn("WorkOS.IdentifierStore.setVerified")(function* (id: string) {
          const userId = userIdOf(id);
          if (userId === undefined) return null;
          const user = yield* update(userId, { email_verified: true });
          return user === null ? null : toIdentifier(user);
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
export const userServiceLayer: Layer.Layer<Auth.UserService, never, WorkOSClient> = Layer.effect(
  Auth.UserService,
  Effect.gen(function* () {
    const { getWire, update } = yield* makeUsers();
    const workos = yield* WorkOSClient;
    const found = (userId: string) => (user: WireUser | null) =>
      user === null
        ? Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId }))
        : Effect.succeed(toUser(user));
    return Auth.UserService.of({
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
        attributes: Auth.Attributes,
      ) {
        const entries = R.toEntries(attributes);
        const invalid = entries.find(([, value]) => !P.isString(value));
        if (invalid !== undefined) {
          return yield* new Auth.InvalidInputError({
            message: "WorkOS user metadata holds only string values",
            field: invalid[0],
          });
        }
        const current = yield* getWire(userId);
        if (current === null) {
          return yield* new Auth.UserNotFoundError({ message: "User not found", userId });
        }
        return yield* Effect.flatMap(
          update(userId, {
            metadata: { ...current.metadata, ...R.filter(attributes, P.isString) },
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
