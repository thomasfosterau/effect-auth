/**
 * Anonymous (guest) authentication.
 *
 * Lets a visitor obtain a real user + session without credentials, then link
 * that identity to a full account on sign-up. Follows the house module pattern
 * (store tag + `Context.Service` tag + `make*` + `*ServiceLayer`), closely
 * mirroring `MagicLink.ts`.
 *
 * Convention: anonymous users carry `attributes.isAnonymous === true` and a
 * placeholder email (e.g. `anon-<id>@anonymous.local`) chosen by the store
 * implementer. Use {@link isAnonymousUser} to detect them.
 *
 * Account linking is triggered explicitly by the app/HTTP layer (hooks operate
 * on input values and cannot see the current session): after a guest signs up
 * for a real account, call {@link AnonymousService.linkAccount} with the
 * anonymous user and the freshly-created user; the `linkAccount` config
 * callback migrates any data, then the anonymous user is deleted.
 */
import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.js";
import type * as Types from "./Types.js";
import { SessionManagerTag } from "./Session.js";
import { Hooks, type HookError } from "./Hooks.js";

/**
 * Persistence for anonymous users. The implementer generates an id and a
 * placeholder email, and sets `attributes.isAnonymous: true`.
 */
export interface AnonymousUserStore {
  readonly createAnonymousUser: () => Effect.Effect<Types.User, Errors.AuthError>;
  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

export class AnonymousUserStoreTag extends Context.Service<
  AnonymousUserStoreTag,
  AnonymousUserStore
>()("@effect-auth/AnonymousUserStore") {}

export const AnonymousUserStore = AnonymousUserStoreTag;

export interface AnonymousConfig {
  /**
   * Migrate data from the anonymous user to the newly-created real user during
   * {@link AnonymousService.linkAccount}. Runs before the anonymous user is
   * deleted, so related rows can still be resolved.
   */
  readonly linkAccount?: (params: {
    readonly anonymousUser: Types.User;
    readonly newUser: Types.User;
  }) => Effect.Effect<void, Errors.AuthError>;
}

export interface AnonymousResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

export interface AnonymousService {
  /** Create an anonymous user and an authenticated session for them. */
  readonly signInAnonymous: (
    sessionAttributes?: Record<string, unknown>,
  ) => Effect.Effect<
    AnonymousResult,
    Errors.AuthError | HookError,
    AnonymousUserStoreTag | SessionManagerTag | Hooks
  >;

  /**
   * Link an anonymous identity to a real account: run the `linkAccount`
   * callback (app data migration), then delete the anonymous user.
   */
  readonly linkAccount: (
    anonymousUser: Types.User,
    newUser: Types.User,
  ) => Effect.Effect<void, Errors.AuthError, AnonymousUserStoreTag>;
}

export class AnonymousServiceTag extends Context.Service<AnonymousServiceTag, AnonymousService>()(
  "@effect-auth/AnonymousService",
) {}

export const AnonymousService = AnonymousServiceTag;

/** Whether a user is an anonymous (guest) user. */
export const isAnonymousUser = (user: Types.User): boolean =>
  user.attributes["isAnonymous"] === true;

export const makeAnonymousService = (
  config: AnonymousConfig = {},
): Effect.Effect<AnonymousService, never> =>
  Effect.sync(
    (): AnonymousService => ({
      signInAnonymous: (sessionAttributes) =>
        Effect.gen(function* () {
          const store = yield* AnonymousUserStoreTag;
          const sessionManager = yield* SessionManagerTag;

          const user = yield* store.createAnonymousUser();
          const session = yield* sessionManager.createSession(user.id, sessionAttributes);

          return { user, session };
        }),

      linkAccount: (anonymousUser, newUser) =>
        Effect.gen(function* () {
          const store = yield* AnonymousUserStoreTag;
          if (config.linkAccount !== undefined) {
            yield* config.linkAccount({ anonymousUser, newUser });
          }
          yield* store.deleteUser(anonymousUser.id);
        }),
    }),
  );

export const AnonymousServiceLayer = (config?: AnonymousConfig) =>
  Layer.effect(AnonymousServiceTag, makeAnonymousService(config));
