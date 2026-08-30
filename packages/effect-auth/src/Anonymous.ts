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
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import { SessionService } from "./session/SessionService.ts";
import { type HookError } from "./Hooks.ts";

/**
 * Persistence for anonymous users. The implementer generates an id and a
 * placeholder email, and sets `attributes.isAnonymous: true`.
 */
export class AnonymousUserStore extends Context.Service<
  AnonymousUserStore,
  {
    readonly createAnonymousUser: () => Effect.Effect<Types.User, Errors.AuthError>;
    readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/AnonymousUserStore") {}

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

export class AnonymousService extends Context.Service<
  AnonymousService,
  {
    /** Create an anonymous user and an authenticated session for them. */
    readonly signInAnonymous: (
      sessionAttributes?: Record<string, unknown>,
    ) => Effect.Effect<AnonymousResult, Errors.AuthError | HookError>;

    /**
     * Link an anonymous identity to a real account: run the `linkAccount`
     * callback (app data migration), invalidate all anonymous user sessions,
     * then delete the anonymous user.
     *
     * Rejects with `InvalidInputError` if `anonymousUser` is not an anonymous
     * user or if `anonymousUser.id === newUser.id`. Idempotent: a second call
     * for an already-linked user is a no-op.
     */
    readonly linkAccount: (
      anonymousUser: Types.User,
      newUser: Types.User,
    ) => Effect.Effect<void, Errors.AuthError | Errors.InvalidInputError>;
  }
>()("@effect-auth/AnonymousService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: AnonymousConfig = {}) =>
    Layer.effect(AnonymousService, make(config));
}

/** Whether a user is an anonymous (guest) user. */
export const isAnonymousUser = (user: Types.User): boolean =>
  user.attributes["isAnonymous"] === true;

export const make = (
  config: AnonymousConfig = {},
): Effect.Effect<typeof AnonymousService.Service, never, AnonymousUserStore | SessionService> =>
  Effect.gen(function* () {
    const store = yield* AnonymousUserStore;
    const sessionManager = yield* SessionService;

    // Tracks IDs currently being linked (single-flight) and already linked
    // (idempotency). Both are needed: inFlight prevents concurrent races;
    // done prevents re-running a completed migration on a second call.
    const inFlight = new Set<string>();
    const done = new Set<string>();

    return {
      signInAnonymous: Effect.fn("AnonymousService.signInAnonymous")(function* (
        sessionAttributes?: Record<string, unknown>,
      ) {
        const user = yield* store.createAnonymousUser();
        const session = yield* sessionManager.createSession(user.id, sessionAttributes);

        return { user, session };
      }),

      linkAccount: Effect.fn("AnonymousService.linkAccount")(function* (
        anonymousUser: Types.User,
        newUser: Types.User,
      ) {
        if (!isAnonymousUser(anonymousUser)) {
          return yield* new Errors.InvalidInputError({
            message: "The provided user is not an anonymous user",
            field: "anonymousUser",
          });
        }

        if (anonymousUser.id === newUser.id) {
          return yield* new Errors.InvalidInputError({
            message: "Cannot link an anonymous account to itself",
            field: "newUser",
          });
        }

        // Idempotent: already successfully linked.
        if (done.has(anonymousUser.id)) return;

        // Single-flight: another fiber is already migrating this user.
        if (inFlight.has(anonymousUser.id)) return;

        inFlight.add(anonymousUser.id);
        try {
          if (config.linkAccount !== undefined) {
            yield* config.linkAccount({ anonymousUser, newUser });
          }

          yield* sessionManager.invalidateUserSessions(anonymousUser.id);
          yield* store.deleteUser(anonymousUser.id);

          done.add(anonymousUser.id);
        } finally {
          inFlight.delete(anonymousUser.id);
        }
      }),
    };
  });
