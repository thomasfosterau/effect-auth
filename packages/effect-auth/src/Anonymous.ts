/**
 * Anonymous (guest) sign-in: a real user and session without credentials,
 * marked `attributes.isAnonymous` ({@link isAnonymousUser}) and holding no
 * identifiers. After the guest signs up, the app calls {@link
 * AnonymousService.linkAccount}, whose callback migrates their data before the
 * anonymous user is deleted.
 */
import { Clock, Context, Effect, Layer, MutableHashMap, MutableHashSet } from "effect";
import { makeAmortizedPrune } from "./AmortizedPrune.ts";
import * as Option from "effect/Option";
import { AccountManagementStore } from "./AccountManagement.ts";
import * as Errors from "./Errors.ts";
import type * as Types from "./Types.ts";
import { IdentifierStore } from "./Identifier.ts";
import { SessionService } from "./SessionService.ts";
import { type HookError } from "./Hooks.ts";
import { purgeUser, userPurgeStores } from "./UserPurge.ts";

/**
 * Persistence for anonymous users. The implementer generates an id and sets
 * `attributes.isAnonymous: true`; anonymous users hold no identifiers.
 */
export class AnonymousUserStore extends Context.Service<
  AnonymousUserStore,
  {
    readonly createAnonymousUser: Effect.Effect<Types.User, Errors.AuthError>;
    readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/AnonymousUserStore") {}

/** Configuration for {@link AnonymousService}. */
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

/**
 * The anonymous user and the session issued for them by {@link AnonymousService.signInAnonymous}.
 */
export interface AnonymousResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  /** The raw session token, the credential the client presents; `session.id` is its digest. */
  readonly token: string;
}

/**
 * Guest sign-in: creates users marked `attributes.isAnonymous` and upgrades them to real accounts with {@link AnonymousService.linkAccount}.
 *
 * Requires `AnonymousUserStore` and `SessionService`.
 */
export class AnonymousService extends Context.Service<
  AnonymousService,
  {
    /** Create an anonymous user and an authenticated session for them. */
    readonly signInAnonymous: (
      sessionAttributes?: Types.Attributes,
    ) => Effect.Effect<AnonymousResult, Errors.AuthError | HookError>;

    /**
     * Link an anonymous identity to a real account: run the `linkAccount`
     * callback (app data migration), then delete the anonymous user and
     * whatever it still holds: the credentials and tokens in the
     * user-keyed stores present where this layer is built, its sessions, any
     * identifiers (when an `IdentifierStore` is present), and the user row
     * last.
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

/** How long `linkAccount` remembers a completed link, for idempotency. */
const LINKED_GUEST_MEMORY_MS = 60 * 60 * 1000;

const make = (
  config: AnonymousConfig = {},
): Effect.Effect<typeof AnonymousService.Service, never, AnonymousUserStore | SessionService> =>
  Effect.gen(function* () {
    const store = yield* AnonymousUserStore;
    const sessionManager = yield* SessionService;
    const purgeServices = {
      ...(yield* userPurgeStores),
      accountTokens: Option.getOrUndefined(yield* Effect.serviceOption(AccountManagementStore)),
      identifiers: Option.getOrUndefined(yield* Effect.serviceOption(IdentifierStore)),
      revokeSessions: sessionManager.invalidateUserSessions,
      deleteUser: store.deleteUser,
    };

    // Tracks IDs currently being linked (single-flight) and already linked
    // (idempotency). Both are needed: inFlight prevents concurrent races;
    // done prevents re-running a completed migration on a repeated call. A
    // linked guest is deleted, so only a repeat soon after can name it again:
    // `done` forgets a link after an hour, pruned as it grows.
    const inFlight = MutableHashSet.empty<string>();
    const done = MutableHashMap.empty<string, number>();
    const pruneDone = makeAmortizedPrune(done);

    return {
      signInAnonymous: Effect.fn("AnonymousService.signInAnonymous")(function* (
        sessionAttributes?: Types.Attributes,
      ) {
        const user = yield* store.createAnonymousUser;
        const { session, token } = yield* sessionManager.createSession(user.id, sessionAttributes);

        return { user, session, token };
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
        if (MutableHashMap.has(done, anonymousUser.id)) return yield* Effect.void;

        // Single-flight: another fiber is already migrating this user.
        if (MutableHashSet.has(inFlight, anonymousUser.id)) return yield* Effect.void;

        MutableHashSet.add(inFlight, anonymousUser.id);
        return yield* Effect.gen(function* () {
          if (config.linkAccount !== undefined) {
            yield* config.linkAccount({ anonymousUser, newUser });
          }

          yield* purgeUser(purgeServices, anonymousUser.id);

          const linkedAt = yield* Clock.currentTimeMillis;
          pruneDone((at) => at + LINKED_GUEST_MEMORY_MS <= linkedAt);
          MutableHashMap.set(done, anonymousUser.id, linkedAt);
        }).pipe(
          Effect.ensuring(Effect.sync(() => MutableHashSet.remove(inFlight, anonymousUser.id))),
        );
      }),
    };
  });
