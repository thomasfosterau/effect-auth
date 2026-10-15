import { Context, Effect } from "effect";
import type * as Types from "./Types.ts";
import * as Errors from "./Errors.ts";
import {
  claimIdentifier,
  type Identifier,
  IdentifierStore,
  IdentifierTakenError,
  type IdentifierType,
  makeIdentifier,
} from "./Identifier.ts";

/**
 * User store interface for managing user persistence
 * Users should implement this interface with their preferred storage backend
 */
export class UserStore extends Context.Service<
  UserStore,
  {
    /**
     * Get a user by ID, or `null` when no such user exists.
     */
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  }
>()("@effect-auth/UserStore") {}

/**
 * The login handle a user is created with, as a flow passes it to its store's
 * `createUser` (the `identifier` field of `CreateUserInput` and of the other
 * flows' create inputs).
 *
 * Core records the handle as an {@link Identifier} through {@link IdentifierStore}
 * straight after the user row exists ({@link createUserWithIdentifier}). A store
 * that keeps the address on the user row itself, such as effect-auth-drizzle's
 * single-table store with a `NOT NULL` `email` column, writes it into the row
 * on insert, and the claim that follows finds it already there. A store that
 * keeps identifiers in a table of their own ignores the field.
 */
export interface NewUserIdentifier {
  readonly type: IdentifierType;
  /** Normalised, as for every identifier. */
  readonly value: string;
  readonly verified: boolean;
  /** When the handle was verified; set only when {@link verified} is `true`. */
  readonly verifiedAt?: Date | undefined;
}

/** `error`, or an {@link IdentifierTakenError} when another user holds `identifier`. */
const takenOr = <E>(
  store: typeof IdentifierStore.Service,
  identifier: NewUserIdentifier,
  error: E,
): Effect.Effect<never, E | Errors.AuthError | IdentifierTakenError> =>
  Effect.gen(function* () {
    const held = yield* store.getByValue(identifier.type, identifier.value);
    if (held === null) return yield* Effect.fail(error);
    return yield* new IdentifierTakenError({
      message: `This ${identifier.type} is already in use`,
      identifierType: identifier.type,
    });
  });

/**
 * Create a user with `create` and record the {@link NewUserIdentifier} it was
 * created with, through {@link claimIdentifier}.
 *
 * `create` receives `identifier` to pass on as its input's `identifier` field.
 * When the store wrote the handle into the user row on insert, the claim finds
 * it already held by this same user: that is the claim succeeding, not a
 * conflict, and the result carries the held record. A held record that is
 * unverified while `identifier` says verified is marked verified, so the user
 * ends up in the state the flow asked for.
 *
 * A handle another user holds fails with {@link IdentifierTakenError}, both when
 * the claim loses to it and when `create` fails with `AuthError` because the
 * store's unique index on the row's address rejected the insert. Any other
 * failure of `create` passes through. As with {@link claimIdentifier}, a user
 * created before the claim fails is left without the handle.
 */
export const createUserWithIdentifier = <E, R>(
  store: typeof IdentifierStore.Service,
  identifier: NewUserIdentifier,
  create: (identifier: NewUserIdentifier) => Effect.Effect<Types.User, E, R>,
): Effect.Effect<
  { readonly user: Types.User; readonly identifier: Identifier },
  E | Errors.AuthError | IdentifierTakenError,
  R
> =>
  Effect.gen(function* () {
    const user = yield* create(identifier).pipe(
      Effect.catchIf(
        (error): error is E & Errors.AuthError => error instanceof Errors.AuthError,
        (error) => takenOr(store, identifier, error),
      ),
    );
    const claimed = yield* claimIdentifier(
      store,
      makeIdentifier({
        userId: user.id,
        type: identifier.type,
        value: identifier.value,
        verified: identifier.verified,
        ...(identifier.verifiedAt !== undefined && { verifiedAt: identifier.verifiedAt }),
      }),
    ).pipe(
      Effect.catchTag("IdentifierTakenError", (taken) =>
        Effect.gen(function* () {
          const held = yield* store.getByValue(identifier.type, identifier.value);
          if (held === null || held.userId !== user.id) return yield* taken;
          if (!identifier.verified || held.verified) return held;
          const verified = yield* store.setVerified(held.id, identifier.verifiedAt ?? new Date());
          return verified ?? held;
        }),
      ),
    );
    return { user, identifier: claimed };
  });
