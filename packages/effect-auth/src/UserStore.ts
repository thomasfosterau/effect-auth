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
  refusalAuthError,
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
 * on insert and reports `created: true` ({@link CreateUserResult}), and the
 * claim that follows finds it already there. A store that keeps identifiers in
 * a table of their own ignores the field.
 */
export interface NewUserIdentifier {
  readonly type: IdentifierType;
  /** Normalised, as for every identifier. */
  readonly value: string;
  readonly verified: boolean;
  /** When the handle was verified; set only when {@link verified} is `true`. */
  readonly verifiedAt?: Date | undefined;
}

/**
 * What a store's `createUser` resolves to: the user, and whether this call
 * inserted it.
 *
 * `created` is `true` only when this call inserted a new user. A writer that
 * finds or creates on the address, and returns a user that already existed,
 * reports `false`, and the flow that called it fails with
 * {@link IdentifierTakenError} without writing anything to that user (no
 * password, no linked account, no verified address). The flag is what lets core
 * treat an address the store wrote on insert as the new user's own (see
 * {@link createUserWithIdentifier}), so a writer reports it honestly.
 *
 * When the user already exists, the writer must not modify that row: core sees
 * the flag only after the write, so an `INSERT … ON CONFLICT DO UPDATE` has
 * already copied the caller's fields onto someone else's account. Use a plain
 * `INSERT` and let the unique index on the address fail (the writer fails with
 * `AuthError`; core then reports the address taken when it finds it held), or
 * `INSERT … ON CONFLICT DO NOTHING` followed by a select of the existing row,
 * reported as `created: false`. If that select finds no row (for example under a REPEATABLE READ snapshot that predates the conflicting insert), fail with `AuthError` rather than return an invented user. Never
 * `ON CONFLICT DO UPDATE`.
 */
export interface CreateUserResult {
  readonly user: Types.User;
  /** `true` only when this call inserted `user`; `false` when it returned an existing user. */
  readonly created: boolean;
}

const takenError = (identifier: NewUserIdentifier): IdentifierTakenError =>
  new IdentifierTakenError({
    message: `This ${identifier.type} is already in use`,
    identifierType: identifier.type,
  });

/**
 * `error`, or an {@link IdentifierTakenError} when another user holds
 * `identifier`. A failed lookup keeps `error`.
 */
const takenOr = <E>(
  store: typeof IdentifierStore.Service,
  identifier: NewUserIdentifier,
  error: E,
): Effect.Effect<never, E | IdentifierTakenError> =>
  Effect.gen(function* () {
    const held = yield* store
      .getByValue(identifier.type, identifier.value)
      .pipe(Effect.orElseSucceed(() => null));
    if (held === null) return yield* Effect.fail(error);
    return yield* takenError(identifier);
  });

/**
 * Create a user with `create` and record the {@link NewUserIdentifier} it was
 * created with, through {@link claimIdentifier}.
 *
 * `create` receives `identifier` to pass on as its input's `identifier` field,
 * and resolves to a {@link CreateUserResult}.
 *
 * - **`created: false`** (the store returned a user that already existed, as a
 *   find-or-create on the address does) fails with
 *   {@link IdentifierTakenError}. Nothing is claimed, and the flow writes
 *   nothing to that user.
 * - **`created: true`**: the claim runs. When the store wrote the handle into
 *   the user row on insert, the claim finds it already held by this new user:
 *   that is the claim succeeding, not a conflict, and the result carries the
 *   held record. A held record that is unverified while `identifier` says
 *   verified is marked verified, so the user ends up in the state the flow
 *   asked for.
 *
 * A handle another user holds fails with {@link IdentifierTakenError}, both when
 * the claim loses to it and when `create` fails with `AuthError` because the
 * store's unique index on the row's address rejected the insert. Any other
 * failure of `create` passes through, as does an `AuthError` when the address
 * is not held or the lookup fails. As with {@link claimIdentifier}, a user
 * created before the claim fails is left without the handle.
 */
export const createUserWithIdentifier = <E, R>(
  store: typeof IdentifierStore.Service,
  identifier: NewUserIdentifier,
  create: (identifier: NewUserIdentifier) => Effect.Effect<CreateUserResult, E, R>,
): Effect.Effect<
  { readonly user: Types.User; readonly identifier: Identifier },
  E | Errors.AuthError | IdentifierTakenError,
  R
> =>
  Effect.gen(function* () {
    const { user, created } = yield* create(identifier).pipe(
      Effect.catchIf(
        (error): error is E & Errors.AuthError => error instanceof Errors.AuthError,
        (error) => takenOr(store, identifier, error),
      ),
    );
    // Only a fresh insert may treat the address it holds as its own.
    if (!created) return yield* takenError(identifier);
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
      Effect.catchTags({
        IdentifierTakenError: (taken) =>
          Effect.gen(function* () {
            const held = yield* store.getByValue(identifier.type, identifier.value);
            if (held === null || held.userId !== user.id) return yield* taken;
            if (!identifier.verified || held.verified) return held;
            const verified = yield* store.setVerified(held.id, identifier.verifiedAt ?? new Date());
            return verified ?? held;
          }),
        // A store that cannot hold the first identifier cannot serve this
        // sign-up at all: a wiring fault, not a request the client can fix.
        IdentifierRefusedError: (error) => Effect.fail(refusalAuthError(error)),
      }),
    );
    return { user, identifier: claimed };
  });
