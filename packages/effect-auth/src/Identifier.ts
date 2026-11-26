/**
 * Identifiers: a user's verified or unverified claims to an email address,
 * username or phone number, kept apart from the `User` record, which carries no
 * login handle. Every flow that asks who owns a value goes through the {@link
 * IdentifierStore}.
 */
import { Context, Data, Effect, MutableHashMap, Order } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Errors from "./Errors.ts";
import * as Types from "./Types.ts";

// ---------------------------------------------------------------------------
// Domain type
// ---------------------------------------------------------------------------

/** The three first-class identifier types. */
export type IdentifierType = "email" | "username" | "phone";

/**
 * An `Identifier` is a normalized, globally-unique claim that a user owns a
 * value for a given type.
 *
 * Uniqueness is enforced on `(type, value)` — the same email address cannot
 * belong to two users, and neither can the same username or phone number.
 *
 * `value` is stored in normalized form: email addresses through
 * `normalizeEmail` (trimmed, the local part lower-cased and NFC-normalised, the
 * domain punycoded under UTS 46); usernames are trimmed and lowercased; phone numbers are stored
 * in E.164 form (app policy; the store does not normalize).
 */
export const Identifier = Schema.Struct({
  id: Schema.String,
  userId: Schema.String,
  type: Schema.Literals(["email", "username", "phone"]),
  value: Schema.String,
  verified: Schema.Boolean,
  verifiedAt: Schema.optional(Schema.Date),
  createdAt: Schema.Date,
});
export type Identifier = typeof Identifier.Type;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Raised by services that need a specific identifier and find none. */
export class IdentifierNotFoundError extends Data.TaggedError("IdentifierNotFoundError")<{
  readonly message: string;
  readonly id?: string;
}> {}

/**
 * Raised by {@link claimIdentifier} when the `(type, value)` pair already
 * belongs to another user. The value is deliberately omitted so the error can
 * be logged without leaking the handle.
 */
export class IdentifierTakenError extends Data.TaggedError("IdentifierTakenError")<{
  readonly message: string;
  readonly identifierType: IdentifierType;
}> {}

/**
 * Raised by an {@link IdentifierStore} `create` that refuses an identifier it
 * cannot hold, on purpose rather than through a failure: a store that keeps one
 * email per user refuses a second one, and a store that keeps emails only
 * refuses any other type. The request is well-formed and no other user holds
 * the value; this store's shape rules it out. The value is omitted, as in
 * {@link IdentifierTakenError}.
 */
export class IdentifierRefusedError extends Data.TaggedError("IdentifierRefusedError")<{
  readonly message: string;
  readonly identifierType: IdentifierType;
}> {}

/**
 * The `AuthError` a flow reports for an {@link IdentifierRefusedError} it does
 * not pass on. Outside SCIM a refusal means the host wired a store that cannot
 * serve the flow (phone sign-in over an emails-only store), which the client
 * cannot correct.
 */
export const refusalAuthError = (error: IdentifierRefusedError): Errors.AuthError =>
  new Errors.AuthError({ message: error.message, cause: error });

// ---------------------------------------------------------------------------
// Store contract (D3 conventions: `Option.none()` on a miss, AuthError for infra failures)
// ---------------------------------------------------------------------------

/** Tag for the `IdentifierStore` service. */
export class IdentifierStore extends Context.Service<
  IdentifierStore,
  {
    /**
     * Look up an identifier by its `(type, value)` pair (the natural unique key).
     * Returns `Option.none()` when no matching record exists.
     *
     * The match is exact: the store compares `value` code unit for code unit,
     * never under a case- or accent-insensitive collation, since the services
     * hand it values that are already normalized. The services read it through
     * {@link lookupIdentifier}, which treats a record whose `type` or `value`
     * differs from the one asked for as a miss.
     */
    readonly getByValue: (
      type: IdentifierType,
      value: string,
    ) => Effect.Effect<Option.Option<Identifier>, Errors.AuthError>;

    /**
     * List all identifiers for a user, ordered by `createdAt` ascending.
     * Returns an empty array when the user has no identifiers.
     */
    readonly listByUser: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Identifier>, Errors.AuthError>;

    /**
     * Persist a new identifier record. A store that cannot hold the identifier
     * by its own shape (one email per user, emails only) refuses it with
     * {@link IdentifierRefusedError}; infrastructure failures are `AuthError`.
     */
    readonly create: (
      identifier: Identifier,
    ) => Effect.Effect<Identifier, Errors.AuthError | IdentifierRefusedError>;

    /**
     * Swap one of a user's identifiers for a new value: claim `to` and release
     * `from` as one change, so the user is never left holding neither.
     *
     * `from` is the identifier being replaced, as this store reported it. `to`
     * is the new record (see {@link makeIdentifier}) for the same `userId` and
     * `type`, with its own `id` and a different `value`; the store fails with
     * `AuthError` when any of these rules is broken ({@link replaceInputError}).
     * A store with transactions writes both in one. A store without them claims
     * `to` before it releases `from`, so a failure between the two leaves the
     * user holding both, never neither.
     *
     * Resolves to the replacement as the store now reports it, or `None` when
     * `from` is no longer held by its user (no record matches its `id`,
     * `userId`, `type` and `value`), in which case nothing is written. A store
     * that keeps the identifier on the user's own record (effect-auth-drizzle's
     * single-table store) instead resolves to that record when it already holds
     * `to`'s value, since the user is then in the state the call asked for.
     * When another user holds `to`'s `(type, value)` the store fails with
     * `AuthError` and `from` stays, as `create` does; {@link replaceIdentifier}
     * reports that as an {@link IdentifierTakenError}. When `from` is stale and
     * `to` is taken as well, a store may report either. Core email change
     * confirms through it.
     *
     * Two concurrent replaces of the same `from` with different values: the
     * in-memory store (one synchronous step), effect-auth/sql (a compare-and-swap
     * on the release) and effect-auth-drizzle's single-table store (an `UPDATE`
     * guarded on `from`'s value) let one succeed, and the other resolves to
     * `None`, writing nothing. For effect-auth/sql on PostgreSQL that holds at
     * the default READ COMMITTED isolation; at stricter levels the losing call
     * fails with a serialization error, surfaced as `AuthError`. On D1
     * (effect-auth-alchemy-cloudflare), which has no transactions, the losing call removes
     * its claim in a statement of its own, so a failure before that statement
     * leaves the user holding both new values. `IdentifierStoreKV` and
     * effect-auth-drizzle's default store check `from` before they write and
     * release it unguarded, so both replaces can succeed and the user holds
     * both new values.
     */
    readonly replace: (
      from: Identifier,
      to: Identifier,
    ) => Effect.Effect<Option.Option<Identifier>, Errors.AuthError>;

    /**
     * Mark an identifier as verified, recording the timestamp.
     * Returns `Option.none()` when no identifier with the given `id` exists.
     */
    readonly setVerified: (
      id: string,
      verifiedAt: Date,
    ) => Effect.Effect<Option.Option<Identifier>, Errors.AuthError>;

    /**
     * Delete a single identifier by `id`.
     * No-ops silently when the identifier does not exist.
     */
    readonly delete: (id: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Delete all identifiers for a user (e.g. on account deletion).
     * No-ops silently when the user has no identifiers.
     */
    readonly deleteByUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/IdentifierStore") {}

// ---------------------------------------------------------------------------
// Read views & helpers
// ---------------------------------------------------------------------------

/**
 * Look up an identifier by its exact `(type, value)` through
 * {@link IdentifierStore} `getByValue`, which is how every core service reads
 * one.
 *
 * A store whose comparison is looser than byte equality (a MySQL column under
 * a case- and accent-insensitive collation such as `utf8mb4_0900_ai_ci`, where
 * `bob@exämple.com` matches `bob@example.com`) can answer with another
 * address's record. A flow that bound a token to that record's user and sent it
 * to the address the caller typed would hand that account to whoever holds the
 * typed address. This helper treats such an answer as a miss and logs a
 * warning without either value, so every store, bring-your-own ones included,
 * resolves only the identifier asked for. A flow that delivers to the
 * identifier sends to the returned `identifier.value`, which then equals
 * `value`.
 */
export const lookupIdentifier = (
  store: typeof IdentifierStore.Service,
  type: IdentifierType,
  value: string,
): Effect.Effect<Option.Option<Identifier>, Errors.AuthError> =>
  Effect.filterOrElse(
    store.getByValue(type, value),
    (found) => !Option.exists(found, (i) => i.type !== type || i.value !== value),
    () =>
      Effect.as(
        Effect.logWarning(
          `IdentifierStore.getByValue returned a different ${type} than the one asked for; treated as a miss. The store's comparison is not exact (check the column's collation).`,
        ),
        Option.none(),
      ),
  );

/**
 * A `User` enriched with all of their identifiers. This is a read-only view:
 * it is never written to any store directly.
 */
export const UserWithIdentifiers = Schema.Struct({
  user: Types.User,
  identifiers: Schema.Array(Identifier),
});
export type UserWithIdentifiers = typeof UserWithIdentifiers.Type;

/** Oldest identifier first. */
const byCreatedAt: Order.Order<Identifier> = Order.mapInput(
  Order.Date,
  (identifier: Identifier) => identifier.createdAt,
);

/**
 * The user's first verified email identifier, or `None` when there is none.
 * When the user has several verified email identifiers, the one with the
 * earliest `createdAt` is primary.
 */
export const primaryEmail = (identifiers: ReadonlyArray<Identifier>): Option.Option<Identifier> =>
  Arr.head(
    Arr.sort(
      identifiers.filter((id) => id.type === "email" && id.verified),
      byCreatedAt,
    ),
  );

/** The value of {@link primaryEmail}, or `None`. */
export const primaryEmailValue = (identifiers: ReadonlyArray<Identifier>): Option.Option<string> =>
  Option.map(primaryEmail(identifiers), (identifier) => identifier.value);

/**
 * The user's email of record for delivery and display: the primary (earliest
 * verified) email identifier when there is one, else the earliest email
 * identifier of any verification state, else `None`.
 */
export const anyEmail = (identifiers: ReadonlyArray<Identifier>): Option.Option<Identifier> =>
  Option.orElse(primaryEmail(identifiers), () =>
    Arr.head(
      Arr.sort(
        identifiers.filter((id) => id.type === "email"),
        byCreatedAt,
      ),
    ),
  );

/** The value of {@link anyEmail}, or `None`. */
export const anyEmailValue = (identifiers: ReadonlyArray<Identifier>): Option.Option<string> =>
  Option.map(anyEmail(identifiers), (identifier) => identifier.value);

/**
 * Construct a new (unpersisted) identifier record with a random id.
 *
 * `now` is the record's `createdAt`. It is required so the time comes from
 * the caller's `Clock` (`yield* DateTime.nowAsDate`), which `TestClock`
 * controls, rather than from the wall clock.
 */
export const makeIdentifier = (input: {
  readonly userId: string;
  readonly type: IdentifierType;
  readonly value: string;
  readonly verified?: boolean;
  readonly verifiedAt?: Date;
  readonly now: Date;
}): Identifier => {
  const now = input.now;
  return {
    id: globalThis.crypto.randomUUID(),
    userId: input.userId,
    type: input.type,
    value: input.value,
    verified: input.verified ?? false,
    ...(input.verifiedAt !== undefined ? { verifiedAt: input.verifiedAt } : {}),
    createdAt: now,
  };
};

/** The `IdentifierTakenError` for a `(type, value)` another user holds. */
const takenError = (type: IdentifierType): IdentifierTakenError =>
  new IdentifierTakenError({
    message: `This ${type} is already in use`,
    identifierType: type,
  });

/**
 * The `AuthError` an {@link IdentifierStore} `replace` fails with when `to` is
 * not a new record for `from`'s user and type, with its own `id` and a
 * different `value`, or `None` when the pair is valid.
 *
 * Exported for store implementations, so every store refuses the same inputs
 * with the same message.
 */
export const replaceInputError = (
  from: Identifier,
  to: Identifier,
): Option.Option<Errors.AuthError> =>
  to.userId === from.userId && to.type === from.type && to.id !== from.id && to.value !== from.value
    ? Option.none()
    : Option.some(
        new Errors.AuthError({
          message:
            "IdentifierStore.replace takes a new record, with its own id and a new value, for the same user and type as the identifier it replaces",
        }),
      );

/**
 * Claim a `(type, value)` identifier for a user.
 *
 * The store's unique index on `(type, value)` is the real claim mechanism;
 * this helper adds a readable failure mode: when `create` fails and the pair
 * turns out to exist (a concurrent claim, or a pre-existing owner), the
 * failure is an {@link IdentifierTakenError}; infrastructure errors pass
 * through as `AuthError`. On an `IdentifierTakenError` the caller's freshly
 * created user (if any) may be orphaned — compensate or surface per flow.
 */
export const claimIdentifier = (
  store: typeof IdentifierStore.Service,
  identifier: Identifier,
): Effect.Effect<Identifier, Errors.AuthError | IdentifierTakenError | IdentifierRefusedError> =>
  Effect.gen(function* () {
    const existing = yield* lookupIdentifier(store, identifier.type, identifier.value);
    if (Option.isSome(existing)) {
      return yield* new IdentifierTakenError({
        message: `This ${identifier.type} is already in use`,
        identifierType: identifier.type,
      });
    }
    return yield* store.create(identifier).pipe(
      Effect.catchTag(
        "AuthError",
        (
          error,
        ): Effect.Effect<
          Identifier,
          Errors.AuthError | IdentifierTakenError | IdentifierRefusedError
        > =>
          Effect.gen(function* () {
            // The unique index may have rejected a concurrent claim — re-check
            // so the caller sees a conflict, not an infrastructure error.
            const raced = yield* lookupIdentifier(store, identifier.type, identifier.value);
            if (Option.isSome(raced)) {
              return yield* new IdentifierTakenError({
                message: `This ${identifier.type} is already in use`,
                identifierType: identifier.type,
              });
            }
            return yield* error;
          }),
      ),
    );
  });

/**
 * Replace one of a user's identifiers with a new value through
 * {@link IdentifierStore} `replace`, with readable failures.
 *
 * `to` is the new record, built with {@link makeIdentifier} for `from`'s user
 * and type. As with {@link claimIdentifier}, an address another user holds is an
 * {@link IdentifierTakenError}, whether it was held before the call or a
 * concurrent claim won the store's unique index; other store failures pass
 * through as `AuthError`. Either way `from` stays the user's. When the user does
 * not hold `from` (it was released or replaced meanwhile) the failure is an
 * {@link IdentifierNotFoundError}, including when the store refused `to`
 * because a concurrent replace of `from` already gave the user that value. That
 * failure does not promise that nothing was written: a store that writes
 * without a transaction (D1 when undoing its own claim fails), or a lost commit
 * acknowledgement, may leave the user holding `to` when it reports
 * `IdentifierNotFoundError`. A caller that needs to know re-reads the user's
 * identifiers.
 */
export const replaceIdentifier = (
  store: typeof IdentifierStore.Service,
  from: Identifier,
  to: Identifier,
): Effect.Effect<Identifier, Errors.AuthError | IdentifierTakenError | IdentifierNotFoundError> =>
  Effect.gen(function* () {
    const existing = yield* lookupIdentifier(store, to.type, to.value);
    if (Option.isSome(existing) && existing.value.userId !== to.userId) {
      return yield* takenError(to.type);
    }
    const replaced = yield* store.replace(from, to).pipe(
      Effect.catchTag(
        "AuthError",
        (
          error,
        ): Effect.Effect<Option.Option<Identifier>, Errors.AuthError | IdentifierTakenError> =>
          Effect.gen(function* () {
            // The unique index may have rejected `to` because another user
            // claimed it concurrently: re-check so the caller sees a conflict.
            const raced = yield* lookupIdentifier(store, to.type, to.value);
            if (Option.isSome(raced) && raced.value.userId !== to.userId) {
              return yield* takenError(to.type);
            }
            // Or a concurrent replace of the same `from` (a double submit)
            // already gave this user `to`'s value and released `from`: report
            // that `from` is gone, as a store that checks `from` first does.
            if (Option.isSome(raced)) {
              const held = yield* lookupIdentifier(store, from.type, from.value);
              if (!Option.exists(held, (h) => h.id === from.id && h.userId === from.userId)) {
                return Option.none();
              }
            }
            return yield* error;
          }),
      ),
    );
    if (Option.isNone(replaced)) {
      return yield* new IdentifierNotFoundError({
        message: `The ${from.type} to replace is no longer held by this user`,
        id: from.id,
      });
    }
    return replaced.value;
  });

/**
 * In-memory {@link IdentifierStore} for tests and single-instance
 * deployments. Uniqueness on `(type, value)` is enforced by construction
 * (synchronous, single-threaded): `create` fails with `AuthError` when the
 * pair is already claimed, mirroring a SQL unique-index violation.
 *
 * Pass your own `MutableHashMap` (keyed by identifier `id`) to inspect or pre-seed
 * state in tests.
 */
export const memoryIdentifierStore = (
  records: MutableHashMap.MutableHashMap<string, Identifier> = MutableHashMap.empty(),
): typeof IdentifierStore.Service => {
  const byValue = (type: IdentifierType, value: string): Option.Option<Identifier> =>
    Arr.findFirst(
      MutableHashMap.values(records),
      (identifier) => identifier.type === type && identifier.value === value,
    );
  return {
    getByValue: (type, value) => Effect.sync(() => byValue(type, value)),
    listByUser: (userId) =>
      Effect.sync(() =>
        Arr.sort(
          Arr.filter(MutableHashMap.values(records), (identifier) => identifier.userId === userId),
          byCreatedAt,
        ),
      ),
    create: (identifier) =>
      Effect.suspend(() => {
        if (Option.isSome(byValue(identifier.type, identifier.value))) {
          return Effect.fail(
            new Errors.AuthError({
              message: `Identifier (${identifier.type}) already exists`,
            }),
          );
        }
        MutableHashMap.set(records, identifier.id, identifier);
        return Effect.succeed(identifier);
      }),
    // Synchronous, so the claim and the release are one indivisible step.
    replace: (from, to) =>
      Effect.suspend(() => {
        const invalid = replaceInputError(from, to);
        if (Option.isSome(invalid)) return Effect.fail(invalid.value);
        const held = MutableHashMap.get(records, from.id);
        if (
          !Option.exists(
            held,
            (h) => h.userId === from.userId && h.type === from.type && h.value === from.value,
          )
        ) {
          return Effect.succeedNone;
        }
        if (Option.isSome(byValue(to.type, to.value))) {
          return Effect.fail(
            new Errors.AuthError({
              message: `Identifier (${to.type}) already exists`,
            }),
          );
        }
        MutableHashMap.remove(records, from.id);
        MutableHashMap.set(records, to.id, to);
        return Effect.succeedSome(to);
      }),
    setVerified: (id, verifiedAt) =>
      Effect.sync(() =>
        Option.map(MutableHashMap.get(records, id), (existing) => {
          const updated: Identifier = { ...existing, verified: true, verifiedAt };
          MutableHashMap.set(records, id, updated);
          return updated;
        }),
      ),
    delete: (id) => Effect.sync(() => void MutableHashMap.remove(records, id)),
    deleteByUser: (userId) =>
      Effect.sync(() => {
        Arr.forEach(Arr.fromIterable(records), ([id, identifier]) => {
          if (identifier.userId === userId) MutableHashMap.remove(records, id);
        });
      }),
  };
};

/**
 * Resolve the user that owns a `(type, value)` identifier, or `None` when the
 * identifier is unclaimed (or its owner no longer exists). `getUser` is any
 * user-by-id lookup (e.g. `UserStore.get`).
 */
export const resolveUserByIdentifier = <E>(
  store: typeof IdentifierStore.Service,
  getUser: (userId: string) => Effect.Effect<Option.Option<Types.User>, E>,
  type: IdentifierType,
  value: string,
): Effect.Effect<
  Option.Option<{ readonly user: Types.User; readonly identifier: Identifier }>,
  Errors.AuthError | E
> =>
  Effect.gen(function* () {
    const found = yield* lookupIdentifier(store, type, value);
    if (Option.isNone(found)) return Option.none();
    const identifier = found.value;
    const user = yield* getUser(identifier.userId);
    return Option.map(user, (user) => ({ user, identifier }));
  });

/**
 * The identifier holding exactly `(type, value)` and its owner, for a sign-in
 * that creates the user when nobody holds the value (magic link, email and
 * phone OTP, SSO, Google One Tap), or `None` when the value is
 * unclaimed. A claimed identifier whose owner no longer exists fails with
 * `onDangling()`, so the flow never creates a second claimant for it. The
 * identifier is read through {@link lookupIdentifier}.
 */
export const findIdentifierOwner = <E, E2>(
  store: typeof IdentifierStore.Service,
  getUser: (userId: string) => Effect.Effect<Option.Option<Types.User>, E>,
  type: IdentifierType,
  value: string,
  onDangling: () => E2,
): Effect.Effect<
  Option.Option<{ readonly identifier: Identifier; readonly user: Types.User }>,
  Errors.AuthError | E | E2
> =>
  Effect.gen(function* () {
    const found = yield* lookupIdentifier(store, type, value);
    if (Option.isNone(found)) return Option.none();
    const identifier = found.value;
    const user = yield* getUser(identifier.userId);
    if (Option.isNone(user)) return yield* Effect.fail(onDangling());
    return Option.some({ identifier, user: user.value });
  });
