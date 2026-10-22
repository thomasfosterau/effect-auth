/**
 * Identifier domain: a surrogate-keyed model for user identity credentials.
 *
 * An `Identifier` is a verified or unverified claim that a user owns a
 * particular value for a given type — an email address, a username, or a phone
 * number. This separates identity claims from the `User` record itself, enabling
 * a user to have multiple emails, rename their username, or add phone as a
 * second factor without changing the user's primary key.
 *
 * Since the surrogate-key migration, identifiers are the **only** place
 * login handles live: `User` carries no `email`/`emailVerified` fields, and
 * every flow that resolves "who owns this email/username/phone" goes through
 * the {@link IdentifierStore}.
 */
import { Array as Arr, Context, Data, Effect, Option, Order, Schema } from "effect";
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
 * `value` is stored in normalized form: email addresses are trimmed and
 * lowercased; usernames are trimmed and lowercased; phone numbers are stored
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

// ---------------------------------------------------------------------------
// Store contract (D3 conventions: null on miss, AuthError for infra failures)
// ---------------------------------------------------------------------------

/** Tag for the `IdentifierStore` service. */
export class IdentifierStore extends Context.Service<
  IdentifierStore,
  {
    /**
     * Look up an identifier by its `(type, value)` pair (the natural unique key).
     * Returns `null` when no matching record exists.
     */
    readonly getByValue: (
      type: IdentifierType,
      value: string,
    ) => Effect.Effect<Identifier | null, Errors.AuthError>;

    /**
     * List all identifiers for a user, ordered by `createdAt` ascending.
     * Returns an empty array when the user has no identifiers.
     */
    readonly listByUser: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Identifier>, Errors.AuthError>;

    /** Persist a new identifier record. */
    readonly create: (identifier: Identifier) => Effect.Effect<Identifier, Errors.AuthError>;

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
     * Resolves to the replacement as the store now reports it, or `null` when
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
     * in-memory store (one synchronous step), effect-auth-sql (a compare-and-swap
     * on the release) and effect-auth-drizzle's single-table store (an `UPDATE`
     * guarded on `from`'s value) let one succeed, and the other resolves to
     * `null`, writing nothing. For effect-auth-sql on PostgreSQL that holds at
     * the default READ COMMITTED isolation; at stricter levels the losing call
     * fails with a serialization error, surfaced as `AuthError`. On D1
     * (effect-auth-alchemy), which has no transactions, the losing call removes
     * its claim in a statement of its own, so a failure before that statement
     * leaves the user holding both new values. `IdentifierStoreKV` and
     * effect-auth-drizzle's default store check `from` before they write and
     * release it unguarded, so both replaces can succeed and the user holds
     * both new values.
     */
    readonly replace: (
      from: Identifier,
      to: Identifier,
    ) => Effect.Effect<Identifier | null, Errors.AuthError>;

    /**
     * Mark an identifier as verified, recording the timestamp.
     * Returns `null` when no identifier with the given `id` exists.
     */
    readonly setVerified: (
      id: string,
      verifiedAt: Date,
    ) => Effect.Effect<Identifier | null, Errors.AuthError>;

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
 * Return the first verified email identifier for a user, or `null` if none
 * exists. When the user has multiple verified email identifiers the one with
 * the earliest `createdAt` is considered primary.
 */
export const primaryEmail = (identifiers: ReadonlyArray<Identifier>): Identifier | null => {
  const verified = Arr.sort(
    identifiers.filter((id) => id.type === "email" && id.verified),
    byCreatedAt,
  );
  return verified[0] ?? null;
};

/**
 * Return the primary email _value_ string, or `null`.
 * Convenience wrapper over {@link primaryEmail}.
 */
export const primaryEmailValue = (identifiers: ReadonlyArray<Identifier>): string | null =>
  primaryEmail(identifiers)?.value ?? null;

/**
 * Return the user's email of record for delivery/display: the primary
 * (earliest verified) email identifier when one exists, otherwise the
 * earliest email identifier of any verification state, otherwise `null`.
 */
export const anyEmail = (identifiers: ReadonlyArray<Identifier>): Identifier | null => {
  const primary = primaryEmail(identifiers);
  if (primary !== null) return primary;
  const emails = Arr.sort(
    identifiers.filter((id) => id.type === "email"),
    byCreatedAt,
  );
  return emails[0] ?? null;
};

/** Convenience wrapper over {@link anyEmail} returning the value string. */
export const anyEmailValue = (identifiers: ReadonlyArray<Identifier>): string | null =>
  anyEmail(identifiers)?.value ?? null;

/** Construct a new (unpersisted) identifier record with a random id. */
export const makeIdentifier = (input: {
  readonly userId: string;
  readonly type: IdentifierType;
  readonly value: string;
  readonly verified?: boolean;
  readonly verifiedAt?: Date;
  readonly now?: Date;
}): Identifier => {
  const now = input.now ?? new Date();
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
 * different `value`, or `null` when the pair is valid.
 *
 * Exported for store implementations, so every store refuses the same inputs
 * with the same message.
 */
export const replaceInputError = (from: Identifier, to: Identifier): Errors.AuthError | null =>
  to.userId === from.userId && to.type === from.type && to.id !== from.id && to.value !== from.value
    ? null
    : new Errors.AuthError({
        message:
          "IdentifierStore.replace takes a new record, with its own id and a new value, for the same user and type as the identifier it replaces",
      });

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
): Effect.Effect<Identifier, Errors.AuthError | IdentifierTakenError> =>
  Effect.gen(function* () {
    const existing = yield* store.getByValue(identifier.type, identifier.value);
    if (existing !== null) {
      return yield* new IdentifierTakenError({
        message: `This ${identifier.type} is already in use`,
        identifierType: identifier.type,
      });
    }
    return yield* store.create(identifier).pipe(
      Effect.catchTag(
        "AuthError",
        (error): Effect.Effect<Identifier, Errors.AuthError | IdentifierTakenError> =>
          Effect.gen(function* () {
            // The unique index may have rejected a concurrent claim — re-check
            // so the caller sees a conflict, not an infrastructure error.
            const raced = yield* store.getByValue(identifier.type, identifier.value);
            if (raced !== null) {
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
    const existing = yield* store.getByValue(to.type, to.value);
    if (existing !== null && existing.userId !== to.userId) {
      return yield* takenError(to.type);
    }
    const replaced = yield* store.replace(from, to).pipe(
      Effect.catchTag(
        "AuthError",
        (error): Effect.Effect<Identifier | null, Errors.AuthError | IdentifierTakenError> =>
          Effect.gen(function* () {
            // The unique index may have rejected `to` because another user
            // claimed it concurrently: re-check so the caller sees a conflict.
            const raced = yield* store.getByValue(to.type, to.value);
            if (raced !== null && raced.userId !== to.userId) {
              return yield* takenError(to.type);
            }
            // Or a concurrent replace of the same `from` (a double submit)
            // already gave this user `to`'s value and released `from`: report
            // that `from` is gone, as a store that checks `from` first does.
            if (raced !== null) {
              const held = yield* store.getByValue(from.type, from.value);
              if (held === null || held.id !== from.id || held.userId !== from.userId) {
                return null;
              }
            }
            return yield* error;
          }),
      ),
    );
    if (replaced === null) {
      return yield* new IdentifierNotFoundError({
        message: `The ${from.type} to replace is no longer held by this user`,
        id: from.id,
      });
    }
    return replaced;
  });

/**
 * In-memory {@link IdentifierStore} for tests and single-instance
 * deployments. Uniqueness on `(type, value)` is enforced by construction
 * (synchronous, single-threaded): `create` fails with `AuthError` when the
 * pair is already claimed, mirroring a SQL unique-index violation.
 *
 * Pass your own `Map` (keyed by identifier `id`) to inspect or pre-seed
 * state in tests.
 */
export const memoryIdentifierStore = (
  records: Map<string, Identifier> = new Map(),
): typeof IdentifierStore.Service => {
  const byValue = (type: IdentifierType, value: string): Identifier | null =>
    Option.getOrNull(
      Arr.findFirst(
        records.values(),
        (identifier) => identifier.type === type && identifier.value === value,
      ),
    );
  return {
    getByValue: (type, value) => Effect.sync(() => byValue(type, value)),
    listByUser: (userId) =>
      Effect.sync(() =>
        Arr.sort(
          Arr.filter(records.values(), (identifier) => identifier.userId === userId),
          byCreatedAt,
        ),
      ),
    create: (identifier) =>
      Effect.suspend(() => {
        if (byValue(identifier.type, identifier.value) !== null) {
          return Effect.fail(
            new Errors.AuthError({
              message: `Identifier (${identifier.type}) already exists`,
            }),
          );
        }
        records.set(identifier.id, identifier);
        return Effect.succeed(identifier);
      }),
    // Synchronous, so the claim and the release are one indivisible step.
    replace: (from, to) =>
      Effect.suspend(() => {
        const invalid = replaceInputError(from, to);
        if (invalid !== null) return Effect.fail(invalid);
        const held = records.get(from.id);
        if (
          held === undefined ||
          held.userId !== from.userId ||
          held.type !== from.type ||
          held.value !== from.value
        ) {
          return Effect.succeed(null);
        }
        if (byValue(to.type, to.value) !== null) {
          return Effect.fail(
            new Errors.AuthError({
              message: `Identifier (${to.type}) already exists`,
            }),
          );
        }
        records.delete(from.id);
        records.set(to.id, to);
        return Effect.succeed(to);
      }),
    setVerified: (id, verifiedAt) =>
      Effect.sync(() => {
        const existing = records.get(id);
        if (existing === undefined) return null;
        const updated: Identifier = { ...existing, verified: true, verifiedAt };
        records.set(id, updated);
        return updated;
      }),
    delete: (id) => Effect.sync(() => void records.delete(id)),
    deleteByUser: (userId) =>
      Effect.sync(() => {
        Arr.forEach(Arr.fromIterable(records.entries()), ([id, identifier]) => {
          if (identifier.userId === userId) records.delete(id);
        });
      }),
  };
};

/**
 * Resolve the user that owns a `(type, value)` identifier, or `null` when the
 * identifier is unclaimed (or its owner no longer exists). `getUser` is any
 * user-by-id lookup (e.g. `UserStore.get`).
 */
export const resolveUserByIdentifier = <E>(
  store: typeof IdentifierStore.Service,
  getUser: (userId: string) => Effect.Effect<Types.User | null, E>,
  type: IdentifierType,
  value: string,
): Effect.Effect<{ user: Types.User; identifier: Identifier } | null, Errors.AuthError | E> =>
  Effect.gen(function* () {
    const identifier = yield* store.getByValue(type, value);
    if (identifier === null) return null;
    const user = yield* getUser(identifier.userId);
    return user === null ? null : { user, identifier };
  });
