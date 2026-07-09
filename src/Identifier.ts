/**
 * Identifier domain: a surrogate-keyed model for user identity credentials.
 *
 * An `Identifier` is a verified or unverified claim that a user owns a
 * particular value for a given type — an email address, a username, or a phone
 * number. This separates identity claims from the `User` record itself, enabling
 * a user to have multiple emails, rename their username, or add phone as a
 * second factor without changing the user's primary key.
 *
 * Phase 1 foundations: domain types, store contract, helpers, and read views.
 * The existing `User.email` / sign-in flows are unchanged here — migration is
 * a later phase (see PLAN.md).
 */
import { Context, Data, Effect, Schema } from "effect";
import * as Errors from "./Errors.ts";

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
  user: Schema.Struct({
    id: Schema.String,
    email: Schema.String,
    emailVerified: Schema.Boolean,
    name: Schema.optional(Schema.String),
    image: Schema.optional(Schema.String),
    createdAt: Schema.Date,
    updatedAt: Schema.Date,
    attributes: Schema.Record(Schema.String, Schema.Unknown),
  }),
  identifiers: Schema.Array(Identifier),
});
export type UserWithIdentifiers = typeof UserWithIdentifiers.Type;

/**
 * Return the first verified email identifier for a user, or `null` if none
 * exists. When the user has multiple verified email identifiers the one with
 * the earliest `createdAt` is considered primary.
 */
export const primaryEmail = (identifiers: ReadonlyArray<Identifier>): Identifier | null => {
  const verified = identifiers
    .filter((id) => id.type === "email" && id.verified)
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  return verified[0] ?? null;
};

/**
 * Return the primary email _value_ string, or `null`.
 * Convenience wrapper over {@link primaryEmail}.
 */
export const primaryEmailValue = (identifiers: ReadonlyArray<Identifier>): string | null =>
  primaryEmail(identifiers)?.value ?? null;
