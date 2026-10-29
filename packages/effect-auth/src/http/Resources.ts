/**
 * The JSON:API resources of the included HTTP API (#205): each entity the
 * contract exposes is declared once, here, as an effect-jsonapi
 * `Resource.make`, and every endpoint, document and client type over it is
 * derived from that declaration.
 *
 * The attributes are the wire projection of the store-facing records in
 * `Types.ts` and `Identifier.ts`: the same field names, with each `Date`
 * carried as epoch milliseconds (`Schema.DateFromMillis`, as the contract's
 * views always have), and each foreign key (`userId`) expressed as a
 * relationship instead of an attribute. `Resources.test.ts` holds the two
 * declarations together, so a field added to one and not the other fails a
 * test rather than drifting.
 *
 * Server-maintained fields are read-only (`Resource.readOnlyAttribute`): no
 * write payload accepts them. In particular the untyped `attributes` bag is
 * never writable over HTTP (#193): a `PATCH` cannot set a `role`.
 *
 * @module http/Resources
 */
import { Schema } from "effect";
import { Relationship, Resource } from "@thomasfosterau/effect-jsonapi";
import { Attributes } from "../Types.ts";

/** An instant on the wire: epoch milliseconds, a `Date` in code. */
const Instant = Schema.DateFromMillis;

/** A server-maintained instant: on the resource, never a write input. */
const instant = Resource.readOnlyAttribute(Instant);

/**
 * A user (`users`): the profile of `Types.User`, plus the derived `email` /
 * `emailVerified` of the user's primary email identifier when the responding
 * handler has the identifiers at hand.
 *
 * Only `name` and `image` are writable, and only through `PATCH /users/me`.
 *
 * @since 0.2.0
 * @category resources
 */
export const User = Resource.make("users", {
  id: Schema.String,
  attributes: {
    name: Resource.attribute(Schema.String, { resource: "optional", create: false }),
    image: Resource.attribute(Schema.String, { resource: "optional", create: false }),
    email: Resource.attribute(Schema.String, {
      resource: "optional",
      create: false,
      update: false,
    }),
    emailVerified: Resource.attribute(Schema.Boolean, {
      resource: "optional",
      create: false,
      update: false,
    }),
    createdAt: instant,
    updatedAt: instant,
    attributes: Resource.readOnlyAttribute(Attributes),
  },
});

/**
 * The decoded `users` resource object.
 *
 * @since 0.2.0
 * @category resources
 */
export type User = typeof User.Type;

/**
 * A session (`sessions`): `Types.Session`, its `userId` as the `user`
 * relationship. The id is the stored id (the hash of the session token), never
 * the token itself, so listing sessions discloses no credential.
 *
 * @since 0.2.0
 * @category resources
 */
export const Session = Resource.make("sessions", {
  id: Schema.String,
  attributes: {
    expiresAt: instant,
    createdAt: instant,
    lastActivityAt: instant,
    attributes: Resource.readOnlyAttribute(Attributes),
  },
  relationships: {
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `sessions` resource object.
 *
 * @since 0.2.0
 * @category resources
 */
export type Session = typeof Session.Type;

/**
 * A login handle (`identifiers`): `Identifier.Identifier`, its `userId` as the
 * `user` relationship and its `type` as `kind` (JSON:API reserves `type`). Identifiers are created and verified through the flows
 * that prove them, so no attribute is writable here.
 *
 * @since 0.2.0
 * @category resources
 */
export const Identifier = Resource.make("identifiers", {
  id: Schema.String,
  attributes: {
    // JSON:API reserves `type` for the resource type, so the identifier's own
    // type travels as `kind`.
    kind: Resource.readOnlyAttribute(Schema.Literals(["email", "username", "phone"])),
    value: Resource.readOnlyAttribute(Schema.String),
    verified: Resource.readOnlyAttribute(Schema.Boolean),
    verifiedAt: Resource.attribute(Instant, {
      resource: "optional",
      create: false,
      update: false,
    }),
    createdAt: instant,
  },
  relationships: {
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `identifiers` resource object.
 *
 * @since 0.2.0
 * @category resources
 */
export type Identifier = typeof Identifier.Type;

/**
 * A pending second factor (`second-factor-challenges`): what `POST /sessions`
 * answers, with `202`, for a user enrolled in multi-factor authentication.
 * The id is the challenge token, presented again to
 * `POST /second-factor-challenges/:id/verifications` with a TOTP or backup
 * code to obtain the session. It is created only by a sign-in, so no
 * attribute is writable.
 *
 * @since 0.2.0
 * @category resources
 */
export const SecondFactorChallenge = Resource.make("second-factor-challenges", {
  id: Schema.String,
  attributes: {
    expiresAt: instant,
  },
});

/**
 * The decoded `second-factor-challenges` resource object.
 *
 * @since 0.2.0
 * @category resources
 */
export type SecondFactorChallenge = typeof SecondFactorChallenge.Type;

/**
 * A Google One Tap nonce (`google-one-tap-nonces`): the id is the nonce to pass
 * to Google's One Tap library (`data-nonce`), then back in a `google-one-tap`
 * sign-in credential.
 *
 * @since 0.2.0
 * @category resources
 */
export const GoogleOneTapNonce = Resource.make("google-one-tap-nonces", {
  id: Schema.String,
  attributes: {},
});

/**
 * The decoded `google-one-tap-nonces` resource object.
 *
 * @since 0.2.0
 * @category resources
 */
export type GoogleOneTapNonce = typeof GoogleOneTapNonce.Type;
