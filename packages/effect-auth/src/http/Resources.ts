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
import * as Schema from "effect/Schema";
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
 * @since 0.1.0
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
 * @since 0.1.0
 * @category resources
 */
export type User = typeof User.Type;

/**
 * A session (`sessions`): `Types.Session`, its `userId` as the `user`
 * relationship. The id is the stored id (the hash of the session token), never
 * the token itself, so listing sessions discloses no credential.
 *
 * @since 0.1.0
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
 * @since 0.1.0
 * @category resources
 */
export type Session = typeof Session.Type;

/**
 * A login handle (`identifiers`): `Identifier.Identifier`, its `userId` as the
 * `user` relationship and its `type` as `kind` (JSON:API reserves `type`). Identifiers are created and verified through the flows
 * that prove them, so no attribute is writable here.
 *
 * @since 0.1.0
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
 * @since 0.1.0
 * @category resources
 */
export type Identifier = typeof Identifier.Type;

/**
 * A pending second factor (`second-factor-challenges`): what `POST /sessions`
 * answers, with `202`, for a user enrolled in multi-factor authentication.
 * The id is the challenge token, presented again (as the `challenge`
 * relationship) to `POST /second-factor-challenges/verifications` with a TOTP
 * or backup code to obtain the session. It is created only by a sign-in, so no
 * attribute is writable.
 *
 * @since 0.1.0
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
 * @since 0.1.0
 * @category resources
 */
export type SecondFactorChallenge = typeof SecondFactorChallenge.Type;

/**
 * A Google One Tap nonce (`google-one-tap-nonces`): the id is the nonce to pass
 * to Google's One Tap library (`data-nonce`), then back in a `google-one-tap`
 * sign-in credential.
 *
 * @since 0.1.0
 * @category resources
 */
export const GoogleOneTapNonce = Resource.make("google-one-tap-nonces", {
  id: Schema.String,
  attributes: {},
});

/**
 * The decoded `google-one-tap-nonces` resource object.
 *
 * @since 0.1.0
 * @category resources
 */
export type GoogleOneTapNonce = typeof GoogleOneTapNonce.Type;

/**
 * The signed-in user's multi-factor enrolment (`multi-factor-enrollments`).
 * There is at most one, so its id is always `current`. `verified` turns `true`
 * once a TOTP code confirms the enrolment. The secret and backup codes are
 * never attributes: they are shown once, in the `meta` of the answer that
 * creates them.
 *
 * @since 0.1.0
 * @category resources
 */
export const MultiFactorEnrollment = Resource.make("multi-factor-enrollments", {
  id: Schema.String,
  attributes: {
    verified: Resource.readOnlyAttribute(Schema.Boolean),
  },
});

/**
 * The decoded `multi-factor-enrollments` resource object.
 *
 * @since 0.1.0
 * @category resources
 */
export type MultiFactorEnrollment = typeof MultiFactorEnrollment.Type;

/**
 * A fresh set of multi-factor backup codes (`backup-code-sets`), replacing the
 * previous set. Its id is the user's; the codes themselves are shown once, in
 * the `meta` of the answer that creates them.
 *
 * @since 0.1.0
 * @category resources
 */
export const BackupCodeSet = Resource.make("backup-code-sets", {
  id: Schema.String,
  attributes: {},
});

/**
 * The decoded `backup-code-sets` resource object.
 *
 * @since 0.1.0
 * @category resources
 */
export type BackupCodeSet = typeof BackupCodeSet.Type;

/**
 * One of the accounts signed in on this device (`device-sessions`), when
 * multi-session is on: a `sessions` resource as the device sees it, plus
 * whether it is the `active` one the requests now carry. The id is the stored
 * id (the hash of the session token), never the token, so listing the
 * device's accounts discloses no credential and the id is safe in a URL.
 *
 * @since 0.3.0
 * @category resources
 */
export const DeviceSession = Resource.make("device-sessions", {
  id: Schema.String,
  attributes: {
    active: Resource.readOnlyAttribute(Schema.Boolean),
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
 * The decoded `device-sessions` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type DeviceSession = typeof DeviceSession.Type;

/** A server-maintained epoch-milliseconds instant, as the organization records keep it. */
const epochMillis = Resource.readOnlyAttribute(Schema.Finite);

/**
 * An organization (`organizations`): `Organization.Organization`. The stored
 * record leaves `defaultRole` and `jitProvisioning` optional; the resource
 * carries them resolved (`"member"`, `false`), so a client never branches on
 * "absent means the default". Both are set by `PATCH` only: `defaultRole`
 * needs the `role:manage` permission, the rest `organization:update`.
 *
 * @since 0.3.0
 * @category resources
 */
export const Organization = Resource.make("organizations", {
  id: Schema.String,
  attributes: {
    name: Schema.String,
    slug: Schema.String,
    logo: Resource.attribute(Schema.String, { resource: "optional", create: "optional" }),
    metadata: Resource.attribute(Attributes, { create: "optional" }),
    defaultRole: Resource.attribute(Schema.String, { create: false }),
    jitProvisioning: Resource.attribute(Schema.Boolean, { create: false }),
    createdAt: epochMillis,
  },
});

/**
 * The decoded `organizations` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type Organization = typeof Organization.Type;

/**
 * A membership (`organization-members`): `Organization.Member`, its
 * `organizationId` and `userId` as the `organization` and `user`
 * relationships. The id is the stored `Member.id`. `role` and `status` are
 * writable through `PATCH /organization-members/:id` (a `status` of
 * `inactive` deactivates the membership, `active` restores it);
 * `previousRole` is the role a reactivation restores.
 *
 * @since 0.3.0
 * @category resources
 */
export const OrganizationMember = Resource.make("organization-members", {
  id: Schema.String,
  attributes: {
    role: Resource.attribute(Schema.String, { create: "optional" }),
    status: Resource.attribute(Schema.Literals(["active", "inactive"]), { create: false }),
    previousRole: Resource.attribute(Schema.String, {
      resource: "optional",
      create: false,
      update: false,
    }),
    createdAt: epochMillis,
  },
  relationships: {
    organization: Relationship.one(() => Organization),
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `organization-members` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type OrganizationMember = typeof OrganizationMember.Type;

/**
 * An invitation to join an organization (`invitations`):
 * `Organization.Invitation`, its `organizationId` and `inviterId` as the
 * `organization` and `inviter` relationships. `status` moves through
 * `PATCH /invitations/:id`: the invitee sets `accepted` or `rejected`, a
 * member holding `invitation:cancel` sets `canceled`.
 *
 * @since 0.3.0
 * @category resources
 */
export const Invitation = Resource.make("invitations", {
  id: Schema.String,
  attributes: {
    email: Resource.attribute(Schema.String, { update: false }),
    role: Resource.attribute(Schema.String, { update: false }),
    status: Resource.attribute(Schema.Literals(["pending", "accepted", "rejected", "canceled"]), {
      create: false,
    }),
    expiresAt: epochMillis,
    createdAt: epochMillis,
  },
  relationships: {
    organization: Relationship.one(() => Organization),
    inviter: Relationship.one(() => User),
  },
});

/**
 * The decoded `invitations` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type Invitation = typeof Invitation.Type;

/**
 * An email domain an organization claims (`organization-domains`):
 * `Organization.OrganizationDomain`, its `organizationId` as the
 * `organization` relationship. A claim is created through
 * `POST /organizations/:id/domains` (`domain`, and optionally the
 * `verificationStrategy`, `dns` by default) and proved through
 * `POST /organization-domains/:id/verifications`; nothing else about it is
 * writable. `verificationToken` is the value a `dns` claim publishes as a TXT
 * record.
 *
 * @since 0.3.0
 * @category resources
 */
export const OrganizationDomain = Resource.make("organization-domains", {
  id: Schema.String,
  attributes: {
    domain: Resource.attribute(Schema.String, { update: false }),
    verificationState: Resource.readOnlyAttribute(
      Schema.Literals(["pending", "verified", "failed"]),
    ),
    verificationStrategy: Resource.attribute(Schema.Literals(["dns", "manual"]), {
      create: "optional",
      update: false,
    }),
    verificationToken: Resource.attribute(Schema.String, {
      resource: "optional",
      create: false,
      update: false,
    }),
    createdAt: epochMillis,
    verifiedAt: Resource.attribute(Schema.Finite, {
      resource: "optional",
      create: false,
      update: false,
    }),
  },
  relationships: {
    organization: Relationship.one(() => Organization),
  },
});

/**
 * The decoded `organization-domains` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type OrganizationDomain = typeof OrganizationDomain.Type;

/**
 * A role one organization defines at runtime (`organization-roles`):
 * `Organization.OrgRole`, its `organizationId` as the `organization`
 * relationship. The id is the stored `OrgRole.id`. The `role` name is set
 * once, by `POST /organizations/:id/roles`; `permissions` are replaced through
 * `PATCH /organization-roles/:id`.
 *
 * @since 0.3.0
 * @category resources
 */
export const OrganizationRole = Resource.make("organization-roles", {
  id: Schema.String,
  attributes: {
    role: Resource.attribute(Schema.String, { update: false }),
    permissions: Schema.Array(Schema.String),
    createdAt: epochMillis,
    updatedAt: epochMillis,
  },
  relationships: {
    organization: Relationship.one(() => Organization),
  },
});

/**
 * The decoded `organization-roles` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type OrganizationRole = typeof OrganizationRole.Type;

/**
 * A team (`teams`): `Organization.Team`, its `organizationId` as the
 * `organization` relationship. Only `name` is writable.
 *
 * @since 0.3.0
 * @category resources
 */
export const Team = Resource.make("teams", {
  id: Schema.String,
  attributes: {
    name: Schema.String,
    createdAt: epochMillis,
    updatedAt: epochMillis,
  },
  relationships: {
    organization: Relationship.one(() => Organization),
  },
});

/**
 * The decoded `teams` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type Team = typeof Team.Type;

/**
 * A team membership (`team-members`): `Organization.TeamMember`, its `teamId`
 * and `userId` as the `team` and `user` relationships. The id is the stored
 * `TeamMember.id`. A team membership carries no role, so nothing about it is
 * writable: it is created (`POST /teams/:id/members`) and deleted
 * (`DELETE /team-members/:id`).
 *
 * @since 0.3.0
 * @category resources
 */
export const TeamMember = Resource.make("team-members", {
  id: Schema.String,
  attributes: {
    createdAt: epochMillis,
  },
  relationships: {
    team: Relationship.one(() => Team),
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `team-members` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type TeamMember = typeof TeamMember.Type;
