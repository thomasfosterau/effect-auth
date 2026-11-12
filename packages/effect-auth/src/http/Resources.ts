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
import { ApiKeyRateLimit } from "./HttpApiSchema.ts";

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
 * `Organization.Invitation` but its `tokenHash`, its `organizationId` and
 * `inviterId` as the `organization` and `inviter` relationships. `status`
 * moves through `PATCH /invitations/:id`: the invitee sets `accepted` or
 * `rejected`, presenting the invitation email's secret as the input-only
 * `token` attribute (#586); a member holding `invitation:cancel` sets
 * `canceled`.
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
    // Input-only: the invitation email's secret, never on the resource.
    token: Resource.attribute(Schema.String, { resource: false, create: false }),
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
 * `POST /organizations/:id/domains` (`domain`; always a `dns` claim) and
 * proved through `POST /organization-domains/:id/verifications`, or attested
 * by the operator through `POST /admin/organization-domains` (a `manual`
 * claim, #598); nothing else about it is writable. `verificationToken` is the
 * value a `dns` claim publishes as a TXT record.
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
      create: false,
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

// -----------------------------------------------------------------------------
// Admin, API keys, OAuth clients, SSO and JWTs (#205, slice 5)
// -----------------------------------------------------------------------------

/**
 * A ban on a user (`user-bans`): the ban fields `AdminService.banUser` writes
 * to the user's `attributes` (`banReason`, `banExpires`), as a resource of its
 * own. A user has at most one ban, so its id is the banned user's id, and the
 * `user` relationship names that user. A ban is created (`POST /user-bans`,
 * with an optional `reason` and `expiresIn`) and lifted
 * (`DELETE /user-bans/:id`); nothing about it is writable in between.
 *
 * @since 0.3.0
 * @category resources
 */
export const UserBan = Resource.make("user-bans", {
  id: Schema.String,
  attributes: {
    reason: Resource.readOnlyAttribute(Schema.String),
    /** When the ban lapses, in epoch milliseconds; absent for a permanent ban. */
    expiresAt: Resource.attribute(Schema.Finite, {
      resource: "optional",
      create: false,
      update: false,
    }),
  },
  relationships: {
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `user-bans` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type UserBan = typeof UserBan.Type;

/**
 * An administrator acting as another user (`impersonations`): the session
 * `AdminService.impersonateUser` creates, its `userId` as the `user`
 * relationship and its `attributes.impersonatedBy` as the `impersonator`. The
 * id is the stored session id (the hash of the session token), never the
 * token, which travels only in the session cookie. Created by
 * `POST /impersonations` and ended by `DELETE /impersonations/current`;
 * nothing about it is writable.
 *
 * @since 0.3.0
 * @category resources
 */
export const Impersonation = Resource.make("impersonations", {
  id: Schema.String,
  attributes: {
    expiresAt: instant,
    createdAt: instant,
  },
  relationships: {
    user: Relationship.one(() => User),
    impersonator: Relationship.one(() => User),
  },
});

/**
 * The decoded `impersonations` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type Impersonation = typeof Impersonation.Type;

/**
 * An API key (`api-keys`): `ApiKey.ApiKey`, its `userId` as the `user`
 * relationship. The key's hash and its refill bookkeeping are never on the
 * wire, and neither is the key itself, except once, in the `meta` of the
 * answer to `POST /api-keys`. `start` is the key's first characters, for
 * telling keys apart. `prefix` is fixed at creation; the rest is writable
 * through `PATCH /api-keys/:id`.
 *
 * @since 0.3.0
 * @category resources
 */
export const ApiKey = Resource.make("api-keys", {
  id: Schema.String,
  attributes: {
    name: Resource.attribute(Schema.String, { resource: "optional", create: "optional" }),
    prefix: Resource.attribute(Schema.String, {
      resource: "optional",
      create: "optional",
      update: false,
    }),
    start: Resource.readOnlyAttribute(Schema.String),
    enabled: Resource.attribute(Schema.Boolean, { create: false }),
    expiresAt: Resource.attribute(Schema.Finite, { resource: "optional", create: false }),
    lastUsedAt: Resource.attribute(Schema.Finite, {
      resource: "optional",
      create: false,
      update: false,
    }),
    permissions: Resource.attribute(Schema.Record(Schema.String, Schema.Array(Schema.String)), {
      resource: "optional",
      create: "optional",
    }),
    metadata: Resource.attribute(Attributes, { create: "optional" }),
    remaining: Resource.attribute(Schema.Finite, { resource: "optional", create: "optional" }),
    rateLimit: Resource.attribute(ApiKeyRateLimit, { resource: "optional", create: "optional" }),
    createdAt: epochMillis,
    updatedAt: epochMillis,
  },
  relationships: {
    user: Relationship.one(() => User),
  },
});

/**
 * The decoded `api-keys` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type ApiKey = typeof ApiKey.Type;

/**
 * A client of this server's OIDC provider (`oauth-clients`):
 * `OidcProvider.OidcClient`, its `clientId` as the id. The secret's hash, the
 * RFC 7591 registration metadata and the registrar are never on the wire; a
 * confidential client's secret is shown once, in the `meta` of the answer to
 * `POST /oauth-clients`. `type` is fixed at creation, and `disabled` is set
 * only by an update.
 *
 * @since 0.3.0
 * @category resources
 */
export const OAuthClient = Resource.make("oauth-clients", {
  id: Schema.String,
  attributes: {
    name: Schema.String,
    redirectUris: Schema.Array(Schema.String),
    clientType: Resource.attribute(Schema.Literals(["web", "native"]), {
      create: "optional",
      update: false,
    }),
    skipConsent: Resource.attribute(Schema.Boolean, { create: "optional" }),
    disabled: Resource.attribute(Schema.Boolean, { create: false }),
    metadata: Resource.attribute(Attributes, { create: "optional" }),
    createdAt: epochMillis,
    updatedAt: epochMillis,
  },
});

/**
 * The decoded `oauth-clients` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type OAuthClient = typeof OAuthClient.Type;

/** A server-maintained string only one of the SSO protocols carries. */
const protocolString = Resource.attribute(Schema.String, {
  resource: "optional",
  create: false,
  update: false,
});

/** A server-maintained list of strings only one of the SSO protocols carries. */
const protocolStrings = Resource.attribute(Schema.Array(Schema.String), {
  resource: "optional",
  create: false,
  update: false,
});

/** A server-maintained flag only the SAML protocol carries. */
const protocolFlag = Resource.attribute(Schema.Boolean, {
  resource: "optional",
  create: false,
  update: false,
});

/**
 * An enterprise SSO connection (`sso-providers`): `Sso.SsoProvider`, of either
 * protocol, discriminated by `protocol`. The attributes are the union of both
 * arms', each present only on the arm that has it; its `organizationId` is the
 * `organization` relationship (`null` when the connection provisions no
 * membership). The OIDC client secret, the PKCE switch and the registrar are
 * never on the wire, as before. A connection is created through
 * `POST /sso-providers` (admin-gated), whose document carries one protocol's
 * registration fields.
 *
 * @since 0.3.0
 * @category resources
 */
export const SsoProvider = Resource.make("sso-providers", {
  id: Schema.String,
  attributes: {
    protocol: Resource.readOnlyAttribute(Schema.Literals(["oidc", "saml"])),
    domain: Resource.readOnlyAttribute(Schema.String),
    issuer: protocolString,
    clientId: protocolString,
    redirectUri: protocolString,
    authorizationEndpoint: protocolString,
    tokenEndpoint: protocolString,
    userInfoEndpoint: protocolString,
    jwksEndpoint: protocolString,
    scopes: protocolStrings,
    entityId: protocolString,
    ssoUrl: protocolString,
    idpCertificates: protocolStrings,
    spEntityId: protocolString,
    acsUrl: protocolString,
    signatureAlgorithms: protocolStrings,
    wantAssertionsSigned: protocolFlag,
    wantAuthnResponseSigned: protocolFlag,
    forceAuthn: protocolFlag,
    createdAt: epochMillis,
  },
  relationships: {
    organization: Relationship.optional(() => Organization),
  },
});

/**
 * The decoded `sso-providers` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type SsoProvider = typeof SsoProvider.Type;

/**
 * A started SSO sign-in (`sso-authorizations`): what
 * `POST /sso-authorizations` answers. `url` is where to send the browser (the
 * IdP's authorization or single sign-on endpoint); the id is the round-trip
 * `state` (OIDC) or `RelayState` (SAML) the IdP echoes back to the callback.
 *
 * @since 0.3.0
 * @category resources
 */
export const SsoAuthorization = Resource.make("sso-authorizations", {
  id: Schema.String,
  attributes: {
    url: Resource.readOnlyAttribute(Schema.String),
  },
});

/**
 * The decoded `sso-authorizations` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type SsoAuthorization = typeof SsoAuthorization.Type;

/**
 * A signed JWT for the signed-in user (`tokens`): what `POST /tokens` answers.
 * A token is not stored, so its id is the SHA-256 digest of the token, never
 * the token itself; `token` is the compact JWS and `expiresAt` its `exp`, in
 * epoch milliseconds.
 *
 * @since 0.3.0
 * @category resources
 */
export const Token = Resource.make("tokens", {
  id: Schema.String,
  attributes: {
    token: Resource.readOnlyAttribute(Schema.String),
    expiresAt: epochMillis,
  },
});

/**
 * The decoded `tokens` resource object.
 *
 * @since 0.3.0
 * @category resources
 */
export type Token = typeof Token.Type;
