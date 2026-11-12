import { describe, expect, it } from "vite-plus/test";
import { Order } from "effect";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import { Resource } from "@thomasfosterau/effect-jsonapi";
import { Identifier } from "../Identifier.ts";
import type {
  Invitation,
  Member,
  OrgRole,
  Organization,
  OrganizationDomain,
  Team,
  TeamMember,
} from "../Organization.ts";
import type { ApiKey } from "../ApiKey.ts";
import type { OidcClient } from "../OidcProvider.ts";
import type { OidcSsoProvider, SamlSsoProvider } from "../Sso.ts";
import { Session, User } from "../Types.ts";
import * as Resources from "./Resources.ts";

/** The keys of a record, sorted. */
const sorted = (keys: Iterable<string>): ReadonlyArray<string> =>
  Arr.sort(Arr.fromIterable(keys), Order.String);

/**
 * The fields a resource carries, named as the store-facing record names them:
 * its declared attributes (renamed where JSON:API reserves the name), its id
 * (as `id` names it in the record), and each to-one relationship as the
 * foreign key it stands for.
 */
const storeFacingKeys = (
  resource: Resource.Any,
  options: {
    readonly id?: string;
    readonly renamed?: Readonly<Record<string, string>>;
    readonly foreignKeys?: Readonly<Record<string, string>>;
    readonly derived?: ReadonlyArray<string>;
  } = {},
): ReadonlyArray<string> =>
  sorted([
    options.id ?? "id",
    ...R.keys(Resource.declaredAttributes(resource))
      .filter((key) => !(options.derived ?? []).includes(key))
      .map((key) => options.renamed?.[key] ?? key),
    ...R.values(options.foreignKeys ?? {}),
  ]);

// The organization records are interfaces, not schemas: these key sets are
// checked against them at compile time (`satisfies` rejects a missing key and
// an extra one), and the tests below hold the resources to them.
const organizationKeys = {
  id: true,
  name: true,
  slug: true,
  logo: true,
  metadata: true,
  defaultRole: true,
  jitProvisioning: true,
  createdAt: true,
} satisfies Record<keyof Organization, true>;

const memberKeys = {
  id: true,
  organizationId: true,
  userId: true,
  role: true,
  status: true,
  previousRole: true,
  createdAt: true,
} satisfies Record<keyof Member, true>;

const invitationKeys = {
  id: true,
  organizationId: true,
  email: true,
  role: true,
  status: true,
  inviterId: true,
  expiresAt: true,
  createdAt: true,
} satisfies Record<keyof Invitation, true>;

const domainKeys = {
  id: true,
  organizationId: true,
  domain: true,
  verificationState: true,
  verificationStrategy: true,
  verificationToken: true,
  createdAt: true,
  verifiedAt: true,
  attestedBy: true,
} satisfies Record<keyof OrganizationDomain, true>;

const orgRoleKeys = {
  id: true,
  organizationId: true,
  role: true,
  permissions: true,
  createdAt: true,
  updatedAt: true,
} satisfies Record<keyof OrgRole, true>;

const teamKeys = {
  id: true,
  organizationId: true,
  name: true,
  createdAt: true,
  updatedAt: true,
} satisfies Record<keyof Team, true>;

const teamMemberKeys = {
  id: true,
  teamId: true,
  userId: true,
  createdAt: true,
} satisfies Record<keyof TeamMember, true>;

// For the records below, `true` is a field the resource carries and `false` one
// it withholds from the wire (a secret's hash, internal bookkeeping), as the
// views before the resources withheld them.
const apiKeyKeys = {
  id: true,
  name: true,
  prefix: true,
  start: true,
  keyHash: false,
  userId: true,
  enabled: true,
  expiresAt: true,
  lastUsedAt: true,
  permissions: true,
  metadata: true,
  remaining: true,
  refillAmount: false,
  refillInterval: false,
  refillMax: false,
  lastRefillAt: false,
  rateLimit: true,
  createdAt: true,
  updatedAt: true,
} satisfies Record<keyof ApiKey, boolean>;

const oidcClientKeys = {
  clientId: true,
  clientSecretHash: false,
  name: true,
  redirectUris: true,
  type: true,
  skipConsent: true,
  disabled: true,
  metadata: true,
  userId: false,
  createdAt: true,
  updatedAt: true,
  registrationAccessTokenHash: false,
  tokenEndpointAuthMethod: false,
  grantTypes: false,
  responseTypes: false,
  scope: false,
  dynamicallyRegistered: false,
} satisfies Record<keyof OidcClient, boolean>;

const ssoProviderKeys = {
  // Both arms.
  id: true,
  domain: true,
  protocol: true,
  organizationId: true,
  userId: false,
  createdAt: true,
  // OIDC.
  issuer: true,
  clientId: true,
  clientSecret: false,
  redirectUri: true,
  authorizationEndpoint: true,
  tokenEndpoint: true,
  userInfoEndpoint: true,
  jwksEndpoint: true,
  scopes: true,
  usePKCE: false,
  // SAML.
  entityId: true,
  ssoUrl: true,
  idpCertificates: true,
  spEntityId: true,
  acsUrl: true,
  signatureAlgorithms: true,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: true,
  forceAuthn: true,
} satisfies Record<keyof OidcSsoProvider | keyof SamlSsoProvider, boolean>;

/** The fields of a key set the resource carries. */
const carried = (keys: Readonly<Record<string, boolean>>): ReadonlyArray<string> =>
  sorted(R.keys(R.filter(keys, (isCarried) => isCarried)));

// One declaration per entity (#205): each resource is the wire projection of
// a store-facing schema, so a field added to one and not the other fails here.
describe("the JSON:API resources", () => {
  it("users carry exactly Types.User, plus the derived email fields", () => {
    expect(storeFacingKeys(Resources.User, { derived: ["email", "emailVerified"] })).toStrictEqual(
      sorted(R.keys(User.fields)),
    );
  });

  it("sessions carry exactly Types.Session, userId as the user relationship", () => {
    expect(storeFacingKeys(Resources.Session, { foreignKeys: { user: "userId" } })).toStrictEqual(
      sorted(R.keys(Session.fields)),
    );
  });

  it("identifiers carry exactly Identifier, type as kind and userId as the user relationship", () => {
    expect(
      storeFacingKeys(Resources.Identifier, {
        renamed: { kind: "type" },
        foreignKeys: { user: "userId" },
      }),
    ).toStrictEqual(sorted(R.keys(Identifier.fields)));
  });

  it("device-sessions carry exactly Types.Session, plus the derived active flag", () => {
    expect(
      storeFacingKeys(Resources.DeviceSession, {
        derived: ["active"],
        foreignKeys: { user: "userId" },
      }),
    ).toStrictEqual(sorted(R.keys(Session.fields)));
  });

  it("organizations carry exactly Organization", () => {
    expect(storeFacingKeys(Resources.Organization)).toStrictEqual(sorted(R.keys(organizationKeys)));
  });

  it("organization-members carry exactly Member, its keys as relationships", () => {
    expect(
      storeFacingKeys(Resources.OrganizationMember, {
        foreignKeys: { organization: "organizationId", user: "userId" },
      }),
    ).toStrictEqual(sorted(R.keys(memberKeys)));
  });

  it("invitations carry exactly Invitation, its keys as relationships", () => {
    expect(
      storeFacingKeys(Resources.Invitation, {
        foreignKeys: { organization: "organizationId", inviter: "inviterId" },
      }),
    ).toStrictEqual(sorted(R.keys(invitationKeys)));
  });

  it("organization-domains carry exactly OrganizationDomain, its organization and attester as relationships", () => {
    expect(
      storeFacingKeys(Resources.OrganizationDomain, {
        foreignKeys: { organization: "organizationId", attester: "attestedBy" },
      }),
    ).toStrictEqual(sorted(R.keys(domainKeys)));
  });

  it("organization-roles carry exactly OrgRole, its organization as a relationship", () => {
    expect(
      storeFacingKeys(Resources.OrganizationRole, {
        foreignKeys: { organization: "organizationId" },
      }),
    ).toStrictEqual(sorted(R.keys(orgRoleKeys)));
  });

  it("teams carry exactly Team, its organization as a relationship", () => {
    expect(
      storeFacingKeys(Resources.Team, { foreignKeys: { organization: "organizationId" } }),
    ).toStrictEqual(sorted(R.keys(teamKeys)));
  });

  it("team-members carry exactly TeamMember, its keys as relationships", () => {
    expect(
      storeFacingKeys(Resources.TeamMember, {
        foreignKeys: { team: "teamId", user: "userId" },
      }),
    ).toStrictEqual(sorted(R.keys(teamMemberKeys)));
  });

  it("accepts writes only to a team's name and a role's permissions", () => {
    expect(sorted(R.keys(Resources.Team.updateInput.fields))).toStrictEqual(sorted(["id", "name"]));
    expect(sorted(R.keys(Resources.OrganizationRole.updateInput.fields))).toStrictEqual(
      sorted(["id", "permissions"]),
    );
    expect(sorted(R.keys(Resources.OrganizationDomain.createInput.fields))).toStrictEqual(
      sorted(["domain"]),
    );
  });

  it("accepts no write to a membership's previousRole or an invitation's invitee", () => {
    expect(sorted(R.keys(Resources.OrganizationMember.updateInput.fields))).toStrictEqual(
      sorted(["id", "role", "status"]),
    );
    expect(sorted(R.keys(Resources.Invitation.updateInput.fields))).toStrictEqual(
      sorted(["id", "status"]),
    );
  });

  it("accepts no write to the attributes bag (#193)", () => {
    // Only `name` and `image` are writable, and only on update.
    expect(sorted(R.keys(Resources.User.updateInput.fields))).toStrictEqual(
      sorted(["id", "name", "image"]),
    );
  });

  it("api-keys carry ApiKey but its hash and refill bookkeeping, userId as the user relationship", () => {
    expect(storeFacingKeys(Resources.ApiKey, { foreignKeys: { user: "userId" } })).toStrictEqual(
      carried(apiKeyKeys),
    );
  });

  it("oauth-clients carry OidcClient but its secrets and registration metadata, type as clientType", () => {
    expect(
      storeFacingKeys(Resources.OAuthClient, { id: "clientId", renamed: { clientType: "type" } }),
    ).toStrictEqual(carried(oidcClientKeys));
  });

  it("sso-providers carry both SsoProvider arms but the secret, organizationId as a relationship", () => {
    expect(
      storeFacingKeys(Resources.SsoProvider, { foreignKeys: { organization: "organizationId" } }),
    ).toStrictEqual(carried(ssoProviderKeys));
  });

  it("accepts writes to an API key's and an OAuth client's settings, never their secrets", () => {
    expect(sorted(R.keys(Resources.ApiKey.updateInput.fields))).toStrictEqual(
      sorted([
        "id",
        "name",
        "enabled",
        "expiresAt",
        "permissions",
        "metadata",
        "remaining",
        "rateLimit",
      ]),
    );
    expect(sorted(R.keys(Resources.OAuthClient.createInput.fields))).toStrictEqual(
      sorted(["name", "redirectUris", "clientType", "skipConsent", "metadata"]),
    );
    expect(sorted(R.keys(Resources.OAuthClient.updateInput.fields))).toStrictEqual(
      sorted(["id", "name", "redirectUris", "skipConsent", "disabled", "metadata"]),
    );
  });

  it("accepts no write to a ban, an impersonation, an SSO connection, a sign-in or a token", () => {
    const updatable = [
      Resources.UserBan,
      Resources.Impersonation,
      Resources.SsoProvider,
      Resources.SsoAuthorization,
      Resources.Token,
    ].map((resource) => R.keys(resource.updateInput.fields));
    expect(updatable).toStrictEqual([["id"], ["id"], ["id"], ["id"], ["id"]]);
  });
});
