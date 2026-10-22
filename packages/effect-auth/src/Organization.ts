/**
 * Organizations (multi-tenant teams) for effect-auth.
 *
 * Mirrors better-auth's organization plugin: users create organizations,
 * invite members by email, and manage member roles. Every mutating operation
 * is permission-checked against a configurable role → permission map using
 * `"resource:action"` permission strings.
 *
 * **Teams:** organizations can be subdivided into teams (see {@link Team}).
 * Team management is governed by the *organization*-scoped `team:*`
 * permissions; team membership itself carries no roles - it is a plain
 * `(teamId, userId)` association, and any organization member may read the
 * team structure. A user must already be a member of the team's organization
 * before they can be added to one of its teams.
 *
 * **Dynamic access control:** on top of the static `roles` config map, each
 * organization may define its own roles at runtime ({@link OrgRole}, managed
 * with {@link OrganizationService.upsertOrgRole} and friends). A custom role
 * *replaces* the static entry of the same name for that organization - the
 * two are never merged, so what a tenant sees is exactly what it defined.
 *
 * **Member status:** a membership can be deactivated ({@link Member.status})
 * instead of deleted. The row - and the member's team memberships and role -
 * survive, but every authorization question in the organization answers as if
 * the user were not a member. Application sessions are deliberately left
 * alone; see {@link OrganizationConfig.onMemberDeactivated}.
 *
 * **Domains:** an organization may claim email domains
 * ({@link OrganizationDomain}), each proved through DNS (via an app-provided
 * {@link DomainVerifier}) or attested manually. A *verified* domain is what
 * lets an SSO sign-in provision membership just in time, per organization and
 * off by default ({@link Organization.jitProvisioning}).
 *
 * **Active organization:** this module deliberately does not manage a
 * per-session "active organization" (better-auth's `setActiveOrganization`).
 * The conventional integration is to store the selected organization id on
 * the session's attribute bag - e.g.
 * `sessionManager.createSession(userId, { activeOrganizationId: org.id })`
 * or by updating `session.attributes.activeOrganizationId` through your
 * session store - and read it back from `session.attributes` when handling
 * requests.
 *
 * @module organization
 */

import { Array as Arr, Context, Crypto, Data, Effect, Layer, Option, Order, Result } from "effect";
import { IdentifierStore } from "./Identifier.ts";
import * as Errors from "./Errors.ts";
import { parsePermission, permissionMatches } from "./Permission.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { normalizeEmail } from "./utils.ts";

/**
 * Organization error
 */
export class OrganizationError extends Data.TaggedError("OrganizationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * An organization (team / tenant).
 */
export interface Organization {
  readonly id: string;
  readonly name: string;
  /** URL-friendly unique identifier */
  readonly slug: string;
  readonly logo?: string;
  /** Arbitrary app-specific metadata */
  readonly metadata: Record<string, unknown>;
  /**
   * Role given to members added without an explicit one (direct
   * {@link OrganizationService.addMember}, JIT provisioning, SCIM). Absent
   * means `"member"`. Only owners may change it - see
   * {@link OrganizationService.setDefaultRole}.
   */
  readonly defaultRole?: string;
  /**
   * Whether a user signing in through SSO whose verified email domain matches
   * one of this organization's *verified* domains is added as a member
   * automatically. Absent means `false`: silent domain absorption is opt-in.
   */
  readonly jitProvisioning?: boolean;
  /** Epoch milliseconds */
  readonly createdAt: number;
}

/**
 * Lifecycle states of a membership.
 *
 * An `inactive` member keeps its row (history, team memberships and the
 * restorable role survive) but is treated as a non-member by every
 * authorization question - see {@link isActiveMember}.
 */
export type MemberStatus = "active" | "inactive";

/**
 * A user's membership in an organization.
 */
export interface Member {
  readonly id: string;
  readonly organizationId: string;
  readonly userId: string;
  /** Role name, resolved against the configured role → permission map */
  readonly role: string;
  /**
   * Membership lifecycle state. Absent means `"active"`, so rows written
   * before member deactivation existed keep working unchanged.
   */
  readonly status?: MemberStatus;
  /**
   * The role the member held when they were deactivated, restored on
   * reactivation. Only set while `status` is `"inactive"`.
   */
  readonly previousRole?: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
}

/**
 * Whether a membership counts for authorization: `status` absent (the
 * historical shape) or `"active"`.
 */
export const isActiveMember = (member: Member): boolean => member.status !== "inactive";

/**
 * Lifecycle states of an invitation.
 */
export type InvitationStatus = "pending" | "accepted" | "rejected" | "canceled";

/**
 * An email invitation to join an organization.
 */
export interface Invitation {
  readonly id: string;
  readonly organizationId: string;
  /** Normalized (trimmed, lowercased) invitee email */
  readonly email: string;
  /** Role the invitee receives upon acceptance */
  readonly role: string;
  readonly status: InvitationStatus;
  /** User id of the member who created the invitation */
  readonly inviterId: string;
  /** Epoch milliseconds */
  readonly expiresAt: number;
  /** Epoch milliseconds */
  readonly createdAt: number;
}

/**
 * A team: a named sub-group of an organization.
 *
 * Teams are managed with the organization-scoped `team:*` permissions; the
 * membership rows ({@link TeamMember}) deliberately carry no role of their own.
 */
export interface Team {
  readonly id: string;
  readonly organizationId: string;
  readonly name: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
  /** Epoch milliseconds */
  readonly updatedAt: number;
}

/**
 * A user's membership in a team.
 *
 * Team membership is orthogonal to the organization role: it grants no
 * permissions by itself. The user is always also a {@link Member} of the
 * team's organization.
 */
export interface TeamMember {
  readonly teamId: string;
  readonly userId: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
}

/**
 * A role defined at runtime by one organization (dynamic access control).
 *
 * An `OrgRole` **replaces** the static {@link OrganizationConfig.roles} entry
 * of the same name, for that organization only: permission resolution never
 * merges the two, so a tenant's role grants exactly the permissions it lists.
 * Permissions are `"resource:action"` strings and may use the `"*"` wildcard
 * (`"team:*"`, `"*:*"`), matched with `permissionMatches`.
 *
 * The protected owner role (`config.creatorRole`, default `owner`) can never
 * be redefined this way - see {@link OrganizationService.upsertOrgRole}.
 */
export interface OrgRole {
  readonly organizationId: string;
  /** Role name, as it appears on a {@link Member} */
  readonly role: string;
  /** `"resource:action"` permission strings, `"*"` wildcards allowed */
  readonly permissions: ReadonlyArray<string>;
  /** Epoch milliseconds */
  readonly createdAt: number;
  /** Epoch milliseconds */
  readonly updatedAt: number;
}

/**
 * How far along a domain claim is.
 *
 * `pending` - the claim exists but nothing has proved it yet; `verified` - the
 * organization has proved control (and only then does the domain carry any
 * authority, e.g. for JIT provisioning); `failed` - the last verification
 * attempt did not find the proof. A `failed` claim can be retried.
 */
export type DomainVerificationState = "pending" | "verified" | "failed";

/**
 * How a domain claim is proved.
 *
 * `dns` - a TXT record carrying {@link OrganizationDomain.verificationToken},
 * checked by a {@link DomainVerifier} the app provides; `manual` - the app (or
 * an org owner/admin acting through the verify endpoint) attests to it out of
 * band.
 */
export type DomainVerificationStrategy = "dns" | "manual";

/**
 * An email domain claimed by an organization.
 *
 * Domains are globally unique: `domain` identifies at most one row across all
 * organizations, pending claims included. Allowing two tenants to hold pending
 * claims on the same domain would make "who gets it" a race decided by
 * verification order, and would leak one tenant's claim to another - so a
 * second organization claiming a domain is refused outright, whatever state
 * the first claim is in.
 */
export interface OrganizationDomain {
  readonly id: string;
  readonly organizationId: string;
  /** Normalized (trimmed, lowercased) domain, e.g. `"acme.test"` */
  readonly domain: string;
  readonly verificationState: DomainVerificationState;
  readonly verificationStrategy: DomainVerificationStrategy;
  /**
   * Random token the DNS TXT record must contain, generated server-side when
   * the claim is added with the `dns` strategy. Absent for `manual` claims.
   */
  readonly verificationToken?: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
  /** Epoch milliseconds; set when the claim reached `verified` */
  readonly verifiedAt?: number;
}

/**
 * Storage for {@link OrganizationDomain} claims.
 *
 * A separate contract from {@link OrganizationStore} so apps that never use
 * domains implement nothing: {@link OrganizationService} resolves it from
 * ambient context and answers "Organization domains are not enabled" when it
 * is absent, exactly as the SAML pieces do in `Sso.ts`.
 *
 * Conventions: lookups answer `null` when the record does not exist, deletes of
 * unknown ids are no-ops, and failures are reported as `AuthError`. Put a
 * unique index on `domain` - the service checks for a conflicting claim before
 * writing, but the index is what makes the guarantee hold under concurrency.
 * {@link OrganizationService.deleteOrganization} releases an organization's
 * claims before deleting it, so this store needs no cascade of its own - but a
 * direct `OrganizationStore.deleteOrganization` call bypasses that, so delete
 * the domain rows alongside it if you go around the service.
 */
export class OrganizationDomainStore extends Context.Service<
  OrganizationDomainStore,
  {
    readonly create: (
      domain: OrganizationDomain,
    ) => Effect.Effect<OrganizationDomain, Errors.AuthError>;
    readonly getById: (
      domainId: string,
    ) => Effect.Effect<OrganizationDomain | null, Errors.AuthError>;
    /** Resolve a claim by its normalized domain, across every organization. */
    readonly getByDomain: (
      domain: string,
    ) => Effect.Effect<OrganizationDomain | null, Errors.AuthError>;
    readonly listByOrganization: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<OrganizationDomain>, Errors.AuthError>;
    readonly update: (
      domain: OrganizationDomain,
    ) => Effect.Effect<OrganizationDomain, Errors.AuthError>;
    /** Release a claim. A no-op for unknown ids. */
    readonly delete: (domainId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/OrganizationDomainStore") {}

/**
 * In-memory {@link OrganizationDomainStore}, keyed by claim id. Single-process
 * only - good for tests and single-instance deployments.
 *
 * Pass your own `Map` to inspect or pre-seed state in tests.
 */
export const memoryOrganizationDomainStore = (
  records: Map<string, OrganizationDomain> = new Map(),
): typeof OrganizationDomainStore.Service => ({
  create: (domain) => Effect.sync(() => (records.set(domain.id, domain), domain)),
  getById: (domainId) => Effect.sync(() => records.get(domainId) ?? null),
  getByDomain: (domain) =>
    Effect.sync(() => [...records.values()].find((record) => record.domain === domain) ?? null),
  listByOrganization: (organizationId) =>
    Effect.sync(() =>
      Arr.sort(
        [...records.values()].filter((record) => record.organizationId === organizationId),
        Order.mapInput(Order.Number, (record: OrganizationDomain) => record.createdAt),
      ),
    ),
  update: (domain) => Effect.sync(() => (records.set(domain.id, domain), domain)),
  delete: (domainId) => Effect.sync(() => void records.delete(domainId)),
});

/**
 * Proof-of-control check for a claimed domain, kept as a contract so core adds
 * no DNS dependency.
 *
 * `verify` answers whether `domain` currently publishes `token` (conventionally
 * as a TXT record). Implement it over whatever resolver your runtime has - Node
 * `dns/promises`, Cloudflare's DoH endpoint, a hosting provider's API - and
 * provide it with `Layer.succeed(DomainVerifier)(impl)`. Without it in context
 * the `dns` strategy is unavailable and `manual` attestation is the only route
 * to a verified domain.
 */
export class DomainVerifier extends Context.Service<
  DomainVerifier,
  {
    readonly verify: (domain: string, token: string) => Effect.Effect<boolean, Errors.AuthError>;
  }
>()("@effect-auth/DomainVerifier") {}

/**
 * Default role → permission map, mirroring better-auth's built-in
 * organization roles. Permissions are `"resource:action"` strings.
 *
 * - `owner` - full control (organization update/delete, member, invitation,
 *   domain and team management, plus `role:manage` for custom organization
 *   roles and the organization's default role)
 * - `admin` - member, invitation, domain and team management plus organization
 *   updates, but cannot delete the organization or manage custom roles
 * - `member` - read-only participant (no management permissions; may still
 *   read the organization's teams and domains)
 *
 * Override via {@link OrganizationConfig.roles}. A map that omits
 * `domain:manage` simply leaves domain management to nobody - resolution fails
 * closed, as it does for every other permission.
 */
export const defaultOrganizationRoles: Record<string, ReadonlyArray<string>> = {
  owner: [
    "organization:update",
    "organization:delete",
    "member:create",
    "member:update",
    "member:delete",
    "invitation:create",
    "invitation:cancel",
    "domain:manage",
    "team:create",
    "team:update",
    "team:delete",
    "team:manage-members",
    "role:manage",
  ],
  admin: [
    "organization:update",
    "member:create",
    "member:update",
    "member:delete",
    "invitation:create",
    "invitation:cancel",
    "domain:manage",
    "team:create",
    "team:update",
    "team:delete",
    "team:manage-members",
  ],
  member: [],
};

/**
 * Storage interface for organizations, members, invitations, teams, and
 * custom organization roles. Implement with your preferred backend (SQL,
 * Redis, ...).
 *
 * Note: `deleteOrganization` should cascade - implementations are expected to
 * remove the organization's members, invitations, teams, team memberships,
 * and custom roles ({@link OrgRole}) as well. `deleteTeam` cascades too: it
 * must remove the team's team-member rows along with the team.
 *
 * Conventions: lookups answer `null` when the record does not exist, deletes
 * of unknown ids are no-ops, and failures are reported as `AuthError`.
 */
export class OrganizationStore extends Context.Service<
  OrganizationStore,
  {
    readonly createOrganization: (
      organization: Organization,
    ) => Effect.Effect<Organization, Errors.AuthError>;
    readonly getOrganizationById: (
      organizationId: string,
    ) => Effect.Effect<Organization | null, Errors.AuthError>;
    readonly getOrganizationBySlug: (
      slug: string,
    ) => Effect.Effect<Organization | null, Errors.AuthError>;
    readonly updateOrganization: (
      organization: Organization,
    ) => Effect.Effect<Organization, Errors.AuthError>;
    readonly deleteOrganization: (organizationId: string) => Effect.Effect<void, Errors.AuthError>;

    readonly createMember: (member: Member) => Effect.Effect<Member, Errors.AuthError>;
    readonly getMember: (
      organizationId: string,
      userId: string,
    ) => Effect.Effect<Member | null, Errors.AuthError>;
    readonly updateMember: (member: Member) => Effect.Effect<Member, Errors.AuthError>;
    readonly deleteMember: (memberId: string) => Effect.Effect<void, Errors.AuthError>;
    readonly listMembersByOrganization: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<Member>, Errors.AuthError>;
    readonly listMembersByUser: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Member>, Errors.AuthError>;
    readonly countMembersByOrganization: (
      organizationId: string,
    ) => Effect.Effect<number, Errors.AuthError>;

    readonly createInvitation: (
      invitation: Invitation,
    ) => Effect.Effect<Invitation, Errors.AuthError>;
    readonly getInvitation: (
      invitationId: string,
    ) => Effect.Effect<Invitation | null, Errors.AuthError>;
    readonly updateInvitation: (
      invitation: Invitation,
    ) => Effect.Effect<Invitation, Errors.AuthError>;
    readonly listInvitationsByOrganization: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;
    readonly listInvitationsByEmail: (
      email: string,
    ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;

    readonly createTeam: (team: Team) => Effect.Effect<Team, Errors.AuthError>;
    readonly getTeam: (teamId: string) => Effect.Effect<Team | null, Errors.AuthError>;
    /** Persist an updated team; answers `null` when the team no longer exists. */
    readonly updateTeam: (team: Team) => Effect.Effect<Team | null, Errors.AuthError>;
    /** Delete a team *and* its team-member rows. A no-op for unknown ids. */
    readonly deleteTeam: (teamId: string) => Effect.Effect<void, Errors.AuthError>;
    readonly listTeams: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<Team>, Errors.AuthError>;

    readonly addTeamMember: (
      teamId: string,
      userId: string,
    ) => Effect.Effect<TeamMember, Errors.AuthError>;
    /** Remove a team membership. A no-op when the user is not in the team. */
    readonly removeTeamMember: (
      teamId: string,
      userId: string,
    ) => Effect.Effect<void, Errors.AuthError>;
    readonly listTeamMembers: (
      teamId: string,
    ) => Effect.Effect<ReadonlyArray<TeamMember>, Errors.AuthError>;
    /** The teams of `organizationId` that `userId` belongs to. */
    readonly listTeamsForMember: (
      organizationId: string,
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Team>, Errors.AuthError>;

    /**
     * Create or replace a custom role definition, keyed by
     * `(organizationId, role)`.
     */
    readonly upsertOrgRole: (orgRole: OrgRole) => Effect.Effect<OrgRole, Errors.AuthError>;
    readonly getOrgRole: (
      organizationId: string,
      role: string,
    ) => Effect.Effect<OrgRole | null, Errors.AuthError>;
    readonly listOrgRoles: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<OrgRole>, Errors.AuthError>;
    /** Delete a custom role definition. A no-op when it does not exist. */
    readonly deleteOrgRole: (
      organizationId: string,
      role: string,
    ) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/OrganizationStore") {}

/**
 * Organization service configuration
 */
export interface OrganizationConfig {
  /** Whether users may create organizations at all (default: true) */
  readonly allowUserToCreateOrganization?: boolean;
  /** Maximum number of organizations a user may belong to (default: 5) */
  readonly organizationLimit?: number;
  /** Maximum number of members per organization (default: 100) */
  readonly membershipLimit?: number;
  /** Invitation lifetime in milliseconds (default: 48 hours) */
  readonly invitationExpiresIn?: number;
  /** Role assigned to the creator of an organization (default: "owner").
   * This role is also treated as the protected "owner" role for the
   * last-owner safeguards in `removeMember`/`updateMemberRole`. */
  readonly creatorRole?: string;
  /**
   * Static role → permission map (default: {@link defaultOrganizationRoles}).
   * A per-organization {@link OrgRole} of the same name replaces the entry
   * here for that organization.
   */
  readonly roles?: Record<string, ReadonlyArray<string>>;
  /** Optional invitation email delivery */
  readonly sendInvitationEmail?: (
    invitation: Invitation,
    organization: Organization,
  ) => Effect.Effect<void, OrganizationError>;
  /**
   * Called after a member is deactivated, with the updated (inactive)
   * membership.
   *
   * **Deliberate deviation from WorkOS:** deactivating a member there ends
   * that user's sessions. Here it does not, because a session is *app*-scoped
   * while a membership is *organization*-scoped: one user may belong to
   * several organizations, and revoking their sessions because one tenant
   * deactivated them would sign them out of the others too. Everything
   * organization-scoped is already denied the moment the row flips (every
   * permission check treats an inactive member as a non-member), so what
   * remains is an app-level policy question - single-tenant apps usually do
   * want the sign-out, multi-tenant ones usually do not. This hook is where
   * that policy goes: call
   * `sessionManager.invalidateUserSessions(member.userId)` from it if your app
   * wants WorkOS's behavior.
   *
   * Failures propagate to the caller of `deactivateMember` (the membership is
   * already stored by then), matching `sendInvitationEmail`.
   */
  readonly onMemberDeactivated?: (
    member: Member,
    organization: Organization,
  ) => Effect.Effect<void, OrganizationError>;
}

/**
 * Input for creating an organization
 */
export interface CreateOrganizationInput {
  readonly name: string;
  readonly slug: string;
  readonly logo?: string;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Partial update of an organization's fields
 */
export interface UpdateOrganizationInput {
  readonly name?: string;
  readonly slug?: string;
  readonly logo?: string;
  readonly metadata?: Record<string, unknown>;
  /**
   * Turn JIT provisioning on or off. Gated on `organization:update` like the
   * rest of this input - the same tier that adds the verified domains JIT
   * acts on. The *role* JIT hands out stays owner-only
   * ({@link OrganizationService.setDefaultRole}).
   */
  readonly jitProvisioning?: boolean;
}

/**
 * Input for claiming an email domain for an organization
 */
export interface AddOrganizationDomainInput {
  /** Domain to claim; normalized (trimmed, lowercased) before storage */
  readonly domain: string;
  /** Defaults to `"dns"` */
  readonly verificationStrategy?: DomainVerificationStrategy;
}

/**
 * Input for inviting a member by email
 */
export interface InviteMemberInput {
  readonly email: string;
  readonly role: string;
}

/**
 * Input for creating a team
 */
export interface CreateTeamInput {
  readonly name: string;
}

/**
 * Partial update of a team's fields
 */
export interface UpdateTeamInput {
  readonly name?: string;
}

/**
 * Input for defining (or redefining) a custom organization role
 */
export interface UpsertOrgRoleInput {
  /** Role name; the protected owner role is rejected */
  readonly role: string;
  /** `"resource:action"` permission strings, `"*"` wildcards allowed */
  readonly permissions: ReadonlyArray<string>;
}

/**
 * An organization together with its member list
 */
export interface FullOrganization {
  readonly organization: Organization;
  readonly members: ReadonlyArray<Member>;
}

/**
 * Organization service
 */
export class OrganizationService extends Context.Service<
  OrganizationService,
  {
    /**
     * Create an organization. Enforces `allowUserToCreateOrganization`,
     * `organizationLimit` (organizations the user already belongs to) and slug
     * uniqueness. The creator becomes a member with `creatorRole`.
     */
    readonly createOrganization: (
      userId: string,
      input: CreateOrganizationInput,
    ) => Effect.Effect<Organization, OrganizationError | Errors.AuthError>;

    /**
     * Update an organization's fields. Requires the `organization:update`
     * permission. Slug changes are checked for uniqueness.
     */
    readonly updateOrganization: (
      userId: string,
      organizationId: string,
      updates: UpdateOrganizationInput,
    ) => Effect.Effect<Organization, OrganizationError | Errors.AuthError>;

    /**
     * Delete an organization. Requires the `organization:delete` permission.
     * Its domain claims are released first (they are globally unique, so
     * leaving them behind would squat those domains forever); the store
     * cascades members, invitations, teams and custom roles.
     */
    readonly deleteOrganization: (
      userId: string,
      organizationId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * Fetch an organization together with all of its members.
     */
    readonly getFullOrganization: (
      organizationId: string,
    ) => Effect.Effect<FullOrganization, OrganizationError | Errors.AuthError>;

    /**
     * List the organizations a user belongs to.
     */
    readonly listOrganizations: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Organization>, Errors.AuthError>;

    /**
     * Invite a user (by email) to the organization. Requires the
     * `invitation:create` permission. Rejects duplicate pending invitations for
     * the same email + organization and enforces `membershipLimit`. When
     * `sendInvitationEmail` is configured it is invoked with the created
     * invitation.
     */
    readonly inviteMember: (
      inviterId: string,
      organizationId: string,
      input: InviteMemberInput,
    ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError>;

    /**
     * Accept a pending invitation. Validates that the invitation is pending,
     * unexpired, and addressed to one of the user's email identifiers.
     * Creates the membership and marks
     * the invitation accepted.
     */
    readonly acceptInvitation: (
      userId: string,
      invitationId: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Reject a pending invitation addressed to one of the user's email
     * identifiers.
     */
    readonly rejectInvitation: (
      userId: string,
      invitationId: string,
    ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError>;

    /**
     * Cancel a pending invitation. The canceler needs the `invitation:cancel`
     * permission in the invitation's organization.
     */
    readonly cancelInvitation: (
      cancelerId: string,
      invitationId: string,
    ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError>;

    /**
     * List all invitations for an organization (any status).
     */
    readonly listInvitations: (
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;

    /**
     * List pending, unexpired invitations addressed to an email.
     */
    readonly listUserInvitations: (
      email: string,
    ) => Effect.Effect<ReadonlyArray<Invitation>, Errors.AuthError>;

    /**
     * Resend a pending invitation: the same row and id, its `expiresAt` pushed
     * out by the configured invitation TTL from now, and
     * `sendInvitationEmail` invoked again. Requires the `invitation:create`
     * permission, like issuing one. Unknown, accepted, rejected and canceled
     * invitations are refused with an `OrganizationError` rather than silently
     * re-issued.
     */
    readonly resendInvitation: (
      actorId: string,
      invitationId: string,
    ) => Effect.Effect<Invitation, OrganizationError | Errors.AuthError>;

    /**
     * Add a user to the organization directly (no invitation). Requires the
     * `member:create` permission and enforces `membershipLimit`. Omitting
     * `role` uses the organization's `defaultRole` (default `"member"`).
     */
    readonly addMember: (
      actorId: string,
      organizationId: string,
      userId: string,
      role?: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Remove a member. Requires the `member:delete` permission. An owner can
     * only be removed by another owner, and the last owner can never be
     * removed. Cascades: the member's memberships in the organization's teams
     * are removed as well.
     */
    readonly removeMember: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * Change a member's role. Requires the `member:update` permission. The last
     * active owner cannot be demoted, and an inactive member's role is not
     * editable - reactivate them first, or the restore would overwrite the
     * change.
     */
    readonly updateMemberRole: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
      role: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Suspend a membership without deleting it. Requires the `member:update`
     * permission; an owner may only be deactivated by another owner, and the
     * last active owner never can.
     *
     * The row survives (history, team memberships and the member's role, kept
     * in `previousRole`), the member is demoted to the organization's
     * `defaultRole` so nothing reading `member.role` directly - the entity
     * projection, your own dashboards - still sees a privileged role, and
     * every permission check in this organization now denies them.
     * Application sessions are deliberately *not* revoked; see
     * {@link OrganizationConfig.onMemberDeactivated}.
     */
    readonly deactivateMember: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Restore a deactivated membership, putting back the role it held when it
     * was deactivated. Requires the `member:update` permission. No capacity
     * check: the row never stopped occupying a seat, so reactivating it adds
     * nothing to `membershipLimit`.
     */
    readonly reactivateMember: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Set the role new members receive when none is given (direct
     * `addMember`, JIT provisioning, SCIM). Requires the `role:manage`
     * permission - owner-only by default, matching custom-role management -
     * and the role must exist in the organization's role set (a custom
     * {@link OrgRole} or an entry of the static `config.roles` map).
     */
    readonly setDefaultRole: (
      actorUserId: string,
      organizationId: string,
      role: string,
    ) => Effect.Effect<Organization, OrganizationError | Errors.AuthError>;

    /**
     * List an organization's claimed email domains. Any member may do so.
     */
    readonly listDomains: (
      actorUserId: string,
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<OrganizationDomain>, OrganizationError | Errors.AuthError>;

    /**
     * Claim an email domain for the organization. Requires the
     * `domain:manage` permission. The claim starts `pending`; with the `dns`
     * strategy a random verification token is generated server-side to publish
     * as a TXT record. A domain already claimed by any organization - pending
     * or verified - is refused.
     */
    readonly addDomain: (
      actorUserId: string,
      organizationId: string,
      input: AddOrganizationDomainInput,
    ) => Effect.Effect<OrganizationDomain, OrganizationError | Errors.AuthError>;

    /**
     * Release a domain claim. Requires the `domain:manage` permission.
     * Releasing an unknown id is refused (the id is scoped to the
     * organization, so a wrong one is a mistake, not a no-op).
     */
    readonly removeDomain: (
      actorUserId: string,
      organizationId: string,
      domainId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * Attempt to verify a domain claim. Requires the `domain:manage`
     * permission.
     *
     * `dns` claims ask the ambient {@link DomainVerifier} whether the domain
     * publishes the claim's token; without that service the strategy is
     * unavailable and the call fails. `manual` claims are attested by the
     * caller's `domain:manage` permission alone. A failed DNS check answers
     * with the claim in state `"failed"` (retryable) rather than an error -
     * "the record is not there yet" is an outcome, not a fault.
     */
    readonly verifyDomain: (
      actorUserId: string,
      organizationId: string,
      domainId: string,
    ) => Effect.Effect<OrganizationDomain, OrganizationError | Errors.AuthError>;

    /**
     * Just-in-time membership for an SSO sign-in: if `email`'s domain is a
     * *verified* domain of an organization with `jitProvisioning` enabled and
     * the user is not a member yet, add them as an active member with that
     * organization's `defaultRole`.
     *
     * Answers the new membership, or `null` when nothing applies (no matching
     * domain, the claim is not verified, JIT is off, the user is already a
     * member, or no {@link OrganizationDomainStore} is configured). Callers
     * must only pass addresses whose ownership has been proved - this is what
     * turns a domain claim into membership.
     */
    readonly provisionJitMembership: (
      userId: string,
      email: string,
    ) => Effect.Effect<Member | null, OrganizationError | Errors.AuthError>;

    /**
     * Create a team inside an organization. Requires the `team:create`
     * permission.
     */
    readonly createTeam: (
      actorUserId: string,
      organizationId: string,
      input: CreateTeamInput,
    ) => Effect.Effect<Team, OrganizationError | Errors.AuthError>;

    /**
     * Rename a team. Requires the `team:update` permission in the team's
     * organization.
     */
    readonly updateTeam: (
      actorUserId: string,
      teamId: string,
      input: UpdateTeamInput,
    ) => Effect.Effect<Team, OrganizationError | Errors.AuthError>;

    /**
     * Delete a team, along with its memberships. Requires the `team:delete`
     * permission in the team's organization.
     */
    readonly deleteTeam: (
      actorUserId: string,
      teamId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * Add a user to a team. Requires the `team:manage-members` permission in
     * the team's organization. The target user must already be a member of
     * that organization, and must not already be in the team.
     */
    readonly addTeamMember: (
      actorUserId: string,
      teamId: string,
      memberUserId: string,
    ) => Effect.Effect<TeamMember, OrganizationError | Errors.AuthError>;

    /**
     * Remove a user from a team. Requires the `team:manage-members` permission
     * in the team's organization.
     */
    readonly removeTeamMember: (
      actorUserId: string,
      teamId: string,
      memberUserId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * List an organization's teams. Any member of the organization may do so.
     */
    readonly listTeams: (
      actorUserId: string,
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<Team>, OrganizationError | Errors.AuthError>;

    /**
     * List a team's members. Any member of the team's organization may do so.
     */
    readonly listTeamMembers: (
      actorUserId: string,
      teamId: string,
    ) => Effect.Effect<ReadonlyArray<TeamMember>, OrganizationError | Errors.AuthError>;

    /**
     * List the organization's teams a given user belongs to. Any member of the
     * organization may do so.
     */
    readonly listTeamsForMember: (
      actorUserId: string,
      organizationId: string,
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Team>, OrganizationError | Errors.AuthError>;

    /**
     * Define or redefine a custom role for the organization. Requires the
     * `role:manage` permission (owner-only by default).
     *
     * The definition *replaces* the static `config.roles` entry of the same
     * name for this organization, and takes effect immediately for every
     * member holding the role. Redefining the protected owner role
     * (`config.creatorRole`, default `owner`) is refused with an
     * `OrganizationError`: owner semantics stay static, so a tenant can never
     * lock itself out of role management.
     */
    readonly upsertOrgRole: (
      actorUserId: string,
      organizationId: string,
      input: UpsertOrgRoleInput,
    ) => Effect.Effect<OrgRole, OrganizationError | Errors.AuthError>;

    /**
     * Remove a custom role definition, falling back to the static
     * `config.roles` entry (if any) for members still holding the role.
     * Requires the `role:manage` permission; deleting the protected owner
     * role is refused, and deleting a role that was never defined is a no-op.
     */
    readonly deleteOrgRole: (
      actorUserId: string,
      organizationId: string,
      role: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * List the organization's custom role definitions. Any member of the
     * organization may do so.
     */
    readonly listOrgRoles: (
      actorUserId: string,
      organizationId: string,
    ) => Effect.Effect<ReadonlyArray<OrgRole>, OrganizationError | Errors.AuthError>;

    /**
     * Whether the user's role in the organization grants the given
     * `"resource:action"` permission - resolved against the organization's
     * custom {@link OrgRole} first, then the static `config.roles` map, and
     * denied when neither defines the role. Non-members - and *inactive*
     * members, which every authorization path treats as non-members - simply
     * get `false`.
     */
    readonly checkPermission: (
      userId: string,
      organizationId: string,
      permission: string,
    ) => Effect.Effect<boolean, Errors.AuthError>;

    /**
     * Like {@link checkPermission} but fails with `OrganizationError` when the
     * permission is not granted.
     */
    readonly requirePermission: (
      userId: string,
      organizationId: string,
      permission: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;
  }
>()("@effect-auth/OrganizationService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: OrganizationConfig = {}) =>
    Layer.effect(OrganizationService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/** Trim surrounding whitespace and lower-case a domain. */
const normalizeDomain = (domain: string): string => domain.trim().toLowerCase();

/** The domain part of an email address, normalized; `""` when there is none. */
const domainOfEmail = (email: string): string => normalizeDomain(email.split("@")[1] ?? "");

/**
 * Create an organization service
 */
export const make = (
  config: OrganizationConfig = {},
): Effect.Effect<
  typeof OrganizationService.Service,
  never,
  OrganizationStore | IdentifierStore | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const allowUserToCreateOrganization = config.allowUserToCreateOrganization ?? true;
    const organizationLimit = config.organizationLimit ?? 5;
    const membershipLimit = config.membershipLimit ?? 100;
    const invitationExpiresIn = config.invitationExpiresIn ?? 48 * 60 * 60 * 1000; // 48 hours
    const creatorRole = config.creatorRole ?? "owner";
    const roles = config.roles ?? defaultOrganizationRoles;

    const store = yield* OrganizationStore;
    const identifiers = yield* IdentifierStore;
    const crypto = yield* Crypto.Crypto;

    /**
     * Domains are an optional half of the module: resolved from ambient
     * context so apps that never claim one implement no extra store. Every
     * domain path goes through {@link requireDomainStore}, which explains the
     * absence rather than failing obscurely.
     */
    const domainStoreOption = yield* Effect.serviceOption(OrganizationDomainStore);
    const domainVerifierOption = yield* Effect.serviceOption(DomainVerifier);

    /** Generate a random identifier for organizations, members, and invitations. */
    const generateId = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(16).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("hex")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate id", cause }),
        ),
      );

    /**
     * Whether one granted permission string satisfies a requested one.
     *
     * Exact equality first - that is the historical behavior of the static
     * role map, and the only thing a string without a `:` separator can
     * support - then `"*"` wildcard matching via `permissionMatches`, so
     * `"team:*"` covers `"team:create"` exactly as an admin grant does.
     * Unparseable grants never match anything but themselves.
     */
    const grantSatisfies = (granted: string, requested: string): boolean => {
      if (granted === requested) return true;
      return Result.getOrElse(
        Result.try(() => permissionMatches(parsePermission(granted), parsePermission(requested))),
        () => false,
      );
    };

    /**
     * The permissions a role name resolves to in an organization: the custom
     * {@link OrgRole} when one exists (it *replaces* the static entry - no
     * merging), else the static `config.roles` entry, else `null` for an
     * unknown role (fail closed: no permissions at all).
     */
    const resolveRolePermissions = (
      organizationId: string,
      role: string,
    ): Effect.Effect<ReadonlyArray<string> | null, Errors.AuthError> =>
      Effect.gen(function* () {
        const custom = yield* store.getOrgRole(organizationId, role);
        if (custom) return custom.permissions;
        return roles[role] ?? null;
      });

    /** Whether a member's role grants a `"resource:action"` permission. */
    const roleHasPermission = (
      organizationId: string,
      role: string,
      permission: string,
    ): Effect.Effect<boolean, Errors.AuthError> =>
      Effect.map(
        resolveRolePermissions(organizationId, role),
        (permissions) =>
          permissions !== null &&
          permissions.some((granted) => grantSatisfies(granted, permission)),
      );

    /** Load an organization, failing when it does not exist. */
    const getOrganizationOrFail = (organizationId: string) =>
      Effect.gen(function* () {
        const organization = yield* store.getOrganizationById(organizationId);
        if (!organization) {
          return yield* new OrganizationError({ message: "Organization not found" });
        }
        return organization;
      });

    /**
     * The actor's membership *for authorization purposes*: the row only counts
     * while it is active, so a deactivated member is indistinguishable from a
     * stranger everywhere a permission is decided.
     */
    const getActiveMember = (organizationId: string, userId: string) =>
      Effect.map(store.getMember(organizationId, userId), (member) =>
        member !== null && isActiveMember(member) ? member : null,
      );

    /**
     * Resolve the actor's membership and enforce a permission, returning the
     * membership so callers can inspect the actor's role.
     */
    const requireMemberPermission = (userId: string, organizationId: string, permission: string) =>
      Effect.gen(function* () {
        const member = yield* getActiveMember(organizationId, userId);
        const granted =
          member !== null && (yield* roleHasPermission(organizationId, member.role, permission));
        if (!member || !granted) {
          return yield* new OrganizationError({
            message: `Missing permission '${permission}' in this organization`,
          });
        }
        return member;
      });

    /**
     * Resolve the actor's membership without requiring any permission - used
     * by the read-only team/domain/role listings, which any organization
     * member may call. Inactive members are not members here either.
     */
    const requireMembership = (userId: string, organizationId: string) =>
      Effect.gen(function* () {
        const member = yield* getActiveMember(organizationId, userId);
        if (!member) {
          return yield* new OrganizationError({
            message: "You are not a member of this organization",
          });
        }
        return member;
      });

    /** Resolve the domain store, explaining its absence when it is not wired. */
    const requireDomainStore = Effect.fn("requireDomainStore")(function* () {
      if (Option.isNone(domainStoreOption)) {
        return yield* new OrganizationError({
          message: "Organization domains are not enabled: provide an OrganizationDomainStore layer",
        });
      }
      return domainStoreOption.value;
    });

    /** Load a team, failing when it does not exist. */
    const getTeamOrFail = (teamId: string) =>
      Effect.gen(function* () {
        const team = yield* store.getTeam(teamId);
        if (!team) {
          return yield* new OrganizationError({ message: "Team not found" });
        }
        return team;
      });

    /**
     * Load a team and enforce a permission in *its* organization, returning the
     * team so callers can use its `organizationId`.
     */
    const requireTeamPermission = (userId: string, teamId: string, permission: string) =>
      Effect.gen(function* () {
        const team = yield* getTeamOrFail(teamId);
        yield* requireMemberPermission(userId, team.organizationId, permission);
        return team;
      });

    /** Enforce the per-organization membership limit before adding a member. */
    const ensureMembershipCapacity = (organizationId: string) =>
      Effect.gen(function* () {
        const count = yield* store.countMembersByOrganization(organizationId);
        if (count >= membershipLimit) {
          return yield* new OrganizationError({
            message: "Organization has reached its membership limit",
          });
        }
      });

    /**
     * Number of *active* members holding the protected owner (creator) role.
     * Inactive owners cannot act, so counting them would let an organization
     * deactivate its way into having nobody who can administer it.
     */
    const countOwners = (organizationId: string) =>
      Effect.gen(function* () {
        const members = yield* store.listMembersByOrganization(organizationId);
        return members.filter((member) => member.role === creatorRole && isActiveMember(member))
          .length;
      });

    /** The role new members get when the caller names none. */
    const defaultRoleOf = (organization: Organization): string =>
      organization.defaultRole ?? "member";

    /**
     * Refuse custom-role writes against the protected owner role: owner
     * semantics stay static, so no tenant can define its way out of
     * `role:manage` (or out of the last-owner safeguards).
     */
    const ensureNotOwnerRole = (role: string) =>
      role === creatorRole
        ? Effect.fail(
            new OrganizationError({
              message: `The '${creatorRole}' role is protected and cannot be redefined`,
            }),
          )
        : Effect.void;

    /** Create a membership record (after all checks have passed). */
    const createMembership = (organizationId: string, userId: string, role: string) =>
      Effect.gen(function* () {
        const member: Member = {
          id: yield* generateId(),
          organizationId,
          userId,
          role,
          status: "active",
          createdAt: Date.now(),
        };
        return yield* store.createMember(member);
      });

    /** Load a membership (active or not), failing when there is none. */
    const getMemberOrFail = (organizationId: string, memberUserId: string) =>
      Effect.gen(function* () {
        const member = yield* store.getMember(organizationId, memberUserId);
        if (!member) {
          return yield* new OrganizationError({ message: "Member not found" });
        }
        return member;
      });

    /**
     * Load one of the organization's domain claims. Claims are addressed by id
     * *within* an organization: a claim belonging to another tenant answers
     * "not found" rather than confirming it exists.
     */
    const getDomainOrFail = (
      domainStore: typeof OrganizationDomainStore.Service,
      organizationId: string,
      domainId: string,
    ) =>
      Effect.gen(function* () {
        const domain = yield* domainStore.getById(domainId);
        if (!domain || domain.organizationId !== organizationId) {
          return yield* new OrganizationError({ message: "Domain not found" });
        }
        return domain;
      });

    /**
     * Load a domain claim the actor may manage: domains must be enabled, the
     * actor must hold `domain:manage` in the organization, and the claim must
     * belong to it.
     */
    const getManagedDomain = (actorUserId: string, organizationId: string, domainId: string) =>
      Effect.gen(function* () {
        const domainStore = yield* requireDomainStore();
        yield* requireMemberPermission(actorUserId, organizationId, "domain:manage");
        const domain = yield* getDomainOrFail(domainStore, organizationId, domainId);
        return { domainStore, domain };
      });

    /**
     * Load a pending invitation addressed to one of `userId`'s email
     * identifiers, enforcing expiry. (Matching mirrors the pre-identifier
     * behavior: the identifier does not need to be verified.)
     */
    const getPendingInvitationFor = (invitationId: string, userId: string) =>
      Effect.gen(function* () {
        const invitation = yield* store.getInvitation(invitationId);
        if (!invitation) {
          return yield* new OrganizationError({ message: "Invitation not found" });
        }
        if (invitation.status !== "pending") {
          return yield* new OrganizationError({ message: "Invitation is no longer pending" });
        }
        const userIdentifiers = yield* identifiers.listByUser(userId);
        const ownsEmail = userIdentifiers.some(
          (id) => id.type === "email" && id.value === normalizeEmail(invitation.email),
        );
        if (!ownsEmail) {
          return yield* new OrganizationError({
            message: "This invitation is addressed to a different email",
          });
        }
        if (Date.now() > invitation.expiresAt) {
          return yield* new OrganizationError({ message: "Invitation has expired" });
        }
        return invitation;
      });

    return {
      createOrganization: Effect.fn("OrganizationService.createOrganization")(function* (
        userId: string,
        input: CreateOrganizationInput,
      ) {
        if (!allowUserToCreateOrganization) {
          return yield* new OrganizationError({
            message: "Users are not allowed to create organizations",
          });
        }

        const memberships = yield* store.listMembersByUser(userId);
        if (memberships.length >= organizationLimit) {
          return yield* new OrganizationError({
            message: `You have reached the maximum of ${organizationLimit} organizations`,
          });
        }

        const existing = yield* store.getOrganizationBySlug(input.slug);
        if (existing) {
          return yield* new OrganizationError({
            message: `An organization with slug '${input.slug}' already exists`,
          });
        }

        const organization: Organization = {
          id: yield* generateId(),
          name: input.name,
          slug: input.slug,
          ...(input.logo !== undefined && { logo: input.logo }),
          metadata: input.metadata ?? {},
          defaultRole: "member",
          jitProvisioning: false,
          createdAt: Date.now(),
        };

        const created = yield* store.createOrganization(organization);
        yield* createMembership(created.id, userId, creatorRole);
        return created;
      }),

      updateOrganization: Effect.fn("OrganizationService.updateOrganization")(function* (
        userId: string,
        organizationId: string,
        updates: UpdateOrganizationInput,
      ) {
        yield* requireMemberPermission(userId, organizationId, "organization:update");

        const organization = yield* getOrganizationOrFail(organizationId);

        if (updates.slug !== undefined && updates.slug !== organization.slug) {
          const existing = yield* store.getOrganizationBySlug(updates.slug);
          if (existing) {
            return yield* new OrganizationError({
              message: `An organization with slug '${updates.slug}' already exists`,
            });
          }
        }

        const updated: Organization = {
          ...organization,
          ...(updates.name !== undefined && { name: updates.name }),
          ...(updates.slug !== undefined && { slug: updates.slug }),
          ...(updates.logo !== undefined && { logo: updates.logo }),
          ...(updates.metadata !== undefined && { metadata: updates.metadata }),
          ...(updates.jitProvisioning !== undefined && {
            jitProvisioning: updates.jitProvisioning,
          }),
        };

        return yield* store.updateOrganization(updated);
      }),

      deleteOrganization: Effect.fn("OrganizationService.deleteOrganization")(function* (
        userId: string,
        organizationId: string,
      ) {
        yield* requireMemberPermission(userId, organizationId, "organization:delete");
        yield* getOrganizationOrFail(organizationId);

        // Release the organization's domain claims first: they are globally
        // unique, so leaving them behind would squat those domains forever.
        if (Option.isSome(domainStoreOption)) {
          const claims = yield* domainStoreOption.value.listByOrganization(organizationId);
          yield* Effect.forEach(claims, (claim) => domainStoreOption.value.delete(claim.id), {
            concurrency: 1,
          });
        }

        yield* store.deleteOrganization(organizationId);
      }),

      getFullOrganization: Effect.fn("OrganizationService.getFullOrganization")(function* (
        organizationId: string,
      ) {
        const organization = yield* getOrganizationOrFail(organizationId);
        const members = yield* store.listMembersByOrganization(organizationId);
        return { organization, members } satisfies FullOrganization;
      }),

      listOrganizations: Effect.fn("OrganizationService.listOrganizations")(function* (
        userId: string,
      ) {
        const memberships = yield* store.listMembersByUser(userId);
        const organizations = yield* Effect.forEach(
          memberships,
          (membership) => store.getOrganizationById(membership.organizationId),
          { concurrency: 1 },
        );
        return organizations.filter(
          (organization): organization is Organization => organization !== null,
        );
      }),

      inviteMember: Effect.fn("OrganizationService.inviteMember")(function* (
        inviterId: string,
        organizationId: string,
        input: InviteMemberInput,
      ) {
        yield* requireMemberPermission(inviterId, organizationId, "invitation:create");
        const organization = yield* getOrganizationOrFail(organizationId);
        yield* ensureMembershipCapacity(organizationId);

        const email = normalizeEmail(input.email);

        const existingInvitations = yield* store.listInvitationsByEmail(email);
        const now = Date.now();
        const duplicate = existingInvitations.find(
          (invitation) =>
            invitation.organizationId === organizationId &&
            invitation.status === "pending" &&
            invitation.expiresAt > now,
        );
        if (duplicate) {
          return yield* new OrganizationError({
            message: "A pending invitation already exists for this email",
          });
        }

        const invitation: Invitation = {
          id: yield* generateId(),
          organizationId,
          email,
          role: input.role,
          status: "pending",
          inviterId,
          expiresAt: now + invitationExpiresIn,
          createdAt: now,
        };

        const created = yield* store.createInvitation(invitation);

        if (config.sendInvitationEmail) {
          yield* config.sendInvitationEmail(created, organization);
        }

        return created;
      }),

      acceptInvitation: Effect.fn("OrganizationService.acceptInvitation")(function* (
        userId: string,
        invitationId: string,
      ) {
        const invitation = yield* getPendingInvitationFor(invitationId, userId);

        const existingMember = yield* store.getMember(invitation.organizationId, userId);
        if (existingMember) {
          return yield* new OrganizationError({
            message: "You are already a member of this organization",
          });
        }

        yield* ensureMembershipCapacity(invitation.organizationId);

        const member = yield* createMembership(invitation.organizationId, userId, invitation.role);
        yield* store.updateInvitation({ ...invitation, status: "accepted" });
        return member;
      }),

      rejectInvitation: Effect.fn("OrganizationService.rejectInvitation")(function* (
        userId: string,
        invitationId: string,
      ) {
        const invitation = yield* getPendingInvitationFor(invitationId, userId);
        return yield* store.updateInvitation({ ...invitation, status: "rejected" });
      }),

      cancelInvitation: Effect.fn("OrganizationService.cancelInvitation")(function* (
        cancelerId: string,
        invitationId: string,
      ) {
        const invitation = yield* store.getInvitation(invitationId);
        if (!invitation) {
          return yield* new OrganizationError({ message: "Invitation not found" });
        }
        if (invitation.status !== "pending") {
          return yield* new OrganizationError({ message: "Invitation is no longer pending" });
        }

        yield* requireMemberPermission(cancelerId, invitation.organizationId, "invitation:cancel");

        return yield* store.updateInvitation({ ...invitation, status: "canceled" });
      }),

      resendInvitation: Effect.fn("OrganizationService.resendInvitation")(function* (
        actorId: string,
        invitationId: string,
      ) {
        const invitation = yield* store.getInvitation(invitationId);
        if (!invitation) {
          return yield* new OrganizationError({ message: "Invitation not found" });
        }
        if (invitation.status !== "pending") {
          return yield* new OrganizationError({ message: "Invitation is no longer pending" });
        }

        yield* requireMemberPermission(actorId, invitation.organizationId, "invitation:create");
        const organization = yield* getOrganizationOrFail(invitation.organizationId);

        // The same row and id: an already-delivered link keeps working, and an
        // expired-but-pending invitation is revived rather than duplicated.
        const refreshed = yield* store.updateInvitation({
          ...invitation,
          expiresAt: Date.now() + invitationExpiresIn,
        });

        if (config.sendInvitationEmail) {
          yield* config.sendInvitationEmail(refreshed, organization);
        }

        return refreshed;
      }),

      listInvitations: Effect.fn("OrganizationService.listInvitations")(function* (
        organizationId: string,
      ) {
        return yield* store.listInvitationsByOrganization(organizationId);
      }),

      listUserInvitations: Effect.fn("OrganizationService.listUserInvitations")(function* (
        email: string,
      ) {
        const invitations = yield* store.listInvitationsByEmail(email);
        const now = Date.now();
        return invitations.filter(
          (invitation) => invitation.status === "pending" && invitation.expiresAt > now,
        );
      }),

      addMember: Effect.fn("OrganizationService.addMember")(function* (
        actorId: string,
        organizationId: string,
        userId: string,
        role?: string,
      ) {
        yield* requireMemberPermission(actorId, organizationId, "member:create");
        const organization = yield* getOrganizationOrFail(organizationId);

        const existing = yield* store.getMember(organizationId, userId);
        if (existing) {
          return yield* new OrganizationError({
            message: "User is already a member of this organization",
          });
        }

        yield* ensureMembershipCapacity(organizationId);
        return yield* createMembership(organizationId, userId, role ?? defaultRoleOf(organization));
      }),

      removeMember: Effect.fn("OrganizationService.removeMember")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
      ) {
        const actor = yield* requireMemberPermission(actorId, organizationId, "member:delete");

        const target = yield* getMemberOrFail(organizationId, memberUserId);

        if (target.role === creatorRole) {
          if (actor.role !== creatorRole) {
            return yield* new OrganizationError({
              message: "Only an owner can remove another owner",
            });
          }
          const owners = yield* countOwners(organizationId);
          if (owners <= 1) {
            return yield* new OrganizationError({
              message: "The last owner of an organization cannot be removed",
            });
          }
        }

        yield* store.deleteMember(target.id);
        // Cascade: leaving the organization also leaves all of its teams.
        const teams = yield* store.listTeamsForMember(organizationId, memberUserId);
        yield* Effect.forEach(teams, (team) => store.removeTeamMember(team.id, memberUserId), {
          concurrency: 1,
        });
      }),

      updateMemberRole: Effect.fn("OrganizationService.updateMemberRole")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
        role: string,
      ) {
        yield* requireMemberPermission(actorId, organizationId, "member:update");

        const target = yield* getMemberOrFail(organizationId, memberUserId);

        if (!isActiveMember(target)) {
          return yield* new OrganizationError({
            message: "Reactivate the member before changing their role",
          });
        }

        if (target.role === creatorRole && role !== creatorRole) {
          const owners = yield* countOwners(organizationId);
          if (owners <= 1) {
            return yield* new OrganizationError({
              message: "The last owner of an organization cannot be demoted",
            });
          }
        }

        return yield* store.updateMember({ ...target, role });
      }),

      deactivateMember: Effect.fn("OrganizationService.deactivateMember")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
      ) {
        const actor = yield* requireMemberPermission(actorId, organizationId, "member:update");
        const organization = yield* getOrganizationOrFail(organizationId);
        const target = yield* getMemberOrFail(organizationId, memberUserId);

        if (!isActiveMember(target)) {
          return yield* new OrganizationError({ message: "Member is already inactive" });
        }

        // Same shape as removal: owners are each other's peers, and the last
        // one standing keeps the organization administrable.
        if (target.role === creatorRole) {
          if (actor.role !== creatorRole) {
            return yield* new OrganizationError({
              message: "Only an owner can deactivate another owner",
            });
          }
          const owners = yield* countOwners(organizationId);
          if (owners <= 1) {
            return yield* new OrganizationError({
              message: "The last owner of an organization cannot be deactivated",
            });
          }
        }

        const deactivated = yield* store.updateMember({
          ...target,
          status: "inactive",
          previousRole: target.role,
          role: defaultRoleOf(organization),
        });

        if (config.onMemberDeactivated) {
          yield* config.onMemberDeactivated(deactivated, organization);
        }

        return deactivated;
      }),

      reactivateMember: Effect.fn("OrganizationService.reactivateMember")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
      ) {
        yield* requireMemberPermission(actorId, organizationId, "member:update");
        const target = yield* getMemberOrFail(organizationId, memberUserId);

        if (isActiveMember(target)) {
          return yield* new OrganizationError({ message: "Member is already active" });
        }

        const { previousRole, ...rest } = target;
        return yield* store.updateMember({
          ...rest,
          status: "active",
          role: previousRole ?? target.role,
        });
      }),

      setDefaultRole: Effect.fn("OrganizationService.setDefaultRole")(function* (
        actorUserId: string,
        organizationId: string,
        role: string,
      ) {
        yield* requireMemberPermission(actorUserId, organizationId, "role:manage");
        const organization = yield* getOrganizationOrFail(organizationId);

        // Fail closed on a role nothing defines: a default nobody can resolve
        // would hand every new member an empty permission set silently.
        const permissions = yield* resolveRolePermissions(organizationId, role);
        if (permissions === null) {
          return yield* new OrganizationError({
            message: `Role '${role}' is not defined for this organization`,
          });
        }

        return yield* store.updateOrganization({ ...organization, defaultRole: role });
      }),

      createTeam: Effect.fn("OrganizationService.createTeam")(function* (
        actorUserId: string,
        organizationId: string,
        input: CreateTeamInput,
      ) {
        yield* requireMemberPermission(actorUserId, organizationId, "team:create");
        yield* getOrganizationOrFail(organizationId);

        const now = Date.now();
        const team: Team = {
          id: yield* generateId(),
          organizationId,
          name: input.name,
          createdAt: now,
          updatedAt: now,
        };
        return yield* store.createTeam(team);
      }),

      updateTeam: Effect.fn("OrganizationService.updateTeam")(function* (
        actorUserId: string,
        teamId: string,
        input: UpdateTeamInput,
      ) {
        const team = yield* requireTeamPermission(actorUserId, teamId, "team:update");

        const updated = yield* store.updateTeam({
          ...team,
          ...(input.name !== undefined && { name: input.name }),
          updatedAt: Date.now(),
        });
        if (!updated) {
          return yield* new OrganizationError({ message: "Team not found" });
        }
        return updated;
      }),

      deleteTeam: Effect.fn("OrganizationService.deleteTeam")(function* (
        actorUserId: string,
        teamId: string,
      ) {
        yield* requireTeamPermission(actorUserId, teamId, "team:delete");
        // The store cascades the team's memberships.
        yield* store.deleteTeam(teamId);
      }),

      addTeamMember: Effect.fn("OrganizationService.addTeamMember")(function* (
        actorUserId: string,
        teamId: string,
        memberUserId: string,
      ) {
        const team = yield* requireTeamPermission(actorUserId, teamId, "team:manage-members");

        const member = yield* store.getMember(team.organizationId, memberUserId);
        if (!member) {
          return yield* new OrganizationError({
            message: "User is not a member of this organization",
          });
        }

        const existing = yield* store.listTeamMembers(teamId);
        if (existing.some((teamMember) => teamMember.userId === memberUserId)) {
          return yield* new OrganizationError({ message: "User is already a member of this team" });
        }

        return yield* store.addTeamMember(teamId, memberUserId);
      }),

      removeTeamMember: Effect.fn("OrganizationService.removeTeamMember")(function* (
        actorUserId: string,
        teamId: string,
        memberUserId: string,
      ) {
        yield* requireTeamPermission(actorUserId, teamId, "team:manage-members");
        yield* store.removeTeamMember(teamId, memberUserId);
      }),

      listTeams: Effect.fn("OrganizationService.listTeams")(function* (
        actorUserId: string,
        organizationId: string,
      ) {
        yield* requireMembership(actorUserId, organizationId);
        return yield* store.listTeams(organizationId);
      }),

      listTeamMembers: Effect.fn("OrganizationService.listTeamMembers")(function* (
        actorUserId: string,
        teamId: string,
      ) {
        const team = yield* getTeamOrFail(teamId);
        yield* requireMembership(actorUserId, team.organizationId);
        return yield* store.listTeamMembers(teamId);
      }),

      listTeamsForMember: Effect.fn("OrganizationService.listTeamsForMember")(function* (
        actorUserId: string,
        organizationId: string,
        userId: string,
      ) {
        yield* requireMembership(actorUserId, organizationId);
        return yield* store.listTeamsForMember(organizationId, userId);
      }),

      listDomains: Effect.fn("OrganizationService.listDomains")(function* (
        actorUserId: string,
        organizationId: string,
      ) {
        const domainStore = yield* requireDomainStore();
        yield* requireMembership(actorUserId, organizationId);
        return yield* domainStore.listByOrganization(organizationId);
      }),

      addDomain: Effect.fn("OrganizationService.addDomain")(function* (
        actorUserId: string,
        organizationId: string,
        input: AddOrganizationDomainInput,
      ) {
        const domainStore = yield* requireDomainStore();
        yield* requireMemberPermission(actorUserId, organizationId, "domain:manage");
        yield* getOrganizationOrFail(organizationId);

        const domain = normalizeDomain(input.domain);
        if (domain === "" || domain.includes("@") || !domain.includes(".")) {
          return yield* new OrganizationError({
            message: `'${input.domain}' is not a valid domain`,
          });
        }

        const conflicting = yield* domainStore.getByDomain(domain);
        if (conflicting) {
          return yield* new OrganizationError({
            message:
              conflicting.organizationId === organizationId
                ? "This organization has already claimed that domain"
                : "That domain is already claimed by another organization",
          });
        }

        const strategy = input.verificationStrategy ?? "dns";
        const claim: OrganizationDomain = {
          id: yield* generateId(),
          organizationId,
          domain,
          verificationState: "pending",
          verificationStrategy: strategy,
          // The token is ours to mint: a client-chosen one would let a tenant
          // "prove" a domain with a record it had already published elsewhere.
          ...(strategy === "dns" && { verificationToken: yield* generateId() }),
          createdAt: Date.now(),
        };
        return yield* domainStore.create(claim);
      }),

      removeDomain: Effect.fn("OrganizationService.removeDomain")(function* (
        actorUserId: string,
        organizationId: string,
        domainId: string,
      ) {
        const { domainStore, domain } = yield* getManagedDomain(
          actorUserId,
          organizationId,
          domainId,
        );
        yield* domainStore.delete(domain.id);
      }),

      verifyDomain: Effect.fn("OrganizationService.verifyDomain")(function* (
        actorUserId: string,
        organizationId: string,
        domainId: string,
      ) {
        const { domainStore, domain } = yield* getManagedDomain(
          actorUserId,
          organizationId,
          domainId,
        );

        if (domain.verificationState === "verified") return domain;

        if (domain.verificationStrategy === "manual") {
          // The `domain:manage` permission *is* the attestation here.
          return yield* domainStore.update({
            ...domain,
            verificationState: "verified",
            verifiedAt: Date.now(),
          });
        }

        if (Option.isNone(domainVerifierOption)) {
          return yield* new OrganizationError({
            message:
              "DNS domain verification is not available: provide a DomainVerifier layer, or claim the domain with the 'manual' strategy",
          });
        }

        const proved = yield* domainVerifierOption.value.verify(
          domain.domain,
          domain.verificationToken ?? "",
        );
        return yield* domainStore.update({
          ...domain,
          verificationState: proved ? "verified" : "failed",
          ...(proved && { verifiedAt: Date.now() }),
        });
      }),

      provisionJitMembership: Effect.fn("OrganizationService.provisionJitMembership")(function* (
        userId: string,
        email: string,
      ) {
        if (Option.isNone(domainStoreOption)) return null;

        const domain = yield* domainStoreOption.value.getByDomain(domainOfEmail(email));
        // Only a *verified* claim carries authority; a pending one is just a
        // request, and honoring it would let anyone absorb a domain by asking.
        if (!domain || domain.verificationState !== "verified") return null;

        const organization = yield* store.getOrganizationById(domain.organizationId);
        if (!organization || organization.jitProvisioning !== true) return null;

        const existing = yield* store.getMember(organization.id, userId);
        if (existing) return null;

        yield* ensureMembershipCapacity(organization.id);
        return yield* createMembership(organization.id, userId, defaultRoleOf(organization));
      }),

      upsertOrgRole: Effect.fn("OrganizationService.upsertOrgRole")(function* (
        actorUserId: string,
        organizationId: string,
        input: UpsertOrgRoleInput,
      ) {
        yield* requireMemberPermission(actorUserId, organizationId, "role:manage");
        yield* getOrganizationOrFail(organizationId);
        yield* ensureNotOwnerRole(input.role);

        const now = Date.now();
        const existing = yield* store.getOrgRole(organizationId, input.role);
        return yield* store.upsertOrgRole({
          organizationId,
          role: input.role,
          permissions: input.permissions,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now,
        });
      }),

      deleteOrgRole: Effect.fn("OrganizationService.deleteOrgRole")(function* (
        actorUserId: string,
        organizationId: string,
        role: string,
      ) {
        yield* requireMemberPermission(actorUserId, organizationId, "role:manage");
        yield* ensureNotOwnerRole(role);
        yield* store.deleteOrgRole(organizationId, role);
      }),

      listOrgRoles: Effect.fn("OrganizationService.listOrgRoles")(function* (
        actorUserId: string,
        organizationId: string,
      ) {
        yield* requireMembership(actorUserId, organizationId);
        return yield* store.listOrgRoles(organizationId);
      }),

      checkPermission: Effect.fn("OrganizationService.checkPermission")(function* (
        userId: string,
        organizationId: string,
        permission: string,
      ) {
        const member = yield* getActiveMember(organizationId, userId);
        if (!member) return false;
        return yield* roleHasPermission(organizationId, member.role, permission);
      }),

      requirePermission: Effect.fn("OrganizationService.requirePermission")(
        (userId: string, organizationId: string, permission: string) =>
          requireMemberPermission(userId, organizationId, permission).pipe(Effect.asVoid),
      ),
    };
  });
