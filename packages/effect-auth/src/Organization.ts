/**
 * Organizations (multi-tenant teams) for effect-auth.
 *
 * Mirrors better-auth's organization plugin: users create organizations,
 * invite members by email, and manage member roles. Every mutating operation
 * is permission-checked against a configurable role → permission map using
 * `"resource:action"` permission strings.
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

import { Context, Crypto, Data, Effect, Layer } from "effect";
import { IdentifierStore } from "./Identifier.ts";
import * as Errors from "./Errors.ts";
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
  /** Epoch milliseconds */
  readonly createdAt: number;
}

/**
 * A user's membership in an organization.
 */
export interface Member {
  readonly id: string;
  readonly organizationId: string;
  readonly userId: string;
  /** Role name, resolved against the configured role → permission map */
  readonly role: string;
  /** Epoch milliseconds */
  readonly createdAt: number;
}

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
 * Default role → permission map, mirroring better-auth's built-in
 * organization roles. Permissions are `"resource:action"` strings.
 *
 * - `owner` - full control (organization update/delete, member and
 *   invitation management)
 * - `admin` - member and invitation management plus organization updates,
 *   but cannot delete the organization
 * - `member` - read-only participant (no management permissions)
 *
 * Override via {@link OrganizationConfig.roles}.
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
  ],
  admin: [
    "organization:update",
    "member:create",
    "member:update",
    "member:delete",
    "invitation:create",
    "invitation:cancel",
  ],
  member: [],
};

/**
 * Storage interface for organizations, members, and invitations.
 * Implement with your preferred backend (SQL, Redis, ...).
 *
 * Note: `deleteOrganization` should cascade - implementations are expected
 * to remove the organization's members and invitations as well.
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
  /** Role → permission map (default: {@link defaultOrganizationRoles}) */
  readonly roles?: Record<string, ReadonlyArray<string>>;
  /** Optional invitation email delivery */
  readonly sendInvitationEmail?: (
    invitation: Invitation,
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
}

/**
 * Input for inviting a member by email
 */
export interface InviteMemberInput {
  readonly email: string;
  readonly role: string;
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
     * Add a user to the organization directly (no invitation). Requires the
     * `member:create` permission and enforces `membershipLimit`.
     */
    readonly addMember: (
      actorId: string,
      organizationId: string,
      userId: string,
      role: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Remove a member. Requires the `member:delete` permission. An owner can
     * only be removed by another owner, and the last owner can never be removed.
     */
    readonly removeMember: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
    ) => Effect.Effect<void, OrganizationError | Errors.AuthError>;

    /**
     * Change a member's role. Requires the `member:update` permission. The last
     * owner cannot be demoted.
     */
    readonly updateMemberRole: (
      actorId: string,
      organizationId: string,
      memberUserId: string,
      role: string,
    ) => Effect.Effect<Member, OrganizationError | Errors.AuthError>;

    /**
     * Whether the user's role in the organization grants the given
     * `"resource:action"` permission. Non-members simply get `false`.
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

    /** Generate a random identifier for organizations, members, and invitations. */
    const generateId = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(16).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("hex")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate id", cause }),
        ),
      );

    /** Whether a role name grants a `"resource:action"` permission. */
    const roleHasPermission = (role: string, permission: string): boolean =>
      (roles[role] ?? []).includes(permission);

    /** Load an organization, failing when it does not exist. */
    const getOrganizationOrFail = (organizationId: string) =>
      Effect.gen(function* () {
        const organization = yield* store.getOrganizationById(organizationId);
        if (!organization) {
          return yield* Effect.fail(new OrganizationError({ message: "Organization not found" }));
        }
        return organization;
      });

    /**
     * Resolve the actor's membership and enforce a permission, returning the
     * membership so callers can inspect the actor's role.
     */
    const requireMemberPermission = (userId: string, organizationId: string, permission: string) =>
      Effect.gen(function* () {
        const member = yield* store.getMember(organizationId, userId);
        if (!member || !roleHasPermission(member.role, permission)) {
          return yield* Effect.fail(
            new OrganizationError({
              message: `Missing permission '${permission}' in this organization`,
            }),
          );
        }
        return member;
      });

    /** Enforce the per-organization membership limit before adding a member. */
    const ensureMembershipCapacity = (organizationId: string) =>
      Effect.gen(function* () {
        const count = yield* store.countMembersByOrganization(organizationId);
        if (count >= membershipLimit) {
          return yield* Effect.fail(
            new OrganizationError({
              message: "Organization has reached its membership limit",
            }),
          );
        }
      });

    /** Number of members holding the protected owner (creator) role. */
    const countOwners = (organizationId: string) =>
      Effect.gen(function* () {
        const members = yield* store.listMembersByOrganization(organizationId);
        return members.filter((member) => member.role === creatorRole).length;
      });

    /** Create a membership record (after all checks have passed). */
    const createMembership = (organizationId: string, userId: string, role: string) =>
      Effect.gen(function* () {
        const member: Member = {
          id: yield* generateId(),
          organizationId,
          userId,
          role,
          createdAt: Date.now(),
        };
        return yield* store.createMember(member);
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
          return yield* Effect.fail(new OrganizationError({ message: "Invitation not found" }));
        }
        if (invitation.status !== "pending") {
          return yield* Effect.fail(
            new OrganizationError({ message: "Invitation is no longer pending" }),
          );
        }
        const userIdentifiers = yield* identifiers.listByUser(userId);
        const ownsEmail = userIdentifiers.some(
          (id) => id.type === "email" && id.value === normalizeEmail(invitation.email),
        );
        if (!ownsEmail) {
          return yield* Effect.fail(
            new OrganizationError({
              message: "This invitation is addressed to a different email",
            }),
          );
        }
        if (Date.now() > invitation.expiresAt) {
          return yield* Effect.fail(new OrganizationError({ message: "Invitation has expired" }));
        }
        return invitation;
      });

    return {
      createOrganization: Effect.fn("OrganizationService.createOrganization")(function* (
        userId: string,
        input: CreateOrganizationInput,
      ) {
        if (!allowUserToCreateOrganization) {
          return yield* Effect.fail(
            new OrganizationError({
              message: "Users are not allowed to create organizations",
            }),
          );
        }

        const memberships = yield* store.listMembersByUser(userId);
        if (memberships.length >= organizationLimit) {
          return yield* Effect.fail(
            new OrganizationError({
              message: `You have reached the maximum of ${organizationLimit} organizations`,
            }),
          );
        }

        const existing = yield* store.getOrganizationBySlug(input.slug);
        if (existing) {
          return yield* Effect.fail(
            new OrganizationError({
              message: `An organization with slug '${input.slug}' already exists`,
            }),
          );
        }

        const organization: Organization = {
          id: yield* generateId(),
          name: input.name,
          slug: input.slug,
          ...(input.logo !== undefined && { logo: input.logo }),
          metadata: input.metadata ?? {},
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
            return yield* Effect.fail(
              new OrganizationError({
                message: `An organization with slug '${updates.slug}' already exists`,
              }),
            );
          }
        }

        const updated: Organization = {
          ...organization,
          ...(updates.name !== undefined && { name: updates.name }),
          ...(updates.slug !== undefined && { slug: updates.slug }),
          ...(updates.logo !== undefined && { logo: updates.logo }),
          ...(updates.metadata !== undefined && { metadata: updates.metadata }),
        };

        return yield* store.updateOrganization(updated);
      }),

      deleteOrganization: Effect.fn("OrganizationService.deleteOrganization")(function* (
        userId: string,
        organizationId: string,
      ) {
        yield* requireMemberPermission(userId, organizationId, "organization:delete");
        yield* getOrganizationOrFail(organizationId);

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
        const organizations = yield* Effect.forEach(memberships, (membership) =>
          store.getOrganizationById(membership.organizationId),
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
          return yield* Effect.fail(
            new OrganizationError({
              message: "A pending invitation already exists for this email",
            }),
          );
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
          return yield* Effect.fail(
            new OrganizationError({
              message: "You are already a member of this organization",
            }),
          );
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
          return yield* Effect.fail(new OrganizationError({ message: "Invitation not found" }));
        }
        if (invitation.status !== "pending") {
          return yield* Effect.fail(
            new OrganizationError({ message: "Invitation is no longer pending" }),
          );
        }

        yield* requireMemberPermission(cancelerId, invitation.organizationId, "invitation:cancel");

        return yield* store.updateInvitation({ ...invitation, status: "canceled" });
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
        role: string,
      ) {
        yield* requireMemberPermission(actorId, organizationId, "member:create");
        yield* getOrganizationOrFail(organizationId);

        const existing = yield* store.getMember(organizationId, userId);
        if (existing) {
          return yield* Effect.fail(
            new OrganizationError({
              message: "User is already a member of this organization",
            }),
          );
        }

        yield* ensureMembershipCapacity(organizationId);
        return yield* createMembership(organizationId, userId, role);
      }),

      removeMember: Effect.fn("OrganizationService.removeMember")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
      ) {
        const actor = yield* requireMemberPermission(actorId, organizationId, "member:delete");

        const target = yield* store.getMember(organizationId, memberUserId);
        if (!target) {
          return yield* Effect.fail(new OrganizationError({ message: "Member not found" }));
        }

        if (target.role === creatorRole) {
          if (actor.role !== creatorRole) {
            return yield* Effect.fail(
              new OrganizationError({ message: "Only an owner can remove another owner" }),
            );
          }
          const owners = yield* countOwners(organizationId);
          if (owners <= 1) {
            return yield* Effect.fail(
              new OrganizationError({
                message: "The last owner of an organization cannot be removed",
              }),
            );
          }
        }

        yield* store.deleteMember(target.id);
      }),

      updateMemberRole: Effect.fn("OrganizationService.updateMemberRole")(function* (
        actorId: string,
        organizationId: string,
        memberUserId: string,
        role: string,
      ) {
        yield* requireMemberPermission(actorId, organizationId, "member:update");

        const target = yield* store.getMember(organizationId, memberUserId);
        if (!target) {
          return yield* Effect.fail(new OrganizationError({ message: "Member not found" }));
        }

        if (target.role === creatorRole && role !== creatorRole) {
          const owners = yield* countOwners(organizationId);
          if (owners <= 1) {
            return yield* Effect.fail(
              new OrganizationError({
                message: "The last owner of an organization cannot be demoted",
              }),
            );
          }
        }

        return yield* store.updateMember({ ...target, role });
      }),

      checkPermission: Effect.fn("OrganizationService.checkPermission")(function* (
        userId: string,
        organizationId: string,
        permission: string,
      ) {
        const member = yield* store.getMember(organizationId, userId);
        return member !== null && roleHasPermission(member.role, permission);
      }),

      requirePermission: Effect.fn("OrganizationService.requirePermission")(
        (userId: string, organizationId: string, permission: string) =>
          requireMemberPermission(userId, organizationId, permission).pipe(Effect.asVoid),
      ),
    };
  });
