import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Array as Arr, Clock, Context, Crypto, DateTime, Effect, Order, Result } from "effect";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import {
  DomainVerifier,
  OrganizationDomainStore,
  OrganizationStore,
  defaultOrganizationRoles,
  memoryOrganizationDomainStore,
  type Invitation,
  type Member,
  type Organization,
  type OrganizationConfig,
  type OrganizationDomain,
  type OrganizationService,
  type OrgRole,
  type Team,
  type TeamMember,
} from "./Organization.ts";
import * as OrganizationModule from "./Organization.ts";

const organizations = new Map<string, Organization>();
const members = new Map<string, Member>();
const invitations = new Map<string, Invitation>();
const teams = new Map<string, Team>();
const teamMembers: TeamMember[] = [];
const orgRoles = new Map<string, OrgRole>();
const domainRecords = new Map<string, OrganizationDomain>();
const identifierRecords = new Map<string, Identifier>();

/** Composite key for the custom-role table. */
const orgRoleKey = (organizationId: string, role: string): string =>
  `${organizationId}\u0000${role}`;

/** Give a user an email identifier so invitations addressed to it can be
 * accepted/rejected by that user. */
const seedEmail = (userId: string, email: string): void => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  identifierRecords.set(identifier.id, identifier);
};

/** Drop every team-membership row matching `predicate` (in-place). */
const removeTeamMemberRows = (predicate: (teamMember: TeamMember) => boolean): void => {
  const kept = teamMembers.filter((teamMember) => !predicate(teamMember));
  teamMembers.splice(0, teamMembers.length, ...kept);
};

const organizationStore = {
  createOrganization: (organization: Organization) =>
    Effect.sync(() => {
      organizations.set(organization.id, organization);
      return organization;
    }),

  getOrganizationById: (organizationId: string) =>
    Effect.sync(() => organizations.get(organizationId) ?? null),

  getOrganizationBySlug: (slug: string) =>
    Effect.sync(
      () =>
        Array.from(organizations.values()).find((organization) => organization.slug === slug) ??
        null,
    ),

  updateOrganization: (organization: Organization) =>
    Effect.sync(() => {
      organizations.set(organization.id, organization);
      return organization;
    }),

  deleteOrganization: (organizationId: string) =>
    Effect.sync(() => {
      organizations.delete(organizationId);
      members.forEach((member, id) => {
        if (member.organizationId === organizationId) {
          members.delete(id);
        }
      });
      invitations.forEach((invitation, id) => {
        if (invitation.organizationId === organizationId) {
          invitations.delete(id);
        }
      });
      teams.forEach((team, id) => {
        if (team.organizationId === organizationId) {
          teams.delete(id);
          removeTeamMemberRows((teamMember) => teamMember.teamId === id);
        }
      });
      orgRoles.forEach((orgRole, key) => {
        if (orgRole.organizationId === organizationId) {
          orgRoles.delete(key);
        }
      });
    }),

  createMember: (member: Member) =>
    Effect.sync(() => {
      members.set(member.id, member);
      return member;
    }),

  getMember: (organizationId: string, userId: string) =>
    Effect.sync(
      () =>
        Array.from(members.values()).find(
          (member) => member.organizationId === organizationId && member.userId === userId,
        ) ?? null,
    ),

  updateMember: (member: Member) =>
    Effect.sync(() => {
      members.set(member.id, member);
      return member;
    }),

  deleteMember: (memberId: string) =>
    Effect.sync(() => {
      members.delete(memberId);
    }),

  listMembersByOrganization: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(members.values()).filter((member) => member.organizationId === organizationId),
    ),

  listMembersByUser: (userId: string) =>
    Effect.sync(() => Array.from(members.values()).filter((member) => member.userId === userId)),

  countMembersByOrganization: (organizationId: string) =>
    Effect.sync(
      () =>
        Array.from(members.values()).filter((member) => member.organizationId === organizationId)
          .length,
    ),

  createInvitation: (invitation: Invitation) =>
    Effect.sync(() => {
      invitations.set(invitation.id, invitation);
      return invitation;
    }),

  getInvitation: (invitationId: string) => Effect.sync(() => invitations.get(invitationId) ?? null),

  updateInvitation: (invitation: Invitation) =>
    Effect.sync(() => {
      invitations.set(invitation.id, invitation);
      return invitation;
    }),

  listInvitationsByOrganization: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(invitations.values()).filter(
        (invitation) => invitation.organizationId === organizationId,
      ),
    ),

  listInvitationsByEmail: (email: string) =>
    Effect.sync(() =>
      Array.from(invitations.values()).filter((invitation) => invitation.email === email),
    ),

  createTeam: (team: Team) =>
    Effect.sync(() => {
      teams.set(team.id, team);
      return team;
    }),

  getTeam: (teamId: string) => Effect.sync(() => teams.get(teamId) ?? null),

  updateTeam: (team: Team) =>
    Effect.sync(() => {
      if (!teams.has(team.id)) return null;
      teams.set(team.id, team);
      return team;
    }),

  deleteTeam: (teamId: string) =>
    Effect.sync(() => {
      teams.delete(teamId);
      removeTeamMemberRows((teamMember) => teamMember.teamId === teamId);
    }),

  listTeams: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(teams.values()).filter((team) => team.organizationId === organizationId),
    ),

  addTeamMember: (teamId: string, userId: string) =>
    Effect.sync(() => {
      const teamMember: TeamMember = {
        teamId,
        userId,
        createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      };
      teamMembers.push(teamMember);
      return teamMember;
    }),

  removeTeamMember: (teamId: string, userId: string) =>
    Effect.sync(() => {
      removeTeamMemberRows(
        (teamMember) => teamMember.teamId === teamId && teamMember.userId === userId,
      );
    }),

  listTeamMembers: (teamId: string) =>
    Effect.sync(() => teamMembers.filter((teamMember) => teamMember.teamId === teamId)),

  listTeamsForMember: (organizationId: string, userId: string) =>
    Effect.sync(() =>
      teamMembers
        .filter((teamMember) => teamMember.userId === userId)
        .map((teamMember) => teams.get(teamMember.teamId))
        .filter(
          (team): team is Team => team !== undefined && team.organizationId === organizationId,
        ),
    ),

  upsertOrgRole: (orgRole: OrgRole) =>
    Effect.sync(() => {
      orgRoles.set(orgRoleKey(orgRole.organizationId, orgRole.role), orgRole);
      return orgRole;
    }),

  getOrgRole: (organizationId: string, role: string) =>
    Effect.sync(() => orgRoles.get(orgRoleKey(organizationId, role)) ?? null),

  listOrgRoles: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(orgRoles.values()).filter((orgRole) => orgRole.organizationId === organizationId),
    ),

  deleteOrgRole: (organizationId: string, role: string) =>
    Effect.sync(() => {
      orgRoles.delete(orgRoleKey(organizationId, role));
    }),
};

/** Everything the service needs except the optional domain half. */
const baseContext = Context.merge(
  Context.merge(
    Context.make(OrganizationStore, organizationStore),
    Context.make(IdentifierStore, memoryIdentifierStore(identifierRecords)),
  ),
  Context.make(Crypto.Crypto, PlatformCrypto.instance),
);

const testContext = Context.merge(
  baseContext,
  Context.make(OrganizationDomainStore, memoryOrganizationDomainStore(domainRecords)),
);

/** Run against an explicit context - used to exercise "domains not enabled". */
const runServiceIn = <A, E>(
  context: Context.Context<OrganizationStore | IdentifierStore | Crypto.Crypto>,
  config: OrganizationConfig,
  program: (
    service: typeof OrganizationService.Service,
  ) => Effect.Effect<A, E, OrganizationStore | IdentifierStore | Crypto.Crypto>,
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* OrganizationModule.make(config);
        return yield* program(service);
      }),
      context,
    ),
  );

const runService = <A, E>(
  config: OrganizationConfig,
  program: (
    service: typeof OrganizationService.Service,
  ) => Effect.Effect<A, E, OrganizationStore | IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* OrganizationModule.make(config);
        return yield* program(service);
      }),
      testContext,
    ),
  );

/** A {@link DomainVerifier} that answers `true` only for the domains it was given. */
const stubDomainVerifier = (
  proved: ReadonlyArray<{ readonly domain: string; readonly token: string }>,
  seen: Array<{ readonly domain: string; readonly token: string }> = [],
): typeof DomainVerifier.Service => ({
  verify: (domain, token) =>
    Effect.sync(() => {
      seen.push({ domain, token });
      return proved.some((entry) => entry.domain === domain && entry.token === token);
    }),
});

/** Run with a {@link DomainVerifier} in context on top of {@link testContext}. */
const runServiceWithVerifier = <A, E>(
  config: OrganizationConfig,
  verifier: typeof DomainVerifier.Service,
  program: (
    service: typeof OrganizationService.Service,
  ) => Effect.Effect<A, E, OrganizationStore | IdentifierStore>,
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* OrganizationModule.make(config);
        return yield* program(service);
      }),
      Context.merge(testContext, Context.make(DomainVerifier, verifier)),
    ),
  );

/** Empty every in-memory table between tests. */
const resetStores = (): void => {
  organizations.clear();
  members.clear();
  invitations.clear();
  teams.clear();
  teamMembers.length = 0;
  orgRoles.clear();
  domainRecords.clear();
  identifierRecords.clear();
};

describe("OrganizationService", () => {
  beforeEach(resetStores);

  it("creates an organization with the creator as owner", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("user-1", {
          name: "Acme",
          slug: "acme",
          logo: "https://example.com/logo.png",
          metadata: { plan: "pro" },
        });
        const full = yield* service.getFullOrganization(organization.id);
        const listed = yield* service.listOrganizations("user-1");
        return { organization, full, listed };
      }),
    );

    expect(result.organization.name).toBe("Acme");
    expect(result.organization.slug).toBe("acme");
    expect(result.organization.logo).toBe("https://example.com/logo.png");
    expect(result.organization.metadata).toEqual({ plan: "pro" });
    expect(result.full.members).toHaveLength(1);
    expect(result.full.members[0].userId).toBe("user-1");
    expect(result.full.members[0].role).toBe("owner");
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0].id).toBe(result.organization.id);
  });

  it("rejects a duplicate slug", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        yield* service.createOrganization("user-1", { name: "Acme", slug: "acme" });
        return yield* Effect.result(
          service.createOrganization("user-2", { name: "Acme Two", slug: "acme" }),
        );
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(organizations.size).toBe(1);
  });

  it("enforces the per-user organization limit", async () => {
    const result = await runService({ organizationLimit: 2 }, (service) =>
      Effect.gen(function* () {
        yield* service.createOrganization("user-1", { name: "One", slug: "one" });
        yield* service.createOrganization("user-1", { name: "Two", slug: "two" });
        return yield* Effect.result(
          service.createOrganization("user-1", { name: "Three", slug: "three" }),
        );
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(organizations.size).toBe(2);
  });

  it("respects allowUserToCreateOrganization: false", async () => {
    const result = await runService({ allowUserToCreateOrganization: false }, (service) =>
      Effect.result(service.createOrganization("user-1", { name: "Acme", slug: "acme" })),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(organizations.size).toBe(0);
  });

  it("permission-checks organization update and delete", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const nonMemberUpdate = yield* Effect.result(
          service.updateOrganization("stranger", organization.id, { name: "Nope" }),
        );
        const memberUpdate = yield* Effect.result(
          service.updateOrganization("member-1", organization.id, { name: "Nope" }),
        );
        const ownerUpdate = yield* service.updateOrganization("owner-1", organization.id, {
          name: "Acme Renamed",
          slug: "acme-renamed",
        });

        const memberDelete = yield* Effect.result(
          service.deleteOrganization("member-1", organization.id),
        );
        yield* service.deleteOrganization("owner-1", organization.id);
        const afterDelete = yield* Effect.result(service.getFullOrganization(organization.id));

        return { nonMemberUpdate, memberUpdate, ownerUpdate, memberDelete, afterDelete };
      }),
    );

    expect(result.nonMemberUpdate._tag).toBe("Failure");
    expect(result.memberUpdate._tag).toBe("Failure");
    expect(result.ownerUpdate.name).toBe("Acme Renamed");
    expect(result.ownerUpdate.slug).toBe("acme-renamed");
    expect(result.memberDelete._tag).toBe("Failure");
    expect(result.afterDelete._tag).toBe("Failure");
    expect(organizations.size).toBe(0);
  });

  it("rejects an organization update to a taken slug", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        yield* service.createOrganization("user-1", { name: "One", slug: "one" });
        const two = yield* service.createOrganization("user-1", { name: "Two", slug: "two" });
        return yield* Effect.result(service.updateOrganization("user-1", two.id, { slug: "one" }));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
  });

  it("runs the invitation lifecycle: invite, send email, accept", async () => {
    const sentEmails: Array<{ invitation: Invitation; organization: Organization }> = [];

    const config: OrganizationConfig = {
      sendInvitationEmail: (invitation, organization) =>
        Effect.sync(() => {
          sentEmails.push({ invitation, organization });
        }),
    };

    seedEmail("invitee-user", "invitee@example.com");

    const result = await runService(config, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });

        const invitation = yield* service.inviteMember("owner-1", organization.id, {
          email: "Invitee@Example.com",
          role: "member",
        });

        const duplicate = yield* Effect.result(
          service.inviteMember("owner-1", organization.id, {
            email: "invitee@example.com",
            role: "member",
          }),
        );

        const userInvitations = yield* service.listUserInvitations("invitee@example.com");

        const member = yield* service.acceptInvitation("invitee-user", invitation.id);

        const afterAccept = yield* service.listUserInvitations("invitee@example.com");
        const full = yield* service.getFullOrganization(organization.id);

        return { invitation, duplicate, userInvitations, member, afterAccept, full };
      }),
    );

    expect(result.invitation.email).toBe("invitee@example.com");
    expect(result.invitation.status).toBe("pending");
    expect(result.invitation.inviterId).toBe("owner-1");
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].invitation.id).toBe(result.invitation.id);
    expect(sentEmails[0].organization.slug).toBe("acme");
    expect(result.duplicate._tag).toBe("Failure");
    expect(result.userInvitations).toHaveLength(1);
    expect(result.member.userId).toBe("invitee-user");
    expect(result.member.role).toBe("member");
    expect(result.afterAccept).toHaveLength(0);
    expect(invitations.get(result.invitation.id)?.status).toBe("accepted");
    expect(result.full.members).toHaveLength(2);
  });

  it("rejects accepting an invitation addressed to a different email", async () => {
    seedEmail("other-user", "other@example.com");

    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const invitation = yield* service.inviteMember("owner-1", organization.id, {
          email: "invitee@example.com",
          role: "member",
        });
        return yield* Effect.result(service.acceptInvitation("other-user", invitation.id));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(Array.from(invitations.values())[0].status).toBe("pending");
  });

  it("rejects accepting an expired invitation", async () => {
    seedEmail("invitee-user", "invitee@example.com");

    const result = await runService({ invitationExpiresIn: -1000 }, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const invitation = yield* service.inviteMember("owner-1", organization.id, {
          email: "invitee@example.com",
          role: "member",
        });
        const accept = yield* Effect.result(
          service.acceptInvitation("invitee-user", invitation.id),
        );
        const userInvitations = yield* service.listUserInvitations("invitee@example.com");
        return { accept, userInvitations };
      }),
    );

    expect(result.accept._tag).toBe("Failure");
    assert(Result.isFailure(result.accept));
    expect(result.accept.failure._tag).toBe("OrganizationError");
    // Expired invitations are excluded from the user's pending list
    expect(result.userInvitations).toHaveLength(0);
  });

  it("supports rejecting an invitation and blocks re-acceptance", async () => {
    seedEmail("invitee-user", "invitee@example.com");

    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const invitation = yield* service.inviteMember("owner-1", organization.id, {
          email: "invitee@example.com",
          role: "member",
        });

        const rejected = yield* service.rejectInvitation("invitee-user", invitation.id);
        const acceptAfterReject = yield* Effect.result(
          service.acceptInvitation("invitee-user", invitation.id),
        );

        return { rejected, acceptAfterReject };
      }),
    );

    expect(result.rejected.status).toBe("rejected");
    expect(result.acceptAfterReject._tag).toBe("Failure");
  });

  it("permission-checks invitation creation and cancelation", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const memberInvite = yield* Effect.result(
          service.inviteMember("member-1", organization.id, {
            email: "friend@example.com",
            role: "member",
          }),
        );

        const invitation = yield* service.inviteMember("owner-1", organization.id, {
          email: "invitee@example.com",
          role: "member",
        });

        const memberCancel = yield* Effect.result(
          service.cancelInvitation("member-1", invitation.id),
        );
        const ownerCancel = yield* service.cancelInvitation("owner-1", invitation.id);
        const orgInvitations = yield* service.listInvitations(organization.id);

        return { memberInvite, memberCancel, ownerCancel, orgInvitations };
      }),
    );

    expect(result.memberInvite._tag).toBe("Failure");
    expect(result.memberCancel._tag).toBe("Failure");
    expect(result.ownerCancel.status).toBe("canceled");
    expect(result.orgInvitations).toHaveLength(1);
    expect(result.orgInvitations[0].status).toBe("canceled");
  });

  it("enforces the membership limit on invites and direct adds", async () => {
    const result = await runService({ membershipLimit: 2 }, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const addOverLimit = yield* Effect.result(
          service.addMember("owner-1", organization.id, "member-2", "member"),
        );
        const inviteOverLimit = yield* Effect.result(
          service.inviteMember("owner-1", organization.id, {
            email: "late@example.com",
            role: "member",
          }),
        );

        return { addOverLimit, inviteOverLimit };
      }),
    );

    expect(result.addOverLimit._tag).toBe("Failure");
    expect(result.inviteOverLimit._tag).toBe("Failure");
  });

  it("manages member roles with last-owner protection", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        // A plain member has no member:update permission
        const memberPromotes = yield* Effect.result(
          service.updateMemberRole("member-1", organization.id, "admin-1", "member"),
        );

        // An admin (member:delete) cannot remove an owner
        const adminRemovesOwner = yield* Effect.result(
          service.removeMember("admin-1", organization.id, "owner-1"),
        );

        // The last owner cannot be removed or demoted, even by an owner
        const removeLastOwner = yield* Effect.result(
          service.removeMember("owner-1", organization.id, "owner-1"),
        );
        const demoteLastOwner = yield* Effect.result(
          service.updateMemberRole("owner-1", organization.id, "owner-1", "member"),
        );

        // Promote a second owner, then the original owner can step down
        const promoted = yield* service.updateMemberRole(
          "owner-1",
          organization.id,
          "admin-1",
          "owner",
        );
        const demoteWithTwoOwners = yield* service.updateMemberRole(
          "owner-1",
          organization.id,
          "owner-1",
          "member",
        );

        // An owner can remove members
        yield* service.removeMember("admin-1", organization.id, "member-1");
        const full = yield* service.getFullOrganization(organization.id);

        return {
          memberPromotes,
          adminRemovesOwner,
          removeLastOwner,
          demoteLastOwner,
          promoted,
          demoteWithTwoOwners,
          full,
        };
      }),
    );

    expect(result.memberPromotes._tag).toBe("Failure");
    expect(result.adminRemovesOwner._tag).toBe("Failure");
    expect(result.removeLastOwner._tag).toBe("Failure");
    expect(result.demoteLastOwner._tag).toBe("Failure");
    expect(result.promoted.role).toBe("owner");
    expect(result.demoteWithTwoOwners.role).toBe("member");
    expect(result.full.members).toHaveLength(2);
  });

  it("rejects adding a duplicate member and removing a missing member", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const duplicateAdd = yield* Effect.result(
          service.addMember("owner-1", organization.id, "member-1", "admin"),
        );
        const removeMissing = yield* Effect.result(
          service.removeMember("owner-1", organization.id, "ghost"),
        );

        return { duplicateAdd, removeMissing };
      }),
    );

    expect(result.duplicateAdd._tag).toBe("Failure");
    expect(result.removeMissing._tag).toBe("Failure");
  });

  it("answers checkPermission and requirePermission", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const ownerCanDelete = yield* service.checkPermission(
          "owner-1",
          organization.id,
          "organization:delete",
        );
        const memberCanDelete = yield* service.checkPermission(
          "member-1",
          organization.id,
          "organization:delete",
        );
        const strangerCanDelete = yield* service.checkPermission(
          "stranger",
          organization.id,
          "organization:delete",
        );
        const required = yield* Effect.result(
          service.requirePermission("member-1", organization.id, "member:create"),
        );

        return { ownerCanDelete, memberCanDelete, strangerCanDelete, required };
      }),
    );

    expect(result.ownerCanDelete).toBe(true);
    expect(result.memberCanDelete).toBe(false);
    expect(result.strangerCanDelete).toBe(false);
    expect(result.required._tag).toBe("Failure");
  });

  it("supports custom roles and creatorRole", async () => {
    const config: OrganizationConfig = {
      creatorRole: "founder",
      roles: {
        founder: [...defaultOrganizationRoles["owner"]],
        collaborator: ["invitation:create"],
      },
    };

    const result = await runService(config, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("founder-1", {
          name: "Startup",
          slug: "startup",
        });
        yield* service.addMember("founder-1", organization.id, "collab-1", "collaborator");

        const collaboratorInvites = yield* service.inviteMember("collab-1", organization.id, {
          email: "new@example.com",
          role: "collaborator",
        });
        const collaboratorRemoves = yield* Effect.result(
          service.removeMember("collab-1", organization.id, "founder-1"),
        );
        const demoteLastFounder = yield* Effect.result(
          service.updateMemberRole("founder-1", organization.id, "founder-1", "collaborator"),
        );
        const full = yield* service.getFullOrganization(organization.id);

        return { collaboratorInvites, collaboratorRemoves, demoteLastFounder, full };
      }),
    );

    expect(result.full.members.find((member) => member.userId === "founder-1")?.role).toBe(
      "founder",
    );
    expect(result.collaboratorInvites.status).toBe("pending");
    expect(result.collaboratorRemoves._tag).toBe("Failure");
    expect(result.demoteLastFounder._tag).toBe("Failure");
  });

  it("creates teams and lists them in both directions", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const engineering = yield* service.createTeam("owner-1", organization.id, {
          name: "Engineering",
        });
        const design = yield* service.createTeam("owner-1", organization.id, { name: "Design" });

        const added = yield* service.addTeamMember("owner-1", engineering.id, "member-1");

        // Any organization member may read the team structure.
        const listed = yield* service.listTeams("member-1", organization.id);
        const teamMembership = yield* service.listTeamMembers("member-1", engineering.id);
        const forMember = yield* service.listTeamsForMember(
          "member-1",
          organization.id,
          "member-1",
        );

        const renamed = yield* service.updateTeam("owner-1", design.id, { name: "Design Ops" });

        return { engineering, design, added, listed, teamMembership, forMember, renamed };
      }),
    );

    expect(result.engineering.name).toBe("Engineering");
    expect(result.engineering.createdAt).toBe(result.engineering.updatedAt);
    expect(result.added.userId).toBe("member-1");
    expect(result.added.teamId).toBe(result.engineering.id);
    expect(
      Arr.sort(
        result.listed.map((team) => team.name),
        Order.String,
      ),
    ).toEqual(["Design", "Engineering"]);
    expect(result.teamMembership).toHaveLength(1);
    expect(result.teamMembership[0].userId).toBe("member-1");
    expect(result.forMember.map((team) => team.id)).toEqual([result.engineering.id]);
    expect(result.renamed.name).toBe("Design Ops");
    expect(result.renamed.updatedAt).toBeGreaterThanOrEqual(result.design.createdAt);
  });

  it("permission-checks team management per role", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        // `member` holds none of the mutating team permissions.
        const memberCreates = yield* Effect.result(
          service.createTeam("member-1", organization.id, { name: "Rogue" }),
        );

        // `admin` holds all four.
        const adminCreates = yield* service.createTeam("admin-1", organization.id, {
          name: "Support",
        });
        const memberUpdates = yield* Effect.result(
          service.updateTeam("member-1", adminCreates.id, { name: "Hijacked" }),
        );
        const memberAdds = yield* Effect.result(
          service.addTeamMember("member-1", adminCreates.id, "member-1"),
        );
        const memberRemoves = yield* Effect.result(
          service.removeTeamMember("member-1", adminCreates.id, "member-1"),
        );
        const memberDeletes = yield* Effect.result(service.deleteTeam("member-1", adminCreates.id));

        // Non-members cannot even read.
        const strangerLists = yield* Effect.result(service.listTeams("stranger", organization.id));
        const strangerListsMembers = yield* Effect.result(
          service.listTeamMembers("stranger", adminCreates.id),
        );
        const strangerListsForMember = yield* Effect.result(
          service.listTeamsForMember("stranger", organization.id, "member-1"),
        );

        const adminDeletes = yield* service.deleteTeam("admin-1", adminCreates.id);

        return {
          memberCreates,
          adminCreates,
          memberUpdates,
          memberAdds,
          memberRemoves,
          memberDeletes,
          strangerLists,
          strangerListsMembers,
          strangerListsForMember,
          adminDeletes,
        };
      }),
    );

    expect(result.memberCreates._tag).toBe("Failure");
    assert(Result.isFailure(result.memberCreates));
    expect(result.memberCreates.failure._tag).toBe("OrganizationError");
    expect(result.adminCreates.name).toBe("Support");
    expect(result.memberUpdates._tag).toBe("Failure");
    expect(result.memberAdds._tag).toBe("Failure");
    expect(result.memberRemoves._tag).toBe("Failure");
    expect(result.memberDeletes._tag).toBe("Failure");
    expect(result.strangerLists._tag).toBe("Failure");
    expect(result.strangerListsMembers._tag).toBe("Failure");
    expect(result.strangerListsForMember._tag).toBe("Failure");
    expect(teams.size).toBe(0);
  });

  it("requires team members to already belong to the organization", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const other = yield* service.createOrganization("owner-2", {
          name: "Other",
          slug: "other",
        });
        yield* service.addMember("owner-1", acme.id, "member-1", "member");

        const team = yield* service.createTeam("owner-1", acme.id, { name: "Engineering" });

        // Not a member of Acme at all.
        const outsider = yield* Effect.result(
          service.addTeamMember("owner-1", team.id, "stranger"),
        );
        // Member of a *different* organization.
        const otherOrgMember = yield* Effect.result(
          service.addTeamMember("owner-1", team.id, "owner-2"),
        );

        yield* service.addTeamMember("owner-1", team.id, "member-1");
        const duplicate = yield* Effect.result(
          service.addTeamMember("owner-1", team.id, "member-1"),
        );

        const missingTeam = yield* Effect.result(
          service.addTeamMember("owner-1", "no-such-team", "member-1"),
        );

        const members = yield* service.listTeamMembers("owner-1", team.id);
        return { other, outsider, otherOrgMember, duplicate, missingTeam, members };
      }),
    );

    expect(result.outsider._tag).toBe("Failure");
    assert(Result.isFailure(result.outsider));
    expect(result.outsider.failure._tag).toBe("OrganizationError");
    expect(result.otherOrgMember._tag).toBe("Failure");
    expect(result.duplicate._tag).toBe("Failure");
    expect(result.missingTeam._tag).toBe("Failure");
    expect(result.members).toHaveLength(1);
  });

  it("cascades team memberships on deleteTeam", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const team = yield* service.createTeam("owner-1", organization.id, {
          name: "Engineering",
        });
        yield* service.addTeamMember("owner-1", team.id, "member-1");
        yield* service.addTeamMember("owner-1", team.id, "owner-1");

        yield* service.deleteTeam("owner-1", team.id);

        const listed = yield* service.listTeams("owner-1", organization.id);
        const forMember = yield* service.listTeamsForMember("owner-1", organization.id, "member-1");
        const gone = yield* Effect.result(service.listTeamMembers("owner-1", team.id));
        return { listed, forMember, gone };
      }),
    );

    expect(result.listed).toHaveLength(0);
    expect(result.forMember).toHaveLength(0);
    expect(result.gone._tag).toBe("Failure");
    expect(teamMembers).toHaveLength(0);
  });

  it("removes team memberships when a member leaves the organization", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const other = yield* service.createOrganization("owner-1", {
          name: "Other",
          slug: "other",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");
        yield* service.addMember("owner-1", other.id, "member-1", "member");

        const engineering = yield* service.createTeam("owner-1", organization.id, {
          name: "Engineering",
        });
        const design = yield* service.createTeam("owner-1", organization.id, { name: "Design" });
        const otherTeam = yield* service.createTeam("owner-1", other.id, { name: "Keep Me" });

        yield* service.addTeamMember("owner-1", engineering.id, "member-1");
        yield* service.addTeamMember("owner-1", design.id, "member-1");
        yield* service.addTeamMember("owner-1", otherTeam.id, "member-1");

        yield* service.removeMember("owner-1", organization.id, "member-1");

        const inRemovedOrg = yield* service.listTeamsForMember(
          "owner-1",
          organization.id,
          "member-1",
        );
        // Teams in other organizations are untouched.
        const inOtherOrg = yield* service.listTeamsForMember("owner-1", other.id, "member-1");
        const engineeringMembers = yield* service.listTeamMembers("owner-1", engineering.id);

        return { inRemovedOrg, inOtherOrg, engineeringMembers, otherTeam };
      }),
    );

    expect(result.inRemovedOrg).toHaveLength(0);
    expect(result.inOtherOrg.map((team) => team.id)).toEqual([result.otherTeam.id]);
    expect(result.engineeringMembers).toHaveLength(0);
  });

  it("fails team operations on an unknown team", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });

        const update = yield* Effect.result(
          service.updateTeam("owner-1", "no-such-team", { name: "Nope" }),
        );
        const remove = yield* Effect.result(service.deleteTeam("owner-1", "no-such-team"));
        const list = yield* Effect.result(service.listTeamMembers("owner-1", "no-such-team"));
        return { update, remove, list };
      }),
    );

    expect(result.update._tag).toBe("Failure");
    assert(Result.isFailure(result.update));
    expect(result.update.failure._tag).toBe("OrganizationError");
    expect(result.remove._tag).toBe("Failure");
    expect(result.list._tag).toBe("Failure");
  });

  it("lets a custom role replace the static definition of the same name", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const other = yield* service.createOrganization("owner-1", {
          name: "Other",
          slug: "other",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");
        yield* service.addMember("owner-1", other.id, "member-1", "member");

        // The static `member` role grants nothing.
        const beforeUpsert = yield* Effect.result(
          service.createTeam("member-1", organization.id, { name: "Nope" }),
        );

        const defined = yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "member",
          permissions: ["team:create"],
        });

        // The replacement is effective immediately, for this organization only.
        const team = yield* service.createTeam("member-1", organization.id, {
          name: "Engineering",
        });
        const inOtherOrg = yield* Effect.result(
          service.createTeam("member-1", other.id, { name: "Nope" }),
        );
        // It *replaces* rather than merges: nothing else the role could have
        // been granted statically survives.
        const canManageTeamMembers = yield* service.checkPermission(
          "member-1",
          organization.id,
          "team:manage-members",
        );

        // Removing the definition falls back to the static map.
        yield* service.deleteOrgRole("owner-1", organization.id, "member");
        const afterDelete = yield* Effect.result(
          service.createTeam("member-1", organization.id, { name: "Nope" }),
        );

        return { beforeUpsert, defined, team, inOtherOrg, canManageTeamMembers, afterDelete };
      }),
    );

    expect(result.beforeUpsert._tag).toBe("Failure");
    expect(result.defined.permissions).toEqual(["team:create"]);
    expect(result.defined.createdAt).toBeLessThanOrEqual(result.defined.updatedAt);
    expect(result.team.name).toBe("Engineering");
    expect(result.inOtherOrg._tag).toBe("Failure");
    expect(result.canManageTeamMembers).toBe(false);
    expect(result.afterDelete._tag).toBe("Failure");
  });

  it("denies every permission for a role no map defines (fail closed)", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "ghost-1", "auditor");

        const beforeDefinition = yield* service.checkPermission(
          "ghost-1",
          organization.id,
          "team:create",
        );
        const requireBefore = yield* Effect.result(
          service.requirePermission("ghost-1", organization.id, "team:create"),
        );

        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: ["team:create"],
        });
        const afterDefinition = yield* service.checkPermission(
          "ghost-1",
          organization.id,
          "team:create",
        );

        return { beforeDefinition, requireBefore, afterDefinition };
      }),
    );

    expect(result.beforeDefinition).toBe(false);
    expect(result.requireBefore._tag).toBe("Failure");
    expect(result.afterDefinition).toBe(true);
  });

  it("honors wildcard permissions in custom role definitions", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "lead-1", "lead");
        yield* service.addMember("owner-1", organization.id, "root-1", "superuser");

        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "lead",
          permissions: ["team:*"],
        });
        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "superuser",
          permissions: ["*:*"],
        });

        const leadCreatesTeams = yield* service.checkPermission(
          "lead-1",
          organization.id,
          "team:create",
        );
        const leadManagesTeamMembers = yield* service.checkPermission(
          "lead-1",
          organization.id,
          "team:manage-members",
        );
        const leadInvites = yield* service.checkPermission(
          "lead-1",
          organization.id,
          "invitation:create",
        );
        const rootDeletesOrganization = yield* service.checkPermission(
          "root-1",
          organization.id,
          "organization:delete",
        );
        const team = yield* service.createTeam("lead-1", organization.id, { name: "Platform" });

        return {
          leadCreatesTeams,
          leadManagesTeamMembers,
          leadInvites,
          rootDeletesOrganization,
          team,
        };
      }),
    );

    expect(result.leadCreatesTeams).toBe(true);
    expect(result.leadManagesTeamMembers).toBe(true);
    expect(result.leadInvites).toBe(false);
    expect(result.rootDeletesOrganization).toBe(true);
    expect(result.team.name).toBe("Platform");
  });

  it("refuses to redefine or delete the protected owner role", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });

        const redefine = yield* Effect.result(
          service.upsertOrgRole("owner-1", organization.id, {
            role: "owner",
            permissions: ["member:create"],
          }),
        );
        const remove = yield* Effect.result(
          service.deleteOrgRole("owner-1", organization.id, "owner"),
        );
        const stillManagesRoles = yield* service.checkPermission(
          "owner-1",
          organization.id,
          "role:manage",
        );
        const listed = yield* service.listOrgRoles("owner-1", organization.id);

        return { redefine, remove, stillManagesRoles, listed };
      }),
    );

    expect(result.redefine._tag).toBe("Failure");
    assert(Result.isFailure(result.redefine));
    expect(result.redefine.failure._tag).toBe("OrganizationError");
    expect(result.remove._tag).toBe("Failure");
    expect(result.stillManagesRoles).toBe(true);
    expect(result.listed).toHaveLength(0);
  });

  it("gates role management on role:manage and listing on membership", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const adminUpserts = yield* Effect.result(
          service.upsertOrgRole("admin-1", organization.id, {
            role: "auditor",
            permissions: ["team:create"],
          }),
        );
        const ownerUpserts = yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: ["team:create"],
        });
        const adminDeletes = yield* Effect.result(
          service.deleteOrgRole("admin-1", organization.id, "auditor"),
        );

        const memberLists = yield* service.listOrgRoles("member-1", organization.id);
        const strangerLists = yield* Effect.result(
          service.listOrgRoles("stranger", organization.id),
        );

        return { adminUpserts, ownerUpserts, adminDeletes, memberLists, strangerLists };
      }),
    );

    expect(result.adminUpserts._tag).toBe("Failure");
    expect(result.adminDeletes._tag).toBe("Failure");
    expect(result.ownerUpserts.role).toBe("auditor");
    expect(result.memberLists.map((orgRole) => orgRole.role)).toEqual(["auditor"]);
    expect(result.strangerLists._tag).toBe("Failure");
  });

  it("cascades custom roles when the organization is deleted", async () => {
    await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const kept = yield* service.createOrganization("owner-1", { name: "Keep", slug: "keep" });

        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: ["team:create"],
        });
        yield* service.upsertOrgRole("owner-1", kept.id, {
          role: "auditor",
          permissions: ["team:create"],
        });

        yield* service.deleteOrganization("owner-1", organization.id);
        return kept;
      }),
    );

    expect([...orgRoles.values()].map((orgRole) => orgRole.role)).toEqual(["auditor"]);
  });

  it("re-upserting a role keeps createdAt and refreshes updatedAt", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const first = yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: ["team:create"],
        });
        const second = yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: ["team:create", "team:delete"],
        });
        const listed = yield* service.listOrgRoles("owner-1", organization.id);
        return { first, second, listed };
      }),
    );

    expect(result.second.createdAt).toBe(result.first.createdAt);
    expect(result.second.updatedAt).toBeGreaterThanOrEqual(result.first.updatedAt);
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0].permissions).toEqual(["team:create", "team:delete"]);
  });
});

describe("OrganizationService - member status", () => {
  beforeEach(resetStores);

  it("deactivates a member, denying every permission, then restores the role", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
        const team = yield* service.createTeam("owner-1", organization.id, { name: "Platform" });
        yield* service.addTeamMember("owner-1", team.id, "admin-1");

        const beforeDeactivation = yield* service.checkPermission(
          "admin-1",
          organization.id,
          "team:create",
        );

        const deactivated = yield* service.deactivateMember("owner-1", organization.id, "admin-1");
        const afterDeactivation = yield* service.checkPermission(
          "admin-1",
          organization.id,
          "team:create",
        );
        // A non-member for authorization, in both the permission and the
        // membership-only paths.
        const managementDenied = yield* Effect.result(
          service.createTeam("admin-1", organization.id, { name: "Nope" }),
        );
        const listingDenied = yield* Effect.result(service.listTeams("admin-1", organization.id));
        // ... but the row, and the team membership, are still there.
        const stillInTheOrganization = yield* service.getFullOrganization(organization.id);
        const stillInTheTeam = yield* service.listTeamMembers("owner-1", team.id);

        const reactivated = yield* service.reactivateMember("owner-1", organization.id, "admin-1");
        const afterReactivation = yield* service.checkPermission(
          "admin-1",
          organization.id,
          "team:create",
        );

        return {
          beforeDeactivation,
          deactivated,
          afterDeactivation,
          managementDenied,
          listingDenied,
          stillInTheOrganization,
          stillInTheTeam,
          reactivated,
          afterReactivation,
        };
      }),
    );

    expect(result.beforeDeactivation).toBe(true);
    expect(result.deactivated.status).toBe("inactive");
    // Demoted to the organization's default role, with the real one parked.
    expect(result.deactivated.role).toBe("member");
    expect(result.deactivated.previousRole).toBe("admin");
    expect(result.afterDeactivation).toBe(false);
    expect(result.managementDenied._tag).toBe("Failure");
    expect(result.listingDenied._tag).toBe("Failure");
    expect(result.stillInTheOrganization.members).toHaveLength(2);
    expect(result.stillInTheTeam.map((member) => member.userId)).toEqual(["admin-1"]);
    expect(result.reactivated.status).toBe("active");
    expect(result.reactivated.role).toBe("admin");
    expect(result.reactivated.previousRole).toBeUndefined();
    expect(result.afterReactivation).toBe(true);
  });

  it("refuses to deactivate the last active owner, or an owner as a non-owner", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
        yield* service.addMember("owner-1", organization.id, "owner-2", "owner");

        const byAdmin = yield* Effect.result(
          service.deactivateMember("admin-1", organization.id, "owner-2"),
        );
        // Two owners: the first may go.
        const first = yield* service.deactivateMember("owner-1", organization.id, "owner-2");
        // One active owner left: they may not.
        const last = yield* Effect.result(
          service.deactivateMember("owner-1", organization.id, "owner-1"),
        );
        // And the inactive owner does not prop the count back up.
        const demoteLast = yield* Effect.result(
          service.updateMemberRole("owner-1", organization.id, "owner-1", "member"),
        );

        return { byAdmin, first, last, demoteLast };
      }),
    );

    expect(result.byAdmin._tag).toBe("Failure");
    expect(result.first.status).toBe("inactive");
    expect(result.last._tag).toBe("Failure");
    assert(Result.isFailure(result.last));
    expect(result.last.failure._tag).toBe("OrganizationError");
    expect(result.demoteLast._tag).toBe("Failure");
  });

  it("refuses double deactivation, reactivating an active member, and inactive role edits", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const reactivateActive = yield* Effect.result(
          service.reactivateMember("owner-1", organization.id, "member-1"),
        );
        yield* service.deactivateMember("owner-1", organization.id, "member-1");
        const deactivateAgain = yield* Effect.result(
          service.deactivateMember("owner-1", organization.id, "member-1"),
        );
        const editRole = yield* Effect.result(
          service.updateMemberRole("owner-1", organization.id, "member-1", "admin"),
        );
        const unknown = yield* Effect.result(
          service.deactivateMember("owner-1", organization.id, "ghost"),
        );

        return { reactivateActive, deactivateAgain, editRole, unknown };
      }),
    );

    expect(result.reactivateActive._tag).toBe("Failure");
    expect(result.deactivateAgain._tag).toBe("Failure");
    expect(result.editRole._tag).toBe("Failure");
    expect(result.unknown._tag).toBe("Failure");
  });

  it("hands the deactivated membership to onMemberDeactivated", async () => {
    const seen: Array<{ readonly userId: string; readonly slug: string }> = [];
    const result = await runService(
      {
        onMemberDeactivated: (member, organization) =>
          Effect.sync(() => void seen.push({ userId: member.userId, slug: organization.slug })),
      },
      (service) =>
        Effect.gen(function* () {
          const organization = yield* service.createOrganization("owner-1", {
            name: "Acme",
            slug: "acme",
          });
          yield* service.addMember("owner-1", organization.id, "member-1", "member");
          return yield* service.deactivateMember("owner-1", organization.id, "member-1");
        }),
    );

    expect(result.status).toBe("inactive");
    expect(seen).toEqual([{ userId: "member-1", slug: "acme" }]);
  });
});

describe("OrganizationService - default role", () => {
  beforeEach(resetStores);

  it("uses the organization's default role when addMember names none", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const beforeChange = yield* service.addMember("owner-1", organization.id, "user-1");

        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "contributor",
          permissions: ["team:create"],
        });
        const updated = yield* service.setDefaultRole("owner-1", organization.id, "contributor");
        const afterChange = yield* service.addMember("owner-1", organization.id, "user-2");
        const explicit = yield* service.addMember("owner-1", organization.id, "user-3", "admin");

        return { beforeChange, updated, afterChange, explicit };
      }),
    );

    expect(result.beforeChange.role).toBe("member");
    expect(result.updated.defaultRole).toBe("contributor");
    expect(result.afterChange.role).toBe("contributor");
    expect(result.explicit.role).toBe("admin");
  });

  it("gates the default role on role:manage and validates it against the role set", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "admin-1", "admin");

        const byAdmin = yield* Effect.result(
          service.setDefaultRole("admin-1", organization.id, "admin"),
        );
        const undefinedRole = yield* Effect.result(
          service.setDefaultRole("owner-1", organization.id, "auditor"),
        );
        const staticRole = yield* service.setDefaultRole("owner-1", organization.id, "admin");

        return { byAdmin, undefinedRole, staticRole };
      }),
    );

    expect(result.byAdmin._tag).toBe("Failure");
    expect(result.undefinedRole._tag).toBe("Failure");
    assert(Result.isFailure(result.undefinedRole));
    expect(result.undefinedRole.failure._tag).toBe("OrganizationError");
    expect(result.staticRole.defaultRole).toBe("admin");
  });
});

describe("OrganizationService - invitations", () => {
  beforeEach(resetStores);

  it("resends a pending invitation on the same row, with a fresh expiry", async () => {
    const delivered: Array<{ readonly id: string; readonly expiresAt: number }> = [];
    const result = await runService(
      {
        invitationExpiresIn: 60_000,
        sendInvitationEmail: (invitation) =>
          Effect.sync(
            () => void delivered.push({ id: invitation.id, expiresAt: invitation.expiresAt }),
          ),
      },
      (service) =>
        Effect.gen(function* () {
          const organization = yield* service.createOrganization("owner-1", {
            name: "Acme",
            slug: "acme",
          });
          const invitation = yield* service.inviteMember("owner-1", organization.id, {
            email: "new@acme.test",
            role: "member",
          });

          // Age the row: a pending-but-expired invitation is exactly what a
          // resend is for.
          invitations.set(invitation.id, {
            ...invitation,
            expiresAt: (yield* Clock.currentTimeMillis) - 1_000,
          });

          const resent = yield* service.resendInvitation("owner-1", invitation.id);
          const listed = yield* service.listInvitations(organization.id);
          return { invitation, resent, listed };
        }),
    );

    expect(result.resent.id).toBe(result.invitation.id);
    expect(result.resent.status).toBe("pending");
    expect(result.resent.expiresAt).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
    expect(result.listed).toHaveLength(1);
    expect(delivered.map((entry) => entry.id)).toEqual([
      result.invitation.id,
      result.invitation.id,
    ]);
    // The resend re-dates from "now", which in a single tick can equal the
    // original expiry - what matters is that the aged row was pushed forward.
    expect(delivered[1].expiresAt).toBeGreaterThanOrEqual(delivered[0].expiresAt);
  });

  it("refuses to resend an unknown, accepted or canceled invitation", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");
        seedEmail("invitee-1", "invitee@acme.test");

        const accepted = yield* service.inviteMember("owner-1", organization.id, {
          email: "invitee@acme.test",
          role: "member",
        });
        yield* service.acceptInvitation("invitee-1", accepted.id);

        const canceled = yield* service.inviteMember("owner-1", organization.id, {
          email: "other@acme.test",
          role: "member",
        });
        yield* service.cancelInvitation("owner-1", canceled.id);

        const pending = yield* service.inviteMember("owner-1", organization.id, {
          email: "third@acme.test",
          role: "member",
        });

        const unknown = yield* Effect.result(service.resendInvitation("owner-1", "no-such-id"));
        const resendAccepted = yield* Effect.result(
          service.resendInvitation("owner-1", accepted.id),
        );
        const resendCanceled = yield* Effect.result(
          service.resendInvitation("owner-1", canceled.id),
        );
        const byPlainMember = yield* Effect.result(
          service.resendInvitation("member-1", pending.id),
        );

        return { unknown, resendAccepted, resendCanceled, byPlainMember };
      }),
    );

    expect(result.unknown._tag).toBe("Failure");
    assert(Result.isFailure(result.unknown));
    expect(result.unknown.failure._tag).toBe("OrganizationError");
    expect(result.resendAccepted._tag).toBe("Failure");
    expect(result.resendCanceled._tag).toBe("Failure");
    expect(result.byPlainMember._tag).toBe("Failure");
  });
});

describe("OrganizationService - domains", () => {
  beforeEach(resetStores);

  it("claims, lists and releases a domain, minting a DNS token server-side", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const claim = yield* service.addDomain("owner-1", organization.id, {
          domain: "  ACME.test ",
        });
        const listedByMember = yield* service.listDomains("member-1", organization.id);
        const claimedByMember = yield* Effect.result(
          service.addDomain("member-1", organization.id, { domain: "other.test" }),
        );
        const invalid = yield* Effect.result(
          service.addDomain("owner-1", organization.id, { domain: "not-a-domain" }),
        );

        yield* service.removeDomain("owner-1", organization.id, claim.id);
        const afterRemoval = yield* service.listDomains("owner-1", organization.id);
        const removeUnknown = yield* Effect.result(
          service.removeDomain("owner-1", organization.id, claim.id),
        );

        return { claim, listedByMember, claimedByMember, invalid, afterRemoval, removeUnknown };
      }),
    );

    expect(result.claim.domain).toBe("acme.test");
    expect(result.claim.verificationState).toBe("pending");
    expect(result.claim.verificationStrategy).toBe("dns");
    expect(result.claim.verificationToken).toBeTypeOf("string");
    expect(result.claim.verifiedAt).toBeUndefined();
    expect(result.listedByMember.map((domain) => domain.domain)).toEqual(["acme.test"]);
    expect(result.claimedByMember._tag).toBe("Failure");
    expect(result.invalid._tag).toBe("Failure");
    expect(result.afterRemoval).toEqual([]);
    expect(result.removeUnknown._tag).toBe("Failure");
  });

  it("keeps a domain unique across organizations, pending claims included", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const globex = yield* service.createOrganization("owner-2", {
          name: "Globex",
          slug: "globex",
        });

        const first = yield* service.addDomain("owner-1", acme.id, { domain: "shared.test" });
        const sameOrganization = yield* Effect.result(
          service.addDomain("owner-1", acme.id, { domain: "shared.test" }),
        );
        const otherOrganization = yield* Effect.result(
          service.addDomain("owner-2", globex.id, { domain: "SHARED.test" }),
        );
        const globexDomains = yield* service.listDomains("owner-2", globex.id);

        return { first, sameOrganization, otherOrganization, globexDomains };
      }),
    );

    expect(result.first.verificationState).toBe("pending");
    expect(result.sameOrganization._tag).toBe("Failure");
    expect(result.otherOrganization._tag).toBe("Failure");
    expect(result.globexDomains).toEqual([]);
  });

  it("releases the organization's domain claims when it is deleted", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const kept = yield* service.createOrganization("owner-1", { name: "Keep", slug: "keep" });
        yield* service.addDomain("owner-1", acme.id, { domain: "acme.test" });
        yield* service.addDomain("owner-1", kept.id, { domain: "keep.test" });

        yield* service.deleteOrganization("owner-1", acme.id);

        // The domain is free again for whoever claims it next.
        const reclaimed = yield* service.addDomain("owner-1", kept.id, { domain: "acme.test" });
        const keptDomains = yield* service.listDomains("owner-1", kept.id);
        return { reclaimed, keptDomains };
      }),
    );

    expect(result.reclaimed.organizationId).toBeTypeOf("string");
    expect(
      Arr.sort(
        result.keptDomains.map((domain) => domain.domain),
        Order.String,
      ),
    ).toEqual(["acme.test", "keep.test"]);
  });

  it("verifies a DNS claim through the DomainVerifier, and records a failed check", async () => {
    const seen: Array<{ readonly domain: string; readonly token: string }> = [];
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const claim = yield* service.addDomain("owner-1", organization.id, {
          domain: "acme.test",
        });
        // No verifier in context: the DNS strategy is simply unavailable.
        const withoutVerifier = yield* Effect.result(
          service.verifyDomain("owner-1", organization.id, claim.id),
        );
        return { organization, claim, withoutVerifier };
      }),
    );

    expect(result.withoutVerifier._tag).toBe("Failure");
    assert(Result.isFailure(result.withoutVerifier));
    expect(result.withoutVerifier.failure._tag).toBe("OrganizationError");

    // Same claim, now with a verifier that does not find the record yet.
    const failed = await runServiceWithVerifier({}, stubDomainVerifier([], seen), (service) =>
      service.verifyDomain("owner-1", result.organization.id, result.claim.id),
    );
    expect(failed.verificationState).toBe("failed");
    expect(failed.verifiedAt).toBeUndefined();
    const token = result.claim.verificationToken;
    assert(token !== undefined, "a DNS claim carries a verification token");
    expect(seen).toEqual([{ domain: "acme.test", token }]);

    // ... and once it does, the retry succeeds.
    const verified = await runServiceWithVerifier(
      {},
      stubDomainVerifier([{ domain: "acme.test", token }]),

      (service) =>
        Effect.gen(function* () {
          const first = yield* service.verifyDomain(
            "owner-1",
            result.organization.id,
            result.claim.id,
          );
          // Re-verifying a verified claim is idempotent.
          const again = yield* service.verifyDomain(
            "owner-1",
            result.organization.id,
            result.claim.id,
          );
          return { first, again };
        }),
    );
    expect(verified.first.verificationState).toBe("verified");
    expect(verified.first.verifiedAt).toBeTypeOf("number");
    expect(verified.again.verifiedAt).toBe(verified.first.verifiedAt);
  });

  it("verifies a manual claim on the actor's permission alone", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addMember("owner-1", organization.id, "member-1", "member");

        const claim = yield* service.addDomain("owner-1", organization.id, {
          domain: "acme.test",
          verificationStrategy: "manual",
        });
        const byMember = yield* Effect.result(
          service.verifyDomain("member-1", organization.id, claim.id),
        );
        const verified = yield* service.verifyDomain("owner-1", organization.id, claim.id);
        return { claim, byMember, verified };
      }),
    );

    // Nothing to publish, so no token is minted.
    expect(result.claim.verificationToken).toBeUndefined();
    expect(result.byMember._tag).toBe("Failure");
    expect(result.verified.verificationState).toBe("verified");
    expect(result.verified.verifiedAt).toBeTypeOf("number");
  });

  it("refuses domain operations when no OrganizationDomainStore is wired", async () => {
    const result = await runServiceIn(baseContext, {}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        const list = yield* Effect.result(service.listDomains("owner-1", organization.id));
        const add = yield* Effect.result(
          service.addDomain("owner-1", organization.id, { domain: "acme.test" }),
        );
        // JIT is a no-op rather than a failure: it runs on a sign-in path.
        const jit = yield* service.provisionJitMembership("user-1", "user@acme.test");
        return { list, add, jit };
      }),
    );

    expect(result.list._tag).toBe("Failure");
    expect(result.add._tag).toBe("Failure");
    expect(result.jit).toBeNull();
  });
});

describe("OrganizationService - JIT provisioning", () => {
  beforeEach(resetStores);

  /** An organization with a verified domain, JIT off until a test turns it on. */
  const withVerifiedDomain = (service: typeof OrganizationService.Service) =>
    Effect.gen(function* () {
      const organization = yield* service.createOrganization("owner-1", {
        name: "Acme",
        slug: "acme",
      });
      const claim = yield* service.addDomain("owner-1", organization.id, {
        domain: "acme.test",
        verificationStrategy: "manual",
      });
      yield* service.verifyDomain("owner-1", organization.id, claim.id);
      return organization;
    });

  it("adds a member with the organization's default role, once JIT is enabled", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* withVerifiedDomain(service);

        // Opt-out is the default: nothing happens until the org says so.
        const optedOut = yield* service.provisionJitMembership("user-1", "new@acme.test");

        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "contributor",
          permissions: ["team:create"],
        });
        yield* service.setDefaultRole("owner-1", organization.id, "contributor");
        yield* service.updateOrganization("owner-1", organization.id, { jitProvisioning: true });

        const provisioned = yield* service.provisionJitMembership("user-1", "NEW@Acme.test");
        const second = yield* service.provisionJitMembership("user-1", "new@acme.test");
        const unrelatedDomain = yield* service.provisionJitMembership("user-2", "x@other.test");
        const members = yield* service.getFullOrganization(organization.id);

        return { optedOut, provisioned, second, unrelatedDomain, members };
      }),
    );

    expect(result.optedOut).toBeNull();
    expect(result.provisioned).not.toBeNull();
    expect(result.provisioned?.role).toBe("contributor");
    expect(result.provisioned?.status).toBe("active");
    // Already a member: no second row, no role churn.
    expect(result.second).toBeNull();
    expect(result.unrelatedDomain).toBeNull();
    expect(result.members.members).toHaveLength(2);
  });

  it("ignores a domain claim that is not verified", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.addDomain("owner-1", organization.id, {
          domain: "acme.test",
          verificationStrategy: "manual",
        });
        yield* service.updateOrganization("owner-1", organization.id, { jitProvisioning: true });

        const pending = yield* service.provisionJitMembership("user-1", "new@acme.test");
        const members = yield* service.getFullOrganization(organization.id);
        return { pending, members };
      }),
    );

    expect(result.pending).toBeNull();
    expect(result.members.members).toHaveLength(1);
  });
});
