import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Crypto, Effect } from "effect";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  OrganizationStore,
  defaultOrganizationRoles,
  type Invitation,
  type Member,
  type Organization,
  type OrganizationConfig,
  type OrganizationService,
} from "./Organization.ts";
import * as OrganizationModule from "./Organization.ts";

const organizations = new Map<string, Organization>();
const members = new Map<string, Member>();
const invitations = new Map<string, Invitation>();

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
      for (const [id, member] of members.entries()) {
        if (member.organizationId === organizationId) {
          members.delete(id);
        }
      }
      for (const [id, invitation] of invitations.entries()) {
        if (invitation.organizationId === organizationId) {
          invitations.delete(id);
        }
      }
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
};

const testContext = Context.merge(
  Context.make(OrganizationStore, organizationStore),
  Context.make(Crypto.Crypto, PlatformCrypto.instance),
);

const runService = <A, E>(
  config: OrganizationConfig,
  program: (service: typeof OrganizationService.Service) => Effect.Effect<A, E, OrganizationStore>,
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

describe("OrganizationService", () => {
  beforeEach(() => {
    organizations.clear();
    members.clear();
    invitations.clear();
  });

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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OrganizationError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OrganizationError");
    }
    expect(organizations.size).toBe(2);
  });

  it("respects allowUserToCreateOrganization: false", async () => {
    const result = await runService({ allowUserToCreateOrganization: false }, (service) =>
      Effect.result(service.createOrganization("user-1", { name: "Acme", slug: "acme" })),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OrganizationError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OrganizationError");
    }
  });

  it("runs the invitation lifecycle: invite, send email, accept", async () => {
    const sentEmails: Array<{ invitation: Invitation; organization: Organization }> = [];

    const config: OrganizationConfig = {
      sendInvitationEmail: (invitation, organization) =>
        Effect.sync(() => {
          sentEmails.push({ invitation, organization });
        }),
    };

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

        const member = yield* service.acceptInvitation(
          "invitee-user",
          invitation.id,
          "invitee@example.com",
        );

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

  it("rejects accepting an invitation with the wrong email", async () => {
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
        return yield* Effect.result(
          service.acceptInvitation("other-user", invitation.id, "other@example.com"),
        );
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OrganizationError");
    }
    expect(Array.from(invitations.values())[0].status).toBe("pending");
  });

  it("rejects accepting an expired invitation", async () => {
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
          service.acceptInvitation("invitee-user", invitation.id, "invitee@example.com"),
        );
        const userInvitations = yield* service.listUserInvitations("invitee@example.com");
        return { accept, userInvitations };
      }),
    );

    expect(result.accept._tag).toBe("Failure");
    if (result.accept._tag === "Failure") {
      expect(result.accept.failure._tag).toBe("OrganizationError");
    }
    // Expired invitations are excluded from the user's pending list
    expect(result.userInvitations).toHaveLength(0);
  });

  it("supports rejecting an invitation and blocks re-acceptance", async () => {
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

        const rejected = yield* service.rejectInvitation(invitation.id, "invitee@example.com");
        const acceptAfterReject = yield* Effect.result(
          service.acceptInvitation("invitee-user", invitation.id, "invitee@example.com"),
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
});
