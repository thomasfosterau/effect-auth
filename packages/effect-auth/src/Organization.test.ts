import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import {
  Clock,
  Context,
  DateTime,
  Effect,
  Exit,
  Layer,
  MutableHashMap,
  Order,
  Result,
} from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { SecureRandom } from "effect/crypto";
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
  type InvitationDelivery,
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
import * as Testing from "./testing/index.ts";
import type { AuthError } from "./Errors.ts";
import { hashToken } from "./TokenHash.ts";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { SessionService } from "./SessionService.ts";

const organizations = MutableHashMap.empty<string, Organization>();
const members = MutableHashMap.empty<string, Member>();
const invitations = MutableHashMap.empty<string, Invitation>();
const teams = MutableHashMap.empty<string, Team>();
const teamMembers: TeamMember[] = [];
const orgRoles = MutableHashMap.empty<string, OrgRole>();
const domainRecords = MutableHashMap.empty<string, OrganizationDomain>();
const identifierRecords = MutableHashMap.empty<string, Identifier>();

/** Composite key for the custom-role table. */
const orgRoleKey = (organizationId: string, role: string): string =>
  `${organizationId}\u0000${role}`;

/** Give a user an email identifier (unverified unless `verified`) so
 * invitations addressed to it can be accepted/rejected by that user. */
const seedEmail = (userId: string, email: string, verified = false): void => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifierRecords, identifier.id, identifier);
};

/** Drop every team-membership row matching `predicate` (in-place). */
const removeTeamMemberRows = (predicate: (teamMember: TeamMember) => boolean): void => {
  const kept = teamMembers.filter((teamMember) => !predicate(teamMember));
  teamMembers.splice(0, teamMembers.length, ...kept);
};

const organizationStore = {
  createOrganization: (organization: Organization) =>
    Effect.sync(() => {
      MutableHashMap.set(organizations, organization.id, organization);
      return organization;
    }),

  getOrganizationById: (organizationId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(organizations, organizationId))),

  getOrganizationBySlug: (slug: string) =>
    Effect.sync(
      () =>
        Array.from(MutableHashMap.values(organizations)).find(
          (organization) => organization.slug === slug,
        ) ?? null,
    ),

  updateOrganization: (organization: Organization) =>
    Effect.sync(() => {
      MutableHashMap.set(organizations, organization.id, organization);
      return organization;
    }),

  deleteOrganization: (organizationId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(organizations, organizationId);
      MutableHashMap.forEach(members, (member, id) => {
        if (member.organizationId === organizationId) {
          MutableHashMap.remove(members, id);
        }
      });
      MutableHashMap.forEach(invitations, (invitation, id) => {
        if (invitation.organizationId === organizationId) {
          MutableHashMap.remove(invitations, id);
        }
      });
      MutableHashMap.forEach(teams, (team, id) => {
        if (team.organizationId === organizationId) {
          MutableHashMap.remove(teams, id);
          removeTeamMemberRows((teamMember) => teamMember.teamId === id);
        }
      });
      MutableHashMap.forEach(orgRoles, (orgRole, key) => {
        if (orgRole.organizationId === organizationId) {
          MutableHashMap.remove(orgRoles, key);
        }
      });
    }),

  createMember: (member: Member) =>
    Effect.sync(() => {
      MutableHashMap.set(members, member.id, member);
      return member;
    }),

  getMember: (organizationId: string, userId: string) =>
    Effect.sync(
      () =>
        Array.from(MutableHashMap.values(members)).find(
          (member) => member.organizationId === organizationId && member.userId === userId,
        ) ?? null,
    ),

  getMemberById: (memberId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(members, memberId))),

  updateMember: (member: Member) =>
    Effect.sync(() => {
      MutableHashMap.set(members, member.id, member);
      return member;
    }),

  deleteMember: (memberId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(members, memberId);
    }),

  listMembersByOrganization: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(members)).filter(
        (member) => member.organizationId === organizationId,
      ),
    ),

  listMembersByUser: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(members)).filter((member) => member.userId === userId),
    ),

  countMembersByOrganization: (organizationId: string) =>
    Effect.sync(
      () =>
        Array.from(MutableHashMap.values(members)).filter(
          (member) => member.organizationId === organizationId,
        ).length,
    ),

  createInvitation: (invitation: Invitation) =>
    Effect.sync(() => {
      MutableHashMap.set(invitations, invitation.id, invitation);
      return invitation;
    }),

  getInvitation: (invitationId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(invitations, invitationId))),

  updateInvitation: (invitation: Invitation) =>
    Effect.sync(() => {
      MutableHashMap.set(invitations, invitation.id, invitation);
      return invitation;
    }),

  listInvitationsByOrganization: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(invitations)).filter(
        (invitation) => invitation.organizationId === organizationId,
      ),
    ),

  listInvitationsByEmail: (email: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(invitations)).filter(
        (invitation) => invitation.email === email,
      ),
    ),

  createTeam: (team: Team) =>
    Effect.sync(() => {
      MutableHashMap.set(teams, team.id, team);
      return team;
    }),

  getTeam: (teamId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(teams, teamId))),

  updateTeam: (team: Team) =>
    Effect.sync(() => {
      if (!MutableHashMap.has(teams, team.id)) return null;
      MutableHashMap.set(teams, team.id, team);
      return team;
    }),

  deleteTeam: (teamId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(teams, teamId);
      removeTeamMemberRows((teamMember) => teamMember.teamId === teamId);
    }),

  listTeams: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(teams)).filter(
        (team) => team.organizationId === organizationId,
      ),
    ),

  addTeamMember: (teamMember: TeamMember) =>
    Effect.sync(() => {
      teamMembers.push(teamMember);
      return teamMember;
    }),

  getTeamMemberById: (teamMemberId: string) =>
    Effect.sync(() => teamMembers.find((teamMember) => teamMember.id === teamMemberId) ?? null),

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
        .map((teamMember) => Option.getOrUndefined(MutableHashMap.get(teams, teamMember.teamId)))
        .filter(
          (team): team is Team => team !== undefined && team.organizationId === organizationId,
        ),
    ),

  upsertOrgRole: (orgRole: OrgRole) =>
    Effect.sync(() => {
      MutableHashMap.set(orgRoles, orgRoleKey(orgRole.organizationId, orgRole.role), orgRole);
      return orgRole;
    }),

  getOrgRole: (organizationId: string, role: string) =>
    Effect.sync(() =>
      Option.getOrNull(MutableHashMap.get(orgRoles, orgRoleKey(organizationId, role))),
    ),

  getOrgRoleById: (orgRoleId: string) =>
    Effect.sync(
      () =>
        Array.from(MutableHashMap.values(orgRoles)).find((orgRole) => orgRole.id === orgRoleId) ??
        null,
    ),

  listOrgRoles: (organizationId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(orgRoles)).filter(
        (orgRole) => orgRole.organizationId === organizationId,
      ),
    ),

  deleteOrgRole: (organizationId: string, role: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(orgRoles, orgRoleKey(organizationId, role));
    }),
};

/** Everything the service needs except the optional domain half. */
const baseContext = Context.merge(
  Context.merge(
    Context.make(OrganizationStore, organizationStore),
    Context.make(IdentifierStore, memoryIdentifierStore(identifierRecords)),
  ),
  Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
);

const testContext = Context.merge(
  baseContext,
  Context.make(OrganizationDomainStore, memoryOrganizationDomainStore(domainRecords)),
);

/** The accounts the first-proof tests sign in (#586); passwords live in `userTable`. */
const userTable = Testing.memoryUserTable();
const accountUsers = Arr.map(["invitee-user", "other-user"], (id) => Testing.fixtureUser({ id }));

/** Invitations the service "emailed", with their secret tokens (newest last). */
const sentInvitations: InvitationDelivery[] = [];

/** The token the invitation's latest email carried. */
const tokenFor = (invitationId: string): string =>
  Option.match(
    Arr.findLast(sentInvitations, (sent) => sent.invitation.id === invitationId),
    { onNone: () => assert.fail(`no email for ${invitationId}`), onSome: (sent) => sent.token },
  );

/** The invitee's answer to `invitation`, with the token its email carried. */
const answer = (invitation: Invitation) => ({
  invitationId: invitation.id,
  token: tokenFor(invitation.id),
});

/** A fresh `SessionService` over {@link accountUsers}, and the {@link userTable} passwords. */
const proofLayer = () =>
  Layer.merge(
    Layer.succeed(EmailPasswordStore, Testing.memoryEmailPasswordStore(userTable)),
    Testing.sessionServiceLayer({ users: accountUsers }),
  );

/** What every service under test is built over, besides the stores in `context`. */
type ProofServices = EmailPasswordStore | SessionService;

/** The stores every run's context holds. */
type BaseServices = OrganizationStore | IdentifierStore | SecureRandom.SecureRandom;

/**
 * Build the service from `config` (delivering invitations into
 * {@link sentInvitations} unless the config says otherwise) over `context`,
 * a fresh `SessionService` and the {@link userTable} passwords, and run
 * `program` with it.
 */
const runServiceIn = <A, E>(
  context: Context.Context<BaseServices>,
  config: OrganizationConfig,
  program: (
    service: typeof OrganizationService.Service,
  ) => Effect.Effect<A, E, BaseServices | ProofServices>,
): Promise<A> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const service = yield* OrganizationModule.make({
        sendInvitationEmail: (delivery) => Effect.sync(() => void sentInvitations.push(delivery)),
        ...config,
      });
      return yield* program(service);
    }).pipe(Effect.provide(Layer.merge(Layer.succeedContext(context), proofLayer()))),
  );

const runService = <A, E>(
  config: OrganizationConfig,
  program: (
    service: typeof OrganizationService.Service,
  ) => Effect.Effect<A, E, BaseServices | ProofServices>,
): Promise<A> => runServiceIn(testContext, config, program);

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
  ) => Effect.Effect<A, E, OrganizationStore | IdentifierStore | ProofServices>,
): Promise<A> =>
  runServiceIn(Context.merge(testContext, Context.make(DomainVerifier, verifier)), config, program);
/** Empty every in-memory table between tests. */
const resetStores = (): void => {
  MutableHashMap.clear(organizations);
  MutableHashMap.clear(members);
  MutableHashMap.clear(invitations);
  MutableHashMap.clear(teams);
  teamMembers.length = 0;
  MutableHashMap.clear(orgRoles);
  MutableHashMap.clear(domainRecords);
  MutableHashMap.clear(identifierRecords);
  MutableHashMap.clear(userTable.passwordHashes);
  sentInvitations.length = 0;
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
    expect(MutableHashMap.size(organizations)).toBe(1);
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
    expect(MutableHashMap.size(organizations)).toBe(2);
  });

  it("respects allowUserToCreateOrganization: false", async () => {
    const result = await runService({ allowUserToCreateOrganization: false }, (service) =>
      Effect.result(service.createOrganization("user-1", { name: "Acme", slug: "acme" })),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(MutableHashMap.size(organizations)).toBe(0);
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
    expect(MutableHashMap.size(organizations)).toBe(0);
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
    seedEmail("invitee-user", "invitee@example.com");

    const result = await runService({}, (service) =>
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

        const member = yield* service.acceptInvitation("invitee-user", answer(invitation));

        const afterAccept = yield* service.listUserInvitations("invitee@example.com");
        const full = yield* service.getFullOrganization(organization.id);

        return { invitation, duplicate, userInvitations, member, afterAccept, full };
      }),
    );

    expect(result.invitation.email).toBe("invitee@example.com");
    expect(result.invitation.status).toBe("pending");
    expect(result.invitation.inviterId).toBe("owner-1");
    expect(sentInvitations).toHaveLength(1);
    expect(sentInvitations[0].invitation.id).toBe(result.invitation.id);
    expect(sentInvitations[0].organization.slug).toBe("acme");
    // Only the token's digest is stored.
    expect(result.invitation.tokenHash).toBe(hashToken(sentInvitations[0].token));
    expect(R.values(result.invitation)).not.toContain(sentInvitations[0].token);
    expect(result.duplicate._tag).toBe("Failure");
    expect(result.userInvitations).toHaveLength(1);
    expect(result.member.userId).toBe("invitee-user");
    expect(result.member.role).toBe("member");
    expect(result.afterAccept).toHaveLength(0);
    expect(
      Option.getOrUndefined(MutableHashMap.get(invitations, result.invitation.id))?.status,
    ).toBe("accepted");
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
        return yield* Effect.result(service.acceptInvitation("other-user", answer(invitation)));
      }),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OrganizationError");
    expect(Array.from(MutableHashMap.values(invitations))[0].status).toBe("pending");
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
          service.acceptInvitation("invitee-user", answer(invitation)),
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

        const rejected = yield* service.rejectInvitation("invitee-user", answer(invitation));
        const acceptAfterReject = yield* Effect.result(
          service.acceptInvitation("invitee-user", answer(invitation)),
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
        const byId = yield* service.getTeamMemberById(added.id);

        return { engineering, design, added, listed, teamMembership, forMember, renamed, byId };
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
    // The service mints the team membership's id; the store reads it back.
    expect(result.teamMembership[0].id).toBe(result.added.id);
    expect(result.byId).toEqual(result.added);
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
    expect(MutableHashMap.size(teams)).toBe(0);
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
        // A role must be defined to be granted (#585), so the member gets
        // `auditor` while it exists, and keeps it once the definition is gone.
        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "auditor",
          permissions: [],
        });
        yield* service.addMember("owner-1", organization.id, "ghost-1", "auditor");
        yield* service.deleteOrgRole("owner-1", organization.id, "auditor");

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
    // Granting `superuser` takes an owner who holds `*:*` itself (#585).
    const config: OrganizationConfig = { roles: { ...defaultOrganizationRoles, owner: ["*:*"] } };
    const result = await runService(config, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "lead",
          permissions: ["team:*"],
        });
        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "superuser",
          permissions: ["*:*"],
        });
        yield* service.addMember("owner-1", organization.id, "lead-1", "lead");
        yield* service.addMember("owner-1", organization.id, "root-1", "superuser");

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

    expect(
      Arr.fromIterable(MutableHashMap.values(orgRoles)).map((orgRole) => orgRole.role),
    ).toEqual(["auditor"]);
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

    // A redefinition keeps the definition's id and creation time.
    expect(result.second.id).toBe(result.first.id);
    expect(result.second.createdAt).toBe(result.first.createdAt);
    expect(result.second.updatedAt).toBeGreaterThanOrEqual(result.first.updatedAt);
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0].permissions).toEqual(["team:create", "team:delete"]);
  });
});

/** An organization owned by `owner-1`, with `admin-1` as an admin. */
const withAdmin = <A, E>(
  config: OrganizationConfig,
  program: (
    service: typeof OrganizationService.Service,
    organization: Organization,
  ) => Effect.Effect<A, E, OrganizationStore | IdentifierStore>,
) =>
  runService(config, (service) =>
    Effect.gen(function* () {
      const organization = yield* service.createOrganization("owner-1", {
        name: "Acme",
        slug: "acme",
      });
      yield* service.addMember("owner-1", organization.id, "admin-1", "admin");
      return yield* program(service, organization);
    }),
  );

/** The `OrganizationError` message `effect` was refused with. */
const refusal = <A, R>(
  effect: Effect.Effect<A, OrganizationModule.OrganizationError | AuthError, R>,
) =>
  Effect.map(Effect.flip(effect), (error) => {
    expect(error._tag).toBe("OrganizationError");
    return error.message;
  });

describe("OrganizationService - no granting beyond your own permissions (#585)", () => {
  beforeEach(resetStores);

  it("refuses an admin promoting themselves, or anyone, to owner", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.addMember("owner-1", organization.id, "member-1", "member");
        const self = yield* refusal(
          service.updateMemberRole("admin-1", organization.id, "admin-1", "owner"),
        );
        const other = yield* refusal(
          service.updateMemberRole("admin-1", organization.id, "member-1", "owner"),
        );
        const full = yield* service.getFullOrganization(organization.id);
        return { self, other, full };
      }),
    );

    expect(result.self).toBe(
      "The 'owner' role carries 'organization:delete', which your role does not grant",
    );
    expect(result.other).toBe(result.self);
    expect(result.full.members.filter((member) => member.role === "owner")).toHaveLength(1);
  });

  it("refuses an admin adding or inviting someone as owner", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        const added = yield* refusal(
          service.addMember("admin-1", organization.id, "user-2", "owner"),
        );
        const invited = yield* refusal(
          service.inviteMember("admin-1", organization.id, {
            email: "second@example.com",
            role: "owner",
          }),
        );
        // At or below their own permissions, both still work.
        const peer = yield* service.addMember("admin-1", organization.id, "user-3", "admin");
        return { added, invited, peer };
      }),
    );

    expect(result.added).toContain("The 'owner' role carries");
    expect(result.invited).toContain("The 'owner' role carries");
    expect(MutableHashMap.size(invitations)).toBe(0);
    expect(result.peer.role).toBe("admin");
  });

  it("refuses an admin changing an owner's role", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.addMember("owner-1", organization.id, "owner-2", "owner");
        return yield* refusal(
          service.updateMemberRole("admin-1", organization.id, "owner-2", "member"),
        );
      }),
    );

    expect(result).toBe(
      "This member's 'owner' role carries 'organization:delete', which your role does not grant",
    );
  });

  it("refuses an admin reactivating a deactivated owner", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.addMember("owner-1", organization.id, "owner-2", "owner");
        yield* service.deactivateMember("owner-1", organization.id, "owner-2");
        const byAdmin = yield* refusal(
          service.reactivateMember("admin-1", organization.id, "owner-2"),
        );
        const byOwner = yield* service.reactivateMember("owner-1", organization.id, "owner-2");
        return { byAdmin, byOwner };
      }),
    );

    expect(result.byAdmin).toContain("This member's 'owner' role carries");
    expect(result.byOwner.role).toBe("owner");
  });

  it("applies to custom roles: no granting, changing or removing above your own permissions", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.upsertOrgRole("owner-1", organization.id, {
          role: "billing",
          permissions: ["role:manage"],
        });
        yield* service.addMember("owner-1", organization.id, "billing-1", "billing");
        const grant = yield* refusal(
          service.addMember("admin-1", organization.id, "user-2", "billing"),
        );
        const change = yield* refusal(
          service.updateMemberRole("admin-1", organization.id, "billing-1", "member"),
        );
        const deactivate = yield* refusal(
          service.deactivateMember("admin-1", organization.id, "billing-1"),
        );
        const remove = yield* refusal(
          service.removeMember("admin-1", organization.id, "billing-1"),
        );
        return { grant, change, deactivate, remove };
      }),
    );

    expect(result.grant).toBe(
      "The 'billing' role carries 'role:manage', which your role does not grant",
    );
    expect(result.change).toContain("This member's 'billing' role carries 'role:manage'");
    expect(result.deactivate).toBe(result.change);
    expect(result.remove).toBe(result.change);
  });

  it("matches wildcards: a `team:*` role takes a granter holding `team:*` or `*:*`", async () => {
    const config: OrganizationConfig = {
      roles: { ...defaultOrganizationRoles, owner: ["*:*"], lead: ["team:*"], root: ["*:*"] },
    };
    const result = await withAdmin(config, (service, organization) =>
      Effect.gen(function* () {
        // The admin holds every team:<action> by name, but not the wildcard.
        const byAdmin = yield* refusal(
          service.addMember("admin-1", organization.id, "lead-1", "lead"),
        );
        yield* service.addMember("owner-1", organization.id, "root-1", "root");
        const byRoot = yield* service.addMember("root-1", organization.id, "lead-1", "lead");
        return { byAdmin, byRoot };
      }),
    );

    expect(result.byAdmin).toBe("The 'lead' role carries 'team:*', which your role does not grant");
    expect(result.byRoot.role).toBe("lead");
  });

  it("rejects a role string nothing defines, on every write path", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.addMember("owner-1", organization.id, "member-1", "member");
        const add = yield* refusal(
          service.addMember("owner-1", organization.id, "user-2", "superadmin"),
        );
        const invite = yield* refusal(
          service.inviteMember("owner-1", organization.id, {
            email: "x@example.com",
            role: "superadmin",
          }),
        );
        const update = yield* refusal(
          service.updateMemberRole("owner-1", organization.id, "member-1", "superadmin"),
        );
        return { add, invite, update };
      }),
    );

    const undefinedRole = "Role 'superadmin' is not defined for this organization";
    expect(result).toEqual({ add: undefinedRole, invite: undefinedRole, update: undefinedRole });
  });

  it("checks the organization's default role when addMember names none", async () => {
    const result = await withAdmin({}, (service, organization) =>
      Effect.gen(function* () {
        yield* service.setDefaultRole("owner-1", organization.id, "owner");
        return yield* refusal(service.addMember("admin-1", organization.id, "user-2"));
      }),
    );

    expect(result).toContain("The 'owner' role carries");
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

  it("resends a pending invitation on the same row, with a fresh token and expiry", async () => {
    seedEmail("invitee-user", "new@acme.test");
    const result = await runService({ invitationExpiresIn: 60_000 }, (service) =>
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
        MutableHashMap.set(invitations, invitation.id, {
          ...invitation,
          expiresAt: (yield* Clock.currentTimeMillis) - 1_000,
        });

        const firstToken = tokenFor(invitation.id);
        const resent = yield* service.resendInvitation("owner-1", invitation.id);
        const listed = yield* service.listInvitations(organization.id);
        // Only the digest is stored, so the resend mints a new token: the
        // link delivered first stops working.
        const staleLink = yield* Effect.result(
          service.acceptInvitation("invitee-user", {
            invitationId: invitation.id,
            token: firstToken,
          }),
        );
        const accepted = yield* service.acceptInvitation("invitee-user", answer(invitation));
        return { invitation, resent, listed, firstToken, staleLink, accepted };
      }),
    );

    expect(result.resent.id).toBe(result.invitation.id);
    expect(result.resent.status).toBe("pending");
    expect(result.resent.expiresAt).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
    expect(result.listed).toHaveLength(1);
    const delivered = sentInvitations.map((sent) => sent.invitation);
    expect(delivered.map((entry) => entry.id)).toEqual([
      result.invitation.id,
      result.invitation.id,
    ]);
    // The resend re-dates from "now", which in a single tick can equal the
    // original expiry - what matters is that the aged row was pushed forward.
    expect(delivered[1].expiresAt).toBeGreaterThanOrEqual(delivered[0].expiresAt);
    expect(tokenFor(result.invitation.id)).not.toBe(result.firstToken);
    expect(result.resent.tokenHash).not.toBe(result.invitation.tokenHash);
    expect(result.staleLink._tag).toBe("Failure");
    expect(result.accepted.userId).toBe("invitee-user");
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
        yield* service.acceptInvitation("invitee-1", answer(accepted));

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

/** The invitee's stored email identifier. */
const inviteeEmail = () =>
  Arr.findFirst(
    Arr.fromIterable(MutableHashMap.values(identifierRecords)),
    (identifier) => identifier.userId === "invitee-user",
  );

/**
 * An organization with an admin invitation to `invitee@example.com`, whose
 * holder has a password and two sessions; runs `program` with them (each
 * session's stored id and its raw token).
 */
const withInvitation = <A, E>(
  verified: boolean,
  program: (
    service: typeof OrganizationService.Service,
    invitation: Invitation,
    sessions: readonly [IssuedSession, IssuedSession],
  ) => Effect.Effect<A, E, BaseServices | ProofServices>,
) => {
  seedEmail("invitee-user", "invitee@example.com", verified);
  MutableHashMap.set(userTable.passwordHashes, "invitee-user", "hash-set-at-sign-up");
  return runService({}, (service) =>
    Effect.gen(function* () {
      const organization = yield* service.createOrganization("owner-1", {
        name: "Acme",
        slug: "acme",
      });
      const invitation = yield* service.inviteMember("owner-1", organization.id, {
        email: "invitee@example.com",
        role: "admin",
      });
      const sessions = yield* SessionService;
      const first = yield* sessions.createSession("invitee-user");
      const second = yield* sessions.createSession("invitee-user");
      return yield* program(service, invitation, [
        { id: first.session.id, token: first.token },
        { id: second.session.id, token: second.token },
      ]);
    }),
  );
};

/** A session the fixture issued: its stored id (the token's digest) and its raw token. */
interface IssuedSession {
  readonly id: string;
  readonly token: string;
}

/** Whether each session's raw token still validates. */
const alive = (issued: ReadonlyArray<IssuedSession>) =>
  Effect.gen(function* () {
    const sessions = yield* SessionService;
    return yield* Effect.forEach(
      issued,
      ({ token }) =>
        Effect.match(sessions.validateSession(token), {
          onFailure: () => false,
          onSuccess: () => true,
        }),
      { concurrency: 1 },
    );
  });

describe("OrganizationService - invitation tokens (#586)", () => {
  beforeEach(resetStores);

  it("accepts and rejects nothing on the invitation id alone, or a wrong token", async () => {
    const result = await withInvitation(false, (service, invitation) =>
      Effect.gen(function* () {
        const forged = { invitationId: invitation.id, token: "forged" };
        const accept = yield* Effect.flip(service.acceptInvitation("invitee-user", forged));
        const empty = yield* Effect.flip(
          service.acceptInvitation("invitee-user", { invitationId: invitation.id, token: "" }),
        );
        const reject = yield* Effect.flip(service.rejectInvitation("invitee-user", forged));
        const full = yield* service.getFullOrganization(invitation.organizationId);
        return { accept, empty, reject, full };
      }),
    );

    expect(result.accept.message).toBe("Invitation not found");
    expect(result.empty.message).toBe("Invitation not found");
    expect(result.reject.message).toBe("Invitation not found");
    expect(result.full.members.map((member) => member.userId)).toEqual(["owner-1"]);
    expect(Option.getOrUndefined(inviteeEmail())?.verified).toBe(false);
    expect(Arr.fromIterable(MutableHashMap.values(invitations))[0].status).toBe("pending");
  });

  it("treats the token as the first proof of an unverified address", async () => {
    const result = await withInvitation(false, (service, invitation, [current, other]) =>
      Effect.gen(function* () {
        const member = yield* service.acceptInvitation("invitee-user", {
          ...answer(invitation),
          currentSessionId: current.id,
        });
        return { member, sessions: yield* alive([current, other]) };
      }),
    );

    expect(result.member.role).toBe("admin");
    expect(Option.getOrUndefined(inviteeEmail())?.verified).toBe(true);
    // Whoever signed up with the address unproven no longer holds the
    // account: the password is gone, and only the accepting session survives.
    expect(MutableHashMap.has(userTable.passwordHashes, "invitee-user")).toBe(false);
    expect(result.sessions).toEqual([true, false]);
  });

  it("revokes every session of an unverified address accepted without a current session", async () => {
    const result = await withInvitation(false, (service, invitation, issued) =>
      Effect.gen(function* () {
        yield* service.acceptInvitation("invitee-user", answer(invitation));
        return yield* alive(issued);
      }),
    );

    expect(result).toEqual([false, false]);
  });

  it("leaves a verified address's password and sessions alone", async () => {
    const result = await withInvitation(true, (service, invitation, issued) =>
      Effect.gen(function* () {
        yield* service.acceptInvitation("invitee-user", answer(invitation));
        return yield* alive(issued);
      }),
    );

    expect(result).toEqual([true, true]);
    expect(MutableHashMap.has(userTable.passwordHashes, "invitee-user")).toBe(true);
  });

  it("refuses to invite when no sendInvitationEmail would carry the token", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* OrganizationModule.make({});
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        return yield* Effect.flip(
          service.inviteMember("owner-1", organization.id, {
            email: "invitee@example.com",
            role: "member",
          }),
        );
      }).pipe(Effect.provide(Layer.merge(Layer.succeedContext(testContext), proofLayer()))),
    );

    expect(result.message).toBe("Invitations are not enabled: configure sendInvitationEmail");
    expect(MutableHashMap.size(invitations)).toBe(0);
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

  it("refuses a second claim by the same organization only, revealing no other tenant's claim (#598)", async () => {
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
        // Another tenant's pending claim neither blocks this one nor shows.
        const otherOrganization = yield* service.addDomain("owner-2", globex.id, {
          domain: "SHARED.test",
        });
        const acmeDomains = yield* service.listDomains("owner-1", acme.id);
        const globexDomains = yield* service.listDomains("owner-2", globex.id);

        return { first, sameOrganization, otherOrganization, acmeDomains, globexDomains };
      }),
    );

    expect(result.first.verificationState).toBe("pending");
    assert(Result.isFailure(result.sameOrganization));
    expect(result.sameOrganization.failure.message).toBe(
      "This organization has already claimed that domain",
    );
    expect(result.otherOrganization.domain).toBe("shared.test");
    expect(result.otherOrganization.verificationState).toBe("pending");
    // Each claim carries its own token: one tenant's record proves nothing for another.
    expect(result.otherOrganization.verificationToken).not.toBe(result.first.verificationToken);
    expect(result.acmeDomains.map((domain) => domain.id)).toEqual([result.first.id]);
    expect(result.globexDomains.map((domain) => domain.id)).toEqual([result.otherOrganization.id]);
  });

  it("lets only the organization that proves DNS control verify a domain several claim (#598)", async () => {
    const claims = await runService({}, (service) =>
      Effect.gen(function* () {
        const squatter = yield* service.createOrganization("owner-1", {
          name: "Squatter",
          slug: "squatter",
        });
        const owner = yield* service.createOrganization("owner-2", {
          name: "Owner",
          slug: "owner",
        });
        const squat = yield* service.addDomain("owner-1", squatter.id, { domain: "acme.test" });
        const real = yield* service.addDomain("owner-2", owner.id, { domain: "acme.test" });
        return { squatter, owner, squat, real };
      }),
    );
    const realToken = claims.real.verificationToken;
    const squatToken = claims.squat.verificationToken;
    assert(realToken !== undefined && squatToken !== undefined);

    // The squatter cannot verify with the real owner's record...
    const squatCheck = await runServiceWithVerifier(
      {},
      stubDomainVerifier([{ domain: "acme.test", token: realToken }]),
      (service) => service.verifyDomain("owner-1", claims.squatter.id, claims.squat.id),
    );
    expect(squatCheck.verificationState).toBe("failed");

    // ...and its pending claim does not stop the real owner from verifying.
    const realCheck = await runServiceWithVerifier(
      {},
      stubDomainVerifier([{ domain: "acme.test", token: realToken }]),
      (service) => service.verifyDomain("owner-2", claims.owner.id, claims.real.id),
    );
    expect(realCheck.verificationState).toBe("verified");

    // A later DNS proof elsewhere cannot take a second verified claim on the domain.
    const second = await runServiceWithVerifier(
      {},
      stubDomainVerifier([{ domain: "acme.test", token: squatToken }]),
      (service) =>
        Effect.result(service.verifyDomain("owner-1", claims.squatter.id, claims.squat.id)),
    );
    assert(Result.isFailure(second));
    expect(second.failure.message).toBe("That domain is already verified for another organization");
    const jit = await runService({}, (service) =>
      service.updateOrganization("owner-2", claims.owner.id, { jitProvisioning: true }).pipe(
        Effect.andThen(
          service.updateOrganization("owner-1", claims.squatter.id, {
            jitProvisioning: true,
          }),
        ),
        Effect.andThen(service.provisionJitMembership("user-1", "new@acme.test")),
      ),
    );
    expect(jit?.organizationId).toBe(claims.owner.id);
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

  it("never lets an organization owner self-attest a domain (#598)", async () => {
    // What an untyped caller (or a caller built against the old input) sends.
    const manualRequest = { domain: "victim.test", verificationStrategy: "manual" };
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Attacker",
          slug: "attacker",
        });
        yield* service.updateOrganization("owner-1", organization.id, { jitProvisioning: true });

        // The requested strategy is ignored: the claim is a DNS claim.
        const claim = yield* service.addDomain("owner-1", organization.id, manualRequest);
        // `domain:manage` is not the proof: with no DNS check there is no verification.
        const verify = yield* Effect.result(
          service.verifyDomain("owner-1", organization.id, claim.id),
        );
        const stored = yield* service.getDomainById(claim.id);
        const jit = yield* service.provisionJitMembership("victim-1", "ceo@victim.test");
        return { claim, verify, stored, jit };
      }),
    );

    expect(result.claim.verificationStrategy).toBe("dns");
    expect(result.claim.verificationToken).toBeTypeOf("string");
    assert(Result.isFailure(result.verify));
    expect(result.verify.failure.message).toBe(
      "DNS domain verification is not available: provide a DomainVerifier layer",
    );
    expect(result.stored?.verificationState).toBe("pending");
    expect(result.jit).toBeNull();
  });

  it("refuses to verify a manual claim on the organization's own say-so (#598)", async () => {
    const result = await runServiceWithVerifier({}, stubDomainVerifier([]), (service) =>
      Effect.gen(function* () {
        const organization = yield* service.createOrganization("owner-1", {
          name: "Acme",
          slug: "acme",
        });
        // A pending manual claim stored before #598.
        const legacy: OrganizationDomain = {
          id: "dom-legacy",
          organizationId: organization.id,
          domain: "acme.test",
          verificationState: "pending",
          verificationStrategy: "manual",
          createdAt: 1,
        };
        MutableHashMap.set(domainRecords, legacy.id, legacy);

        const verify = yield* Effect.result(
          service.verifyDomain("owner-1", organization.id, legacy.id),
        );
        const stored = yield* service.getDomainById(legacy.id);
        return { verify, stored };
      }),
    );

    assert(Result.isFailure(result.verify));
    expect(result.verify.failure._tag).toBe("OrganizationError");
    expect(result.stored?.verificationState).toBe("pending");
  });

  it("lets the operator attest a domain server-side, creating or attesting the claim (#598)", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const pending = yield* service.addDomain("owner-1", acme.id, { domain: "acme.test" });

        // An existing pending DNS claim is attested in place.
        const attested = yield* service.attestDomain(acme.id, " ACME.test ");
        const again = yield* service.attestDomain(acme.id, "acme.test");
        // With no claim yet, the attestation creates one.
        const created = yield* service.attestDomain(acme.id, "acme-corp.test");
        const listed = yield* service.listDomains("owner-1", acme.id);
        return { pending, attested, again, created, listed };
      }),
    );

    expect(result.attested).toMatchObject({
      id: result.pending.id,
      domain: "acme.test",
      verificationState: "verified",
      verificationStrategy: "manual",
      createdAt: result.pending.createdAt,
    });
    expect(result.attested.verificationToken).toBeUndefined();
    expect(result.attested.verifiedAt).toBeTypeOf("number");
    // Idempotent: a verified claim is answered unchanged.
    expect(result.again).toStrictEqual(result.attested);
    expect(result.created).toMatchObject({
      domain: "acme-corp.test",
      verificationState: "verified",
      verificationStrategy: "manual",
    });
    expect(result.listed).toHaveLength(2);
  });

  it("refuses an attestation for an unknown organization, a bad domain or another tenant's verified domain", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const globex = yield* service.createOrganization("owner-2", {
          name: "Globex",
          slug: "globex",
        });
        yield* service.attestDomain(acme.id, "acme.test");

        const unknown = yield* Effect.result(service.attestDomain("org-nope", "x.test"));
        const invalid = yield* Effect.result(service.attestDomain(acme.id, "not-a-domain"));
        const taken = yield* Effect.result(service.attestDomain(globex.id, "acme.test"));
        return { unknown, invalid, taken };
      }),
    );

    expect(result.unknown._tag).toBe("Failure");
    expect(result.invalid._tag).toBe("Failure");
    assert(Result.isFailure(result.taken));
    expect(result.taken.failure.message).toBe(
      "That domain is already verified for another organization",
    );
  });

  it("records who attested a claim, and keeps the first attester on a repeat (#680)", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const pending = yield* service.addDomain("owner-1", acme.id, { domain: "acme.test" });
        const attested = yield* service.attestDomain(acme.id, "acme.test", {
          attestedBy: "ops-1",
        });
        const again = yield* service.attestDomain(acme.id, "acme.test", { attestedBy: "ops-2" });
        const anonymous = yield* service.attestDomain(acme.id, "acme-corp.test");
        const stored = yield* service.getDomainById(pending.id);
        return { pending, attested, again, anonymous, stored };
      }),
    );

    // A tenant's DNS claim never names an attester.
    expect(result.pending.attestedBy).toBeUndefined();
    expect(result.attested).toMatchObject({ id: result.pending.id, attestedBy: "ops-1" });
    expect(result.attested.verifiedAt).toBeTypeOf("number");
    expect(result.stored?.attestedBy).toBe("ops-1");
    // A claim already verified is answered unchanged: the record of who
    // attested it is not overwritten.
    expect(result.again).toStrictEqual(result.attested);
    expect("attestedBy" in result.anonymous).toBe(false);
  });

  it("lets the operator release an organization's claim in any state (#680)", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const globex = yield* service.createOrganization("owner-2", {
          name: "Globex",
          slug: "globex",
        });
        const pending = yield* service.addDomain("owner-1", acme.id, { domain: "pending.test" });
        const verified = yield* service.attestDomain(acme.id, "acme.test", {
          attestedBy: "ops-1",
        });
        // Globex holds its own pending claim on the domain Acme holds verified.
        const globexClaim = yield* service.addDomain("owner-2", globex.id, {
          domain: "acme.test",
        });

        const releasedPending = yield* service.releaseDomain(acme.id, " PENDING.test ");
        // The dispute: Acme's verified claim blocks Globex's attestation until
        // the operator releases it.
        const blocked = yield* Effect.result(service.attestDomain(globex.id, "acme.test"));
        const releasedVerified = yield* service.releaseDomain(acme.id, "acme.test");
        const handedOver = yield* service.attestDomain(globex.id, "acme.test", {
          attestedBy: "ops-1",
        });

        const acmeDomains = yield* service.listDomains("owner-1", acme.id);
        return {
          pending,
          verified,
          globexClaim,
          releasedPending,
          blocked,
          releasedVerified,
          handedOver,
          acmeDomains,
        };
      }),
    );

    expect(result.releasedPending).toStrictEqual(result.pending);
    assert(Result.isFailure(result.blocked));
    expect(result.blocked.failure.message).toBe(
      "That domain is already verified for another organization",
    );
    expect(result.releasedVerified).toStrictEqual(result.verified);
    expect(result.acmeDomains).toEqual([]);
    // Globex's own pending claim is the one attested, in place.
    expect(result.handedOver).toMatchObject({
      id: result.globexClaim.id,
      verificationState: "verified",
      attestedBy: "ops-1",
    });
  });

  it("refuses a release for an unknown organization, a bad domain or a domain it holds no claim on (#680)", async () => {
    const result = await runService({}, (service) =>
      Effect.gen(function* () {
        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const globex = yield* service.createOrganization("owner-2", {
          name: "Globex",
          slug: "globex",
        });
        yield* service.attestDomain(acme.id, "acme.test");

        const unknown = yield* Effect.result(service.releaseDomain("org-nope", "acme.test"));
        const invalid = yield* Effect.result(service.releaseDomain(acme.id, "not-a-domain"));
        // Another organization's claim is never released through this one.
        const unclaimed = yield* Effect.result(service.releaseDomain(globex.id, "acme.test"));
        const acmeDomains = yield* service.listDomains("owner-1", acme.id);
        return { unknown, invalid, unclaimed, acmeDomains };
      }),
    );

    assert(Result.isFailure(result.unknown));
    expect(result.unknown.failure._tag).toBe("OrganizationError");
    assert(Result.isFailure(result.invalid));
    expect(result.invalid.failure._tag).toBe("OrganizationError");
    assert(Result.isFailure(result.unclaimed));
    expect(result.unclaimed.failure.message).toBe(
      "That organization holds no claim on that domain",
    );
    expect(result.acmeDomains).toHaveLength(1);
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
        const attest = yield* Effect.result(service.attestDomain(organization.id, "acme.test"));
        const release = yield* Effect.result(service.releaseDomain(organization.id, "acme.test"));
        // JIT is a no-op rather than a failure: it runs on a sign-in path.
        const jit = yield* service.provisionJitMembership("user-1", "user@acme.test");
        return { list, add, attest, release, jit };
      }),
    );

    expect(result.list._tag).toBe("Failure");
    expect(result.add._tag).toBe("Failure");
    expect(result.attest._tag).toBe("Failure");
    expect(result.release._tag).toBe("Failure");
    expect(result.jit).toBeNull();
  });
});

describe("OrganizationService - JIT provisioning", () => {
  beforeEach(resetStores);

  /** An organization with an operator-attested domain, JIT off until a test turns it on. */
  const withVerifiedDomain = (service: typeof OrganizationService.Service) =>
    Effect.gen(function* () {
      const organization = yield* service.createOrganization("owner-1", {
        name: "Acme",
        slug: "acme",
      });
      yield* service.attestDomain(organization.id, "acme.test");
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
        yield* service.addDomain("owner-1", organization.id, { domain: "acme.test" });
        yield* service.updateOrganization("owner-1", organization.id, { jitProvisioning: true });

        const pending = yield* service.provisionJitMembership("user-1", "new@acme.test");
        const members = yield* service.getFullOrganization(organization.id);
        return { pending, members };
      }),
    );

    expect(result.pending).toBeNull();
    expect(result.members.members).toHaveLength(1);
  });

  it("follows a DNS-verified claim, and not another tenant's pending claim on it (#598)", async () => {
    const claims = await runService({}, (service) =>
      Effect.gen(function* () {
        const squatter = yield* service.createOrganization("owner-2", {
          name: "Squatter",
          slug: "squatter",
        });
        yield* service.addDomain("owner-2", squatter.id, { domain: "acme.test" });
        yield* service.updateOrganization("owner-2", squatter.id, { jitProvisioning: true });
        const beforeProof = yield* service.provisionJitMembership("user-0", "a@acme.test");

        const acme = yield* service.createOrganization("owner-1", { name: "Acme", slug: "acme" });
        const claim = yield* service.addDomain("owner-1", acme.id, { domain: "acme.test" });
        yield* service.updateOrganization("owner-1", acme.id, { jitProvisioning: true });
        return { acme, claim, beforeProof };
      }),
    );
    expect(claims.beforeProof).toBeNull();
    const token = claims.claim.verificationToken;
    assert(token !== undefined);

    const provisioned = await runServiceWithVerifier(
      {},
      stubDomainVerifier([{ domain: "acme.test", token }]),
      (service) =>
        service
          .verifyDomain("owner-1", claims.acme.id, claims.claim.id)
          .pipe(Effect.andThen(service.provisionJitMembership("user-1", "new@acme.test"))),
    );
    expect(provisioned?.organizationId).toBe(claims.acme.id);
  });
});

// The membership half of the store contract, `getMemberById` included, over
// this file's in-memory store; and a store that loses the id-keyed lookup,
// which the suite must fail.
describe("OrganizationStore conformance", () => {
  const suite = Testing.organizationStoreConformance();
  it.each(suite.cases)("$name", async ({ run }) => {
    await expect(
      Effect.runPromise(run.pipe(Effect.provideService(OrganizationStore, organizationStore))),
    ).resolves.toBeUndefined();
  });

  it.each(["getMemberById", "getTeamMemberById", "getOrgRoleById"] as const)(
    "fails a store whose %s misses, in every case that reads it",
    async (lookup) => {
      const forgetful = { ...organizationStore, [lookup]: () => Effect.succeed(null) };
      const reading = suite.cases.filter((testCase) => testCase.name.includes(lookup));
      expect(reading.length).toBeGreaterThan(0);
      const exits = await Promise.all(
        reading.map((testCase) =>
          Effect.runPromiseExit(
            testCase.run.pipe(Effect.provideService(OrganizationStore, forgetful)),
          ),
        ),
      );
      expect(exits.filter(Exit.isFailure)).toHaveLength(reading.length);
    },
  );
});
