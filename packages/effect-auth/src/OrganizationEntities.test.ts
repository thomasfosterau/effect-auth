import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { OrganizationStore, type Member, type Organization, type Team } from "./Organization.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";
import * as Authorizer from "./Authorizer.ts";
import * as OrganizationEntities from "./OrganizationEntities.ts";

const ACME = "org-acme";
const GLOBEX = "org-globex";

const organizations: ReadonlyArray<Organization> = [
  { id: ACME, name: "Acme", slug: "acme", metadata: {}, createdAt: 1 },
  { id: GLOBEX, name: "Globex", slug: "globex", metadata: {}, createdAt: 2 },
];

const members: ReadonlyArray<Member> = [
  { id: "m1", organizationId: ACME, userId: "alice", role: "admin", createdAt: 1 },
  { id: "m2", organizationId: GLOBEX, userId: "alice", role: "member", createdAt: 1 },
  { id: "m3", organizationId: ACME, userId: "bob", role: "member", createdAt: 1 },
  // Deactivated: the row is still there, the authority is not.
  {
    id: "m4",
    organizationId: GLOBEX,
    userId: "carol",
    role: "member",
    status: "inactive",
    previousRole: "admin",
    createdAt: 1,
  },
];

const teams: ReadonlyArray<Team> = [
  { id: "team-eng", organizationId: ACME, name: "Engineering", createdAt: 1, updatedAt: 1 },
  { id: "team-ops", organizationId: GLOBEX, name: "Ops", createdAt: 1, updatedAt: 1 },
];

const teamMemberships: ReadonlyArray<{ teamId: string; userId: string }> = [
  { teamId: "team-eng", userId: "alice" },
  { teamId: "team-ops", userId: "alice" },
];

/** The read-only slice of `OrganizationStore` the resolver actually calls. */
const store = {
  getOrganizationById: (organizationId: string) =>
    Effect.succeed(organizations.find((o) => o.id === organizationId) ?? null),
  listMembersByUser: (userId: string) => Effect.succeed(members.filter((m) => m.userId === userId)),
  getTeam: (teamId: string) => Effect.succeed(teams.find((t) => t.id === teamId) ?? null),
  listTeamsForMember: (organizationId: string, userId: string) =>
    Effect.succeed(
      teamMemberships
        .filter((tm) => tm.userId === userId)
        .map((tm) => teams.find((t) => t.id === tm.teamId))
        .filter((t): t is Team => t !== undefined && t.organizationId === organizationId),
    ),
  // Never touched by the entity projection:
  createOrganization: () => Effect.die("unused"),
  getOrganizationBySlug: () => Effect.die("unused"),
  updateOrganization: () => Effect.die("unused"),
  deleteOrganization: () => Effect.die("unused"),
  createMember: () => Effect.die("unused"),
  getMember: () => Effect.die("unused"),
  updateMember: () => Effect.die("unused"),
  deleteMember: () => Effect.die("unused"),
  listMembersByOrganization: () => Effect.die("unused"),
  countMembersByOrganization: () => Effect.die("unused"),
  createInvitation: () => Effect.die("unused"),
  getInvitation: () => Effect.die("unused"),
  updateInvitation: () => Effect.die("unused"),
  listInvitationsByOrganization: () => Effect.die("unused"),
  listInvitationsByEmail: () => Effect.die("unused"),
  createTeam: () => Effect.die("unused"),
  updateTeam: () => Effect.die("unused"),
  deleteTeam: () => Effect.die("unused"),
  listTeams: () => Effect.die("unused"),
  addTeamMember: () => Effect.die("unused"),
  removeTeamMember: () => Effect.die("unused"),
  listTeamMembers: () => Effect.die("unused"),
  upsertOrgRole: () => Effect.die("unused"),
  getOrgRole: () => Effect.die("unused"),
  listOrgRoles: () => Effect.die("unused"),
  deleteOrgRole: () => Effect.die("unused"),
} satisfies typeof OrganizationStore.Service;

const resolver = OrganizationEntities.organizationEntityResolver(store);

const resolve = (refs: ReadonlyArray<Entity.EntityRef>) =>
  Effect.runPromise(resolver.resolve(refs));

describe("organizationEntityResolver", () => {
  it("gives a user org, role and team parents, with the ancestor closure", async () => {
    const resolved = await resolve([OrganizationEntities.userRef("alice")]);
    const slice = Entity.slice(resolved);

    const alice = Entity.getEntity(slice, OrganizationEntities.userRef("alice"));
    expect(alice?.parents).toContainEqual(OrganizationEntities.organizationRef(ACME));
    expect(alice?.parents).toContainEqual(OrganizationEntities.roleRef(ACME, "admin"));
    expect(alice?.parents).toContainEqual(OrganizationEntities.roleRef(GLOBEX, "member"));
    expect(alice?.parents).toContainEqual(OrganizationEntities.teamRef("team-eng"));
    expect(alice?.parents).toContainEqual(OrganizationEntities.teamRef("team-ops"));

    // Ancestors came along: both organizations and both teams are in the slice,
    // so hierarchy checks decide from it alone.
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.userRef("alice"),
        OrganizationEntities.roleRef(ACME, "admin"),
      ),
    ).toBe(true);
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.userRef("alice"),
        OrganizationEntities.organizationRef(GLOBEX),
      ),
    ).toBe(true);
    // Reached transitively through Team::"team-eng" → Org::"org-acme".
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.teamRef("team-eng"),
        OrganizationEntities.organizationRef(ACME),
      ),
    ).toBe(true);
    // Roles are namespaced per organization.
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.userRef("alice"),
        OrganizationEntities.roleRef(GLOBEX, "admin"),
      ),
    ).toBe(false);
  });

  it("projects nothing for a deactivated membership", async () => {
    const resolved = await resolve([OrganizationEntities.userRef("carol")]);
    const slice = Entity.slice(resolved);

    const carol = Entity.getEntity(slice, OrganizationEntities.userRef("carol"));
    expect(carol?.parents).toEqual([]);
    // Neither the parked role nor the one the row currently carries.
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.userRef("carol"),
        OrganizationEntities.roleRef(GLOBEX, "admin"),
      ),
    ).toBe(false);
    expect(
      Entity.entityIn(
        slice,
        OrganizationEntities.userRef("carol"),
        OrganizationEntities.organizationRef(GLOBEX),
      ),
    ).toBe(false);
  });

  it("projects teams and organizations with their attributes", async () => {
    const resolved = await resolve([
      OrganizationEntities.teamRef("team-eng"),
      OrganizationEntities.organizationRef(GLOBEX),
    ]);
    const slice = Entity.slice(resolved);

    const team = Entity.getEntity(slice, OrganizationEntities.teamRef("team-eng"));
    expect(team?.attributes).toEqual({ name: "Engineering", organizationId: ACME });
    expect(team?.parents).toEqual([OrganizationEntities.organizationRef(ACME)]);

    const acme = Entity.getEntity(slice, OrganizationEntities.organizationRef(ACME));
    expect(acme?.attributes).toEqual({ name: "Acme", slug: "acme" });
    expect(acme?.parents).toEqual([]);

    const globex = Entity.getEntity(slice, OrganizationEntities.organizationRef(GLOBEX));
    expect(globex?.attributes).toEqual({ name: "Globex", slug: "globex" });
  });

  it("omits references it does not recognize and unknown records", async () => {
    const resolved = await resolve([
      Entity.ref("Document", "doc-1"),
      OrganizationEntities.roleRef(ACME, "admin"),
      OrganizationEntities.organizationRef("no-such-org"),
      OrganizationEntities.teamRef("no-such-team"),
    ]);
    expect(resolved).toEqual([]);
  });

  it("resolves a user with no memberships to a parentless entity", async () => {
    const resolved = await resolve([OrganizationEntities.userRef("nobody")]);
    expect(resolved).toEqual([Entity.entity(OrganizationEntities.userRef("nobody"))]);
  });
});

describe("organization entities in policies", () => {
  const orgAdminMayManage = Policy.role(OrganizationEntities.orgRoleId(ACME, "admin"), {
    resource: Policy.inScope(OrganizationEntities.organizationRef(ACME)),
  });

  it("decides Policy.role over the resolved slice (decidePure)", async () => {
    const resolved = await resolve([
      OrganizationEntities.userRef("alice"),
      OrganizationEntities.userRef("bob"),
      OrganizationEntities.teamRef("team-eng"),
    ]);
    const slice = Entity.slice(resolved);
    const action = Entity.ref("Action", "team:update");

    // The Acme admin may act on a team *inside* Acme (resource in Org::acme).
    const allowed = Policy.decidePure(
      [orgAdminMayManage],
      Policy.request({
        principal: OrganizationEntities.userRef("alice"),
        action,
        resource: OrganizationEntities.teamRef("team-eng"),
      }),
      slice,
    );
    expect(allowed.allowed).toBe(true);
    expect(allowed.reason).toBe("permit");

    // A plain Acme member is not in Role::"org:org-acme:admin".
    const deniedPrincipal = Policy.decidePure(
      [orgAdminMayManage],
      Policy.request({
        principal: OrganizationEntities.userRef("bob"),
        action,
        resource: OrganizationEntities.teamRef("team-eng"),
      }),
      slice,
    );
    expect(deniedPrincipal.allowed).toBe(false);
    expect(deniedPrincipal.reason).toBe("default-deny");

    // Alice is an admin in Acme only: a Globex team is out of scope.
    const outOfScope = Policy.decidePure(
      [orgAdminMayManage],
      Policy.request({
        principal: OrganizationEntities.userRef("alice"),
        action,
        resource: OrganizationEntities.teamRef("team-ops"),
      }),
      slice,
    );
    expect(outOfScope.allowed).toBe(false);
  });

  it("works end to end through the Authorizer layer", async () => {
    const resolverLayer = OrganizationEntities.layer.pipe(
      Layer.provide(Layer.succeed(OrganizationStore)(store)),
    );
    const authorizerLayer = Authorizer.Authorizer.layer({
      policies: [orgAdminMayManage],
    }).pipe(Layer.provide(resolverLayer));

    const check = (userId: string, resource: Entity.EntityRef) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const authorizer = yield* Authorizer.Authorizer;
          return yield* authorizer.check({ action: "team:update", resource });
        }).pipe(
          Authorizer.CurrentPrincipal.provide(OrganizationEntities.userRef(userId)),
          Effect.provide(authorizerLayer),
        ),
      );

    expect(await check("alice", OrganizationEntities.teamRef("team-eng"))).toBe(true);
    expect(await check("alice", OrganizationEntities.organizationRef(ACME))).toBe(true);
    expect(await check("bob", OrganizationEntities.teamRef("team-eng"))).toBe(false);
    expect(await check("alice", OrganizationEntities.teamRef("team-ops"))).toBe(false);
  });
});
