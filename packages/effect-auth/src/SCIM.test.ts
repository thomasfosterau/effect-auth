import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import { EmailPasswordService } from "./email/EmailPassword.ts";
import { EmailVerificationService } from "./email/EmailVerification.ts";
import { Hooks } from "./Hooks.ts";
import { type AuthServices } from "./http/HttpServer.ts";
import * as HTTPServer from "./http/HttpServer.ts";
import {
  IdentifierStore,
  memoryIdentifierStore,
  makeIdentifier,
  type Identifier,
} from "./Identifier.ts";
import { OrganizationStore, type Member, type Team, type TeamMember } from "./Organization.ts";
import { PasswordHasher } from "./password/Password.ts";
import { PasswordResetService } from "./password/PasswordReset.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as SCIM from "./SCIM.ts";
import {
  memorySCIMConnectionStore,
  SCIMConnectionStore,
  SCIMDeactivatedPlugin,
  SCIMError,
  SCIMService,
  SCIMUserStore,
  SCIM_DEACTIVATED_ATTRIBUTE,
  SCIM_EXTERNAL_ID_ATTRIBUTE,
  type SCIMConnection,
} from "./SCIM.ts";
import { SessionService } from "./session/SessionService.ts";
import { UserStore } from "./session/UserStore.ts";
import { UserService, UserServiceStore } from "./User.ts";
import type * as Types from "./Types.ts";

const ORG_A = "org-a";
const ORG_B = "org-b";

/**
 * In-memory stand-ins for everything `SCIMService` touches.
 *
 * The organization store implements only the methods SCIM reaches for —
 * members and teams — and dies loudly on the rest, so a test that accidentally
 * exercises an unmapped path fails instead of quietly succeeding.
 */
const makeStores = () => {
  const usersById = new Map<string, Types.User>();
  const identifierRecords = new Map<string, Identifier>();
  const identifiers = memoryIdentifierStore(identifierRecords);
  const connectionRecords = new Map<string, SCIMConnection>();
  const members: Member[] = [];
  const teams = new Map<string, Team>();
  const teamMembers: TeamMember[] = [];
  const sessions = new Map<string, Types.Session>();
  let userSeq = 0;
  let teamSeq = 0;

  const userStore: typeof SCIMUserStore.Service = {
    create: (input) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: input.attributes ?? {},
        };
        usersById.set(user.id, user);
        return user;
      }),
    get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
    update: (user) => Effect.sync(() => (usersById.set(user.id, user), user)),
  };

  const coreUserStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: () => Effect.succeed(null),
  };

  const userServiceStore: typeof UserServiceStore.Service = {
    get: coreUserStore.get,
    update: userStore.update,
    delete: (userId) => Effect.sync(() => void usersById.delete(userId)),
  };

  /** A session manager just real enough to observe revocation. */
  const sessionManager: typeof SessionService.Service = {
    createSession: (userId) =>
      Effect.sync(() => {
        const now = new Date();
        const session: Types.Session = {
          id: `s-${userId}-${sessions.size}`,
          userId,
          expiresAt: new Date(Date.now() + 3600_000),
          createdAt: now,
          lastActivityAt: now,
          attributes: {},
        };
        sessions.set(session.id, session);
        return session;
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
    invalidateUserSessions: (userId) =>
      Effect.sync(() => {
        for (const [id, session] of sessions) {
          if (session.userId === userId) sessions.delete(id);
        }
      }),
    listSessions: (userId) =>
      Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const unused = () => Effect.die("unused") as never;

  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    listMembersByOrganization: (organizationId: string) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId)),
    createTeam: (t: Team) => Effect.sync(() => (teams.set(t.id, t), t)),
    getTeam: (teamId: string) => Effect.succeed(teams.get(teamId) ?? null),
    updateTeam: (t: Team) =>
      Effect.sync(() => {
        if (!teams.has(t.id)) return null;
        teams.set(t.id, t);
        return t;
      }),
    deleteTeam: (teamId: string) =>
      Effect.sync(() => {
        teams.delete(teamId);
        for (let i = teamMembers.length - 1; i >= 0; i--) {
          if (teamMembers[i]!.teamId === teamId) teamMembers.splice(i, 1);
        }
      }),
    listTeams: (organizationId: string) =>
      Effect.succeed([...teams.values()].filter((t) => t.organizationId === organizationId)),
    addTeamMember: (teamId: string, userId: string) =>
      Effect.sync(() => {
        const teamMember: TeamMember = { teamId, userId, createdAt: Date.now() };
        teamMembers.push(teamMember);
        return teamMember;
      }),
    removeTeamMember: (teamId: string, userId: string) =>
      Effect.sync(() => {
        const i = teamMembers.findIndex((m) => m.teamId === teamId && m.userId === userId);
        if (i >= 0) teamMembers.splice(i, 1);
      }),
    listTeamMembers: (teamId: string) =>
      Effect.succeed(teamMembers.filter((m) => m.teamId === teamId)),
    // Never reached by SCIM.
    createOrganization: unused,
    getOrganizationById: unused,
    getOrganizationBySlug: unused,
    updateOrganization: unused,
    deleteOrganization: unused,
    updateMember: unused,
    deleteMember: unused,
    listMembersByUser: unused,
    countMembersByOrganization: unused,
    createInvitation: unused,
    getInvitation: unused,
    updateInvitation: unused,
    listInvitationsByOrganization: unused,
    listInvitationsByEmail: unused,
    listTeamsForMember: unused,
    upsertOrgRole: unused,
    getOrgRole: unused,
    listOrgRoles: unused,
    deleteOrgRole: unused,
  };

  /** Seed a user that SCIM did not create (e.g. someone who signed up directly). */
  const seedUser = (organizationId: string, email: string): string => {
    const now = new Date();
    const user: Types.User = {
      id: `u${++userSeq}`,
      createdAt: now,
      updatedAt: now,
      attributes: {},
    };
    usersById.set(user.id, user);
    const identifier = makeIdentifier({
      userId: user.id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
      now,
    });
    identifierRecords.set(identifier.id, identifier);
    members.push({
      id: `m${members.length + 1}`,
      organizationId,
      userId: user.id,
      role: "member",
      createdAt: Date.now(),
    });
    return user.id;
  };

  const seedTeam = (organizationId: string, name: string): Team => {
    const now = Date.now();
    const team: Team = {
      id: `t${++teamSeq}`,
      organizationId,
      name,
      createdAt: now,
      updatedAt: now,
    };
    teams.set(team.id, team);
    return team;
  };

  const layer = Layer.mergeAll(
    Layer.succeed(SCIMConnectionStore)(memorySCIMConnectionStore(connectionRecords)),
    Layer.succeed(SCIMUserStore)(userStore),
    Layer.succeed(IdentifierStore)(identifiers),
    Layer.succeed(UserStore)(coreUserStore),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(OrganizationStore)(orgStore as never),
    Layer.succeed(SessionService)(sessionManager),
    Hooks.Default,
    PlatformCrypto.layer,
  );

  return {
    layer,
    usersById,
    identifiers,
    identifierRecords,
    members,
    teams,
    teamMembers,
    sessions,
    sessionManager,
    connectionRecords,
    seedUser,
    seedTeam,
  };
};

/** Build the service plus a connection for each of two organizations. */
const makeFixture = async (config: SCIM.SCIMConfig = {}) => {
  const stores = makeStores();
  const service = await Effect.runPromise(SCIM.make(config).pipe(Effect.provide(stores.layer)));
  const run = <A, E>(effect: Effect.Effect<A, E, never>): Promise<A> => Effect.runPromise(effect);
  const a = await run(service.createConnection(ORG_A));
  const b = await run(service.createConnection(ORG_B));
  return { ...stores, service, run, a, b };
};

const ADA = { userName: "ada@acme.test", displayName: "Ada Lovelace", externalId: "okta-1" };

describe("SCIMService — connections", () => {
  it("mints a token once, resolves it, and stops resolving it after a revoke", async () => {
    const fx = await makeFixture();

    // The raw token is never persisted — only its digest.
    const stored = [...fx.connectionRecords.values()];
    expect(stored.some((c) => c.tokenHash === fx.a.token)).toBe(false);
    expect(fx.a.token.length).toBeGreaterThan(20);

    const resolved = await fx.run(fx.service.authenticate(fx.a.token));
    expect(resolved.id).toBe(fx.a.connection.id);
    expect(resolved.organizationId).toBe(ORG_A);

    // Using a connection stamps it, so an operator can spot a dead integration.
    expect(fx.connectionRecords.get(fx.a.connection.id)?.lastUsedAt).toBeTypeOf("number");

    await fx.run(fx.service.revokeConnection(fx.a.connection.id));
    const err = await fx.run(Effect.flip(fx.service.authenticate(fx.a.token)));
    expect((err as SCIMError).status).toBe(401);
  });

  it("answers 401 the same way for an empty and an unknown token", async () => {
    const fx = await makeFixture();
    const empty = await fx.run(Effect.flip(fx.service.authenticate("")));
    const unknown = await fx.run(Effect.flip(fx.service.authenticate("not-a-token")));
    expect((empty as SCIMError).status).toBe(401);
    expect((unknown as SCIMError).status).toBe(401);
    expect((empty as SCIMError).message).toBe((unknown as SCIMError).message);
  });

  it("lists an organization's connections without leaking other tenants'", async () => {
    const fx = await makeFixture();
    const listed = await fx.run(fx.service.listConnections(ORG_A));
    expect(listed.map((c) => c.id)).toEqual([fx.a.connection.id]);
  });
});

describe("SCIMService — users", () => {
  it("provisions a user with a verified email and an org membership", async () => {
    const fx = await makeFixture();
    const resource = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    expect(resource.userName).toBe("ada@acme.test");
    expect(resource.displayName).toBe("Ada Lovelace");
    expect(resource.externalId).toBe("okta-1");
    expect(resource.active).toBe(true);
    expect(resource.emails).toEqual([{ value: "ada@acme.test", primary: true, type: "work" }]);

    // The IdP is the system of record for the address, so it lands verified.
    const identifier = await fx.run(fx.identifiers.getByValue("email", "ada@acme.test"));
    expect(identifier?.userId).toBe(resource.id);
    expect(identifier?.verified).toBe(true);

    // ...and the user is a member of the connection's organization, no other.
    expect(fx.members.map((m) => ({ organizationId: m.organizationId, role: m.role }))).toEqual([
      { organizationId: ORG_A, role: "member" },
    ]);
  });

  it("honours a configured default role", async () => {
    const fx = await makeFixture({ defaultRole: "guest" });
    await fx.run(fx.service.createUser(fx.a.connection, ADA));
    expect(fx.members[0]?.role).toBe("guest");
  });

  it("normalizes userName and claims the extra emails alongside it", async () => {
    const fx = await makeFixture();
    const resource = await fx.run(
      fx.service.createUser(fx.a.connection, {
        userName: "  Ada@ACME.test ",
        emails: [{ value: "ada@acme.test", primary: true }, { value: "Ada.L@acme.test" }],
      }),
    );
    expect(resource.userName).toBe("ada@acme.test");
    expect(resource.emails.map((e) => e.value).sort()).toEqual([
      "ada.l@acme.test",
      "ada@acme.test",
    ]);
    expect(resource.emails.filter((e) => e.primary === true)).toHaveLength(1);
  });

  it("reports a taken address as a 409 uniqueness conflict, creating nothing", async () => {
    const fx = await makeFixture();
    await fx.run(fx.service.createUser(fx.a.connection, ADA));

    const err = await fx.run(Effect.flip(fx.service.createUser(fx.a.connection, ADA)));
    expect((err as SCIMError).status).toBe(409);
    expect((err as SCIMError).scimType).toBe("uniqueness");
    // The pre-flight check runs before the user row, so no orphan is left.
    expect(fx.usersById.size).toBe(1);
  });

  it("rejects an empty userName", async () => {
    const fx = await makeFixture();
    const err = await fx.run(
      Effect.flip(fx.service.createUser(fx.a.connection, { userName: " " })),
    );
    expect((err as SCIMError).status).toBe(400);
    expect((err as SCIMError).scimType).toBe("invalidValue");
  });

  it("keeps organizations apart: a connection cannot read another org's user", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    // Org B's connection sees the id as absent — not forbidden, absent — so it
    // cannot use the status code to enumerate the rest of the directory.
    const err = await fx.run(Effect.flip(fx.service.getUser(fx.b.connection, ada.id)));
    expect((err as SCIMError).status).toBe(404);

    const listed = await fx.run(fx.service.listUsers(fx.b.connection));
    expect(listed.totalResults).toBe(0);

    // Nor can it patch or deactivate across the boundary.
    const patchErr = await fx.run(
      Effect.flip(
        fx.service.patchUser(fx.b.connection, ada.id, [
          { op: "replace", path: "active", value: false },
        ]),
      ),
    );
    expect((patchErr as SCIMError).status).toBe(404);
    const deleteErr = await fx.run(Effect.flip(fx.service.deactivateUser(fx.b.connection, ada.id)));
    expect((deleteErr as SCIMError).status).toBe(404);
    expect(SCIM.isSCIMDeactivated(fx.usersById.get(ada.id)!)).toBe(false);
  });

  it("finds a user by the one filter Okta and Entra actually send", async () => {
    const fx = await makeFixture();
    await fx.run(fx.service.createUser(fx.a.connection, ADA));
    await fx.run(
      fx.service.createUser(fx.a.connection, { userName: "grace@acme.test", externalId: "okta-2" }),
    );

    const byUserName = await fx.run(
      fx.service.listUsers(fx.a.connection, { filter: 'userName eq "ada@acme.test"' }),
    );
    expect(byUserName.totalResults).toBe(1);
    expect(byUserName.resources[0]?.userName).toBe("ada@acme.test");

    // IdPs are inconsistent about case in the address they filter on.
    const caseInsensitive = await fx.run(
      fx.service.listUsers(fx.a.connection, { filter: 'userName eq "Ada@Acme.test"' }),
    );
    expect(caseInsensitive.totalResults).toBe(1);

    const byExternalId = await fx.run(
      fx.service.listUsers(fx.a.connection, { filter: 'externalId eq "okta-2"' }),
    );
    expect(byExternalId.resources[0]?.userName).toBe("grace@acme.test");

    const miss = await fx.run(
      fx.service.listUsers(fx.a.connection, { filter: 'userName eq "nobody@acme.test"' }),
    );
    expect(miss.totalResults).toBe(0);
    expect(miss.resources).toEqual([]);
  });

  it("refuses a filter it cannot honour rather than returning the directory", async () => {
    const fx = await makeFixture();
    await fx.run(fx.service.createUser(fx.a.connection, ADA));

    for (const filter of ['displayName eq "Ada"', 'userName co "ada"', "userName pr"]) {
      const err = await fx.run(Effect.flip(fx.service.listUsers(fx.a.connection, { filter })));
      expect((err as SCIMError).status).toBe(400);
      expect((err as SCIMError).scimType).toBe("invalidFilter");
    }
  });

  it("paginates with a 1-based startIndex and a capped count", async () => {
    const fx = await makeFixture({ maxPageSize: 2 });
    for (const name of ["a", "b", "c"]) {
      await fx.run(fx.service.createUser(fx.a.connection, { userName: `${name}@acme.test` }));
    }

    const first = await fx.run(fx.service.listUsers(fx.a.connection, { startIndex: 1, count: 2 }));
    expect(first.totalResults).toBe(3);
    expect(first.startIndex).toBe(1);
    expect(first.itemsPerPage).toBe(2);
    expect(first.resources.map((r) => r.userName)).toEqual(["a@acme.test", "b@acme.test"]);

    const second = await fx.run(fx.service.listUsers(fx.a.connection, { startIndex: 3, count: 2 }));
    expect(second.resources.map((r) => r.userName)).toEqual(["c@acme.test"]);
    expect(second.itemsPerPage).toBe(1);

    // A page larger than the maximum is clamped, not honoured.
    const greedy = await fx.run(fx.service.listUsers(fx.a.connection, { count: 100 }));
    expect(greedy.itemsPerPage).toBe(2);
    expect(greedy.totalResults).toBe(3);
  });

  it("deactivates on PATCH active:false, revoking every live session", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    await fx.run(fx.sessionManager.createSession(ada.id));
    await fx.run(fx.sessionManager.createSession(ada.id));
    expect(fx.sessions.size).toBe(2);

    const patched = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "replace", path: "active", value: false },
      ]),
    );
    expect(patched.active).toBe(false);
    expect(fx.usersById.get(ada.id)?.attributes[SCIM_DEACTIVATED_ATTRIBUTE]).toBe(true);
    expect(fx.sessions.size).toBe(0);

    // The account survives: reactivation is one write, not a re-provision.
    const reactivated = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "replace", path: "active", value: true },
      ]),
    );
    expect(reactivated.active).toBe(true);
    expect(fx.usersById.get(ada.id)?.attributes[SCIM_DEACTIVATED_ATTRIBUTE]).toBeUndefined();
  });

  it("accepts Entra ID's path-less patch and its stringly-typed booleans", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    const patched = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "Replace", value: { active: "False" } },
      ]),
    );
    expect(patched.active).toBe(false);
  });

  it("replaces displayName, userName and externalId through PATCH", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    const patched = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "replace", path: "displayName", value: "Ada B. Lovelace" },
        { op: "replace", path: "userName", value: "ada.lovelace@acme.test" },
        { op: "replace", path: "externalId", value: "okta-99" },
      ]),
    );

    expect(patched.displayName).toBe("Ada B. Lovelace");
    expect(patched.externalId).toBe("okta-99");
    // A rename repoints userName and unclaims the address it left behind, so
    // the old handle is free and the new one is the primary.
    expect(patched.userName).toBe("ada.lovelace@acme.test");
    expect(patched.emails.map((e) => e.value)).toEqual(["ada.lovelace@acme.test"]);
    expect(await fx.run(fx.identifiers.getByValue("email", "ada@acme.test"))).toBeNull();
  });

  it("keeps userName pinned when an older secondary email exists", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(
      fx.service.createUser(fx.a.connection, {
        userName: "ada@acme.test",
        emails: [{ value: "ada.old@acme.test" }],
      }),
    );

    const patched = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "replace", path: "userName", value: "ada.new@acme.test" },
      ]),
    );
    // Without the pin, the older `ada.old@` identifier would take over as the
    // "primary" (earliest verified) email and userName would silently regress.
    expect(patched.userName).toBe("ada.new@acme.test");
    expect(patched.emails.map((e) => e.value).sort()).toEqual([
      "ada.new@acme.test",
      "ada.old@acme.test",
    ]);
  });

  it("adds and removes emails, but never the one userName resolves to", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    const added = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "add", path: "emails", value: [{ value: "ada.work@acme.test" }] },
      ]),
    );
    expect(added.emails.map((e) => e.value).sort()).toEqual([
      "ada.work@acme.test",
      "ada@acme.test",
    ]);

    const removed = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [
        { op: "remove", path: "emails", value: [{ value: "ada.work@acme.test" }] },
      ]),
    );
    expect(removed.emails.map((e) => e.value)).toEqual(["ada@acme.test"]);

    // A blanket remove still cannot strip the handle the resource is keyed by.
    const blanket = await fx.run(
      fx.service.patchUser(fx.a.connection, ada.id, [{ op: "remove", path: "emails" }]),
    );
    expect(blanket.emails.map((e) => e.value)).toEqual(["ada@acme.test"]);
  });

  it("refuses an email already claimed by someone else", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    await fx.run(fx.service.createUser(fx.a.connection, { userName: "grace@acme.test" }));

    const err = await fx.run(
      Effect.flip(
        fx.service.patchUser(fx.a.connection, ada.id, [
          { op: "add", path: "emails", value: [{ value: "grace@acme.test" }] },
        ]),
      ),
    );
    expect((err as SCIMError).status).toBe(409);
  });

  it("rejects an unsupported patch path with 400 invalidPath", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));

    const err = await fx.run(
      Effect.flip(
        fx.service.patchUser(fx.a.connection, ada.id, [
          { op: "replace", path: "name.givenName", value: "Ada" },
        ]),
      ),
    );
    expect((err as SCIMError).status).toBe(400);
    expect((err as SCIMError).scimType).toBe("invalidPath");
  });

  it("replaces a user with PUT, treating emails as authoritative only when sent", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(
      fx.service.createUser(fx.a.connection, {
        ...ADA,
        emails: [{ value: "ada.alt@acme.test" }],
      }),
    );

    // No `emails`: the profile is reconciled, the address book is left alone.
    const profileOnly = await fx.run(
      fx.service.replaceUser(fx.a.connection, ada.id, {
        userName: "ada@acme.test",
        displayName: "Ada L.",
      }),
    );
    expect(profileOnly.displayName).toBe("Ada L.");
    expect(profileOnly.emails.map((e) => e.value).sort()).toEqual([
      "ada.alt@acme.test",
      "ada@acme.test",
    ]);
    // externalId is absent from the PUT body, so it is cleared.
    expect(profileOnly.externalId).toBeUndefined();

    // With `emails`, anything missing from the list is unclaimed.
    const authoritative = await fx.run(
      fx.service.replaceUser(fx.a.connection, ada.id, {
        userName: "ada@acme.test",
        emails: [{ value: "ada@acme.test", primary: true }],
        active: false,
      }),
    );
    expect(authoritative.emails.map((e) => e.value)).toEqual(["ada@acme.test"]);
    expect(authoritative.active).toBe(false);
    expect(await fx.run(fx.identifiers.getByValue("email", "ada.alt@acme.test"))).toBeNull();
  });

  it("treats DELETE as a soft disable, not a delete", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    await fx.run(fx.sessionManager.createSession(ada.id));

    await fx.run(fx.service.deactivateUser(fx.a.connection, ada.id));

    // The user, its identifiers and its membership all survive.
    expect(fx.usersById.has(ada.id)).toBe(true);
    expect(await fx.run(fx.identifiers.getByValue("email", "ada@acme.test"))).not.toBeNull();
    expect(fx.members).toHaveLength(1);
    expect(fx.sessions.size).toBe(0);

    const resource = await fx.run(fx.service.getUser(fx.a.connection, ada.id));
    expect(resource.active).toBe(false);
  });

  it("projects a user it did not create, falling back to the primary email", async () => {
    const fx = await makeFixture();
    const userId = fx.seedUser(ORG_A, "signed-up@acme.test");

    const resource = await fx.run(fx.service.getUser(fx.a.connection, userId));
    expect(resource.userName).toBe("signed-up@acme.test");
    expect(resource.active).toBe(true);
    expect(resource.externalId).toBeUndefined();

    // And SCIM can then adopt it — e.g. stamp the IdP's own id on it.
    const patched = await fx.run(
      fx.service.patchUser(fx.a.connection, userId, [
        { op: "replace", path: "externalId", value: "okta-7" },
      ]),
    );
    expect(patched.externalId).toBe("okta-7");
    expect(fx.usersById.get(userId)?.attributes[SCIM_EXTERNAL_ID_ATTRIBUTE]).toBe("okta-7");
  });
});

describe("SCIMService — groups", () => {
  it("maps a group onto a team and its members onto team members", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    const grace = await fx.run(
      fx.service.createUser(fx.a.connection, { userName: "grace@acme.test" }),
    );

    const group = await fx.run(
      fx.service.createGroup(fx.a.connection, {
        displayName: "Engineering",
        members: [{ value: ada.id }, { value: grace.id }],
      }),
    );

    expect(group.displayName).toBe("Engineering");
    expect(group.members.map((m) => m.value).sort()).toEqual([ada.id, grace.id].sort());
    expect(fx.teams.get(group.id)?.organizationId).toBe(ORG_A);
    expect(fx.teamMembers).toHaveLength(2);
  });

  it("refuses to add a member from outside the connection's organization", async () => {
    const fx = await makeFixture();
    const outsider = fx.seedUser(ORG_B, "outsider@other.test");

    const err = await fx.run(
      Effect.flip(
        fx.service.createGroup(fx.a.connection, {
          displayName: "Engineering",
          members: [{ value: outsider }],
        }),
      ),
    );
    expect((err as SCIMError).status).toBe(400);
    expect((err as SCIMError).scimType).toBe("invalidValue");
  });

  it("cannot see or delete another organization's group", async () => {
    const fx = await makeFixture();
    const group = await fx.run(
      fx.service.createGroup(fx.a.connection, { displayName: "Engineering" }),
    );

    const err = await fx.run(Effect.flip(fx.service.getGroup(fx.b.connection, group.id)));
    expect((err as SCIMError).status).toBe(404);
    const deleteErr = await fx.run(Effect.flip(fx.service.deleteGroup(fx.b.connection, group.id)));
    expect((deleteErr as SCIMError).status).toBe(404);
    expect(fx.teams.has(group.id)).toBe(true);

    expect((await fx.run(fx.service.listGroups(fx.b.connection))).totalResults).toBe(0);
  });

  it("adds and removes members through PATCH, in both dialects", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    const grace = await fx.run(
      fx.service.createUser(fx.a.connection, { userName: "grace@acme.test" }),
    );
    const group = await fx.run(
      fx.service.createGroup(fx.a.connection, { displayName: "Engineering" }),
    );

    const added = await fx.run(
      fx.service.patchGroup(fx.a.connection, group.id, [
        { op: "add", path: "members", value: [{ value: ada.id }, { value: grace.id }] },
      ]),
    );
    expect(added.members).toHaveLength(2);

    // Adding a member twice is idempotent, not a duplicate row.
    const again = await fx.run(
      fx.service.patchGroup(fx.a.connection, group.id, [
        { op: "add", path: "members", value: [{ value: ada.id }] },
      ]),
    );
    expect(again.members).toHaveLength(2);

    // The `members[value eq "..."]` path filter both major IdPs use to remove.
    const removed = await fx.run(
      fx.service.patchGroup(fx.a.connection, group.id, [
        { op: "remove", path: `members[value eq "${ada.id}"]` },
      ]),
    );
    expect(removed.members.map((m) => m.value)).toEqual([grace.id]);
  });

  it("renames a group through PATCH and through PUT", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    const group = await fx.run(
      fx.service.createGroup(fx.a.connection, {
        displayName: "Engineering",
        members: [{ value: ada.id }],
      }),
    );

    const patched = await fx.run(
      fx.service.patchGroup(fx.a.connection, group.id, [
        { op: "replace", path: "displayName", value: "Platform" },
      ]),
    );
    expect(patched.displayName).toBe("Platform");
    expect(patched.members.map((m) => m.value)).toEqual([ada.id]);

    // PUT is authoritative about membership too.
    const replaced = await fx.run(
      fx.service.replaceGroup(fx.a.connection, group.id, {
        displayName: "Platform Engineering",
        members: [],
      }),
    );
    expect(replaced.displayName).toBe("Platform Engineering");
    expect(replaced.members).toEqual([]);
  });

  it("lists and filters groups, and deletes one without touching its members", async () => {
    const fx = await makeFixture();
    const ada = await fx.run(fx.service.createUser(fx.a.connection, ADA));
    const engineering = await fx.run(
      fx.service.createGroup(fx.a.connection, {
        displayName: "Engineering",
        members: [{ value: ada.id }],
      }),
    );
    await fx.run(fx.service.createGroup(fx.a.connection, { displayName: "Design" }));

    const all = await fx.run(fx.service.listGroups(fx.a.connection));
    expect(all.totalResults).toBe(2);

    const filtered = await fx.run(
      fx.service.listGroups(fx.a.connection, { filter: 'displayName eq "Design"' }),
    );
    expect(filtered.totalResults).toBe(1);
    expect(filtered.resources[0]?.displayName).toBe("Design");

    const badFilter = await fx.run(
      Effect.flip(fx.service.listGroups(fx.a.connection, { filter: 'members eq "x"' })),
    );
    expect((badFilter as SCIMError).scimType).toBe("invalidFilter");

    await fx.run(fx.service.deleteGroup(fx.a.connection, engineering.id));
    expect(fx.teams.has(engineering.id)).toBe(false);
    // Deleting a team is not deprovisioning: the user keeps their membership.
    expect(fx.members.some((m) => m.userId === ada.id)).toBe(true);
    expect(fx.usersById.has(ada.id)).toBe(true);
  });

  it("adopts a team created outside SCIM", async () => {
    const fx = await makeFixture();
    const team = fx.seedTeam(ORG_A, "Founders");
    const group = await fx.run(fx.service.getGroup(fx.a.connection, team.id));
    expect(group.displayName).toBe("Founders");
    expect(group.members).toEqual([]);
  });
});

describe("SCIMDeactivatedPlugin", () => {
  it("fails session validation for a deactivated user and passes everyone else", async () => {
    const active: Types.SessionWithUser = {
      session: {
        id: "s1",
        userId: "u1",
        expiresAt: new Date(Date.now() + 1000),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        attributes: {},
      },
      user: {
        id: "u1",
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      },
    };
    const deactivated: Types.SessionWithUser = {
      ...active,
      user: { ...active.user, attributes: { [SCIM_DEACTIVATED_ATTRIBUTE]: true } },
    };

    const layer = SCIMDeactivatedPlugin.pipe(Layer.provide(Hooks.Default));
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return {
          allowed: yield* hooks.afterValidateSession(active),
          blocked: yield* Effect.flip(hooks.afterValidateSession(deactivated)),
        };
      }).pipe(Effect.provide(layer)),
    );

    expect(result.allowed.user.id).toBe("u1");
    expect(result.blocked._tag).toBe("UserBannedError");
  });
});

// --- HTTP layer --------------------------------------------------------------

/** A web handler wired with the SCIM endpoints over the in-memory stores. */
const makeHttpFixture = async (config: SCIM.SCIMConfig = {}) => {
  const stores = makeStores();

  // Members the SCIM handlers never touch, but `AuthServices` requires.
  // `SessionService` and `IdentifierStore` come from `stores.layer` for real.
  const base = Layer.mergeAll(
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(UserService)(undefined as never),
    Hooks.Default,
  );

  const scimServiceLayer = SCIMService.layer(config).pipe(Layer.provide(stores.layer));
  const withSCIM = Layer.mergeAll(
    stores.layer,
    base,
    scimServiceLayer,
  ) as Layer.Layer<AuthServices>;
  const withoutSCIM = Layer.mergeAll(stores.layer, base) as Layer.Layer<AuthServices>;

  const service = await Effect.runPromise(SCIM.make(config).pipe(Effect.provide(stores.layer)));
  const connection = await Effect.runPromise(service.createConnection(ORG_A));
  const other = await Effect.runPromise(service.createConnection(ORG_B));

  return {
    ...stores,
    token: connection.token,
    otherToken: other.token,
    handler: HTTPServer.make({ services: withSCIM, cookie: { secure: false } }).handler,
    handlerWithoutSCIM: HTTPServer.make({ services: withoutSCIM, cookie: { secure: false } })
      .handler,
  };
};

const scimReq = (
  method: string,
  path: string,
  options: { readonly token?: string; readonly body?: unknown } = {},
): Request =>
  new Request(`http://test/scim/v2${path}`, {
    method,
    headers: {
      ...(options.body !== undefined ? { "content-type": "application/scim+json" } : {}),
      ...(options.token !== undefined ? { authorization: `Bearer ${options.token}` } : {}),
    },
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });

interface ScimUserBody {
  readonly schemas: ReadonlyArray<string>;
  readonly id: string;
  readonly userName: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly emails: ReadonlyArray<{ value: string; primary?: boolean }>;
  readonly active: boolean;
  readonly meta: { resourceType: string; location: string; created: string; lastModified: string };
}

interface ScimListBody<A> {
  readonly schemas: ReadonlyArray<string>;
  readonly totalResults: number;
  readonly startIndex: number;
  readonly itemsPerPage: number;
  readonly Resources: ReadonlyArray<A>;
}

interface ScimErrorBody {
  readonly schemas: ReadonlyArray<string>;
  readonly status: string;
  readonly scimType?: string;
  readonly detail?: string;
}

describe("HTTP SCIM endpoints", () => {
  it("gates every route on the provisioning token", async () => {
    const fx = await makeHttpFixture();

    const anonymous = await fx.handler(scimReq("GET", "/Users"));
    expect(anonymous.status).toBe(401);
    const body = (await anonymous.json()) as ScimErrorBody;
    expect(body.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
    expect(body.status).toBe("401");
    expect(anonymous.headers.get("content-type")).toContain("application/scim+json");

    const wrongToken = await fx.handler(scimReq("GET", "/Users", { token: "nope" }));
    expect(wrongToken.status).toBe(401);

    const authorized = await fx.handler(scimReq("GET", "/Users", { token: fx.token }));
    expect(authorized.status).toBe(200);
  });

  it("returns 404 in SCIM's error shape when provisioning is not configured", async () => {
    const fx = await makeHttpFixture();
    const res = await fx.handlerWithoutSCIM(scimReq("GET", "/Users", { token: fx.token }));
    expect(res.status).toBe(404);
    const body = (await res.json()) as ScimErrorBody;
    expect(body.status).toBe("404");
    expect(body.detail).toMatch(/not enabled/);
  });

  it("runs an Okta-style provisioning lifecycle end to end", async () => {
    const fx = await makeHttpFixture({ baseUrl: "https://app.test/api/auth/scim/v2" });

    // 1. Okta looks the user up before deciding to create them.
    const probe = await fx.handler(
      scimReq("GET", `/Users?filter=${encodeURIComponent('userName eq "ada@acme.test"')}`, {
        token: fx.token,
      }),
    );
    expect(probe.status).toBe(200);
    expect(((await probe.json()) as ScimListBody<ScimUserBody>).totalResults).toBe(0);

    // 2. Not found, so it creates them — with `name` but no `displayName`.
    const created = await fx.handler(
      scimReq("POST", "/Users", {
        token: fx.token,
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
          userName: "ada@acme.test",
          externalId: "00u1",
          name: { givenName: "Ada", familyName: "Lovelace" },
          emails: [{ value: "ada@acme.test", primary: true, type: "work" }],
          active: true,
        },
      }),
    );
    expect(created.status).toBe(201);
    expect(created.headers.get("content-type")).toContain("application/scim+json");
    const user = (await created.json()) as ScimUserBody;
    expect(user.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:User"]);
    expect(user.userName).toBe("ada@acme.test");
    // `name` was folded into a display name.
    expect(user.displayName).toBe("Ada Lovelace");
    expect(user.active).toBe(true);
    expect(user.meta.resourceType).toBe("User");
    expect(user.meta.location).toBe(`https://app.test/api/auth/scim/v2/Users/${user.id}`);

    // 3. Creating the same userName again is a uniqueness conflict.
    const duplicate = await fx.handler(
      scimReq("POST", "/Users", { token: fx.token, body: { userName: "ada@acme.test" } }),
    );
    expect(duplicate.status).toBe(409);
    const conflict = (await duplicate.json()) as ScimErrorBody;
    expect(conflict.status).toBe("409");
    expect(conflict.scimType).toBe("uniqueness");
    // The body is RFC 7644 §3.12 verbatim — no repo-specific members.
    expect(Object.keys(conflict).sort()).toEqual(["detail", "schemas", "scimType", "status"]);

    // 4. The filter now finds them.
    const found = await fx.handler(
      scimReq("GET", `/Users?filter=${encodeURIComponent('userName eq "ada@acme.test"')}`, {
        token: fx.token,
      }),
    );
    const list = (await found.json()) as ScimListBody<ScimUserBody>;
    expect(list.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    expect(list.totalResults).toBe(1);
    expect(list.startIndex).toBe(1);
    expect(list.itemsPerPage).toBe(1);
    expect(list.Resources[0]?.id).toBe(user.id);

    // 5. A single read by id.
    const read = await fx.handler(scimReq("GET", `/Users/${user.id}`, { token: fx.token }));
    expect(read.status).toBe(200);
    expect(((await read.json()) as ScimUserBody).userName).toBe("ada@acme.test");

    // 6. Ada leaves: Okta deactivates rather than deletes.
    const deactivated = await fx.handler(
      scimReq("PATCH", `/Users/${user.id}`, {
        token: fx.token,
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "replace", path: "active", value: false }],
        },
      }),
    );
    expect(deactivated.status).toBe(200);
    expect(((await deactivated.json()) as ScimUserBody).active).toBe(false);

    // 7. Groups: create one, then push a member into it.
    const group = await fx.handler(
      scimReq("POST", "/Groups", {
        token: fx.token,
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          displayName: "Engineering",
        },
      }),
    );
    expect(group.status).toBe(201);
    const groupBody = (await group.json()) as { id: string; displayName: string; members: [] };
    expect(groupBody.displayName).toBe("Engineering");
    expect(groupBody.members).toEqual([]);

    const withMember = await fx.handler(
      scimReq("PATCH", `/Groups/${groupBody.id}`, {
        token: fx.token,
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "add", path: "members", value: [{ value: user.id }] }],
        },
      }),
    );
    expect(withMember.status).toBe(200);
    const patchedGroup = (await withMember.json()) as {
      members: ReadonlyArray<{ value: string }>;
      meta: { resourceType: string };
    };
    expect(patchedGroup.members.map((m) => m.value)).toEqual([user.id]);
    expect(patchedGroup.meta.resourceType).toBe("Group");

    // 8. DELETE is a soft disable; the account is still readable.
    const removed = await fx.handler(scimReq("DELETE", `/Users/${user.id}`, { token: fx.token }));
    expect(removed.status).toBe(204);
    const after = await fx.handler(scimReq("GET", `/Users/${user.id}`, { token: fx.token }));
    expect(after.status).toBe(200);
    expect(((await after.json()) as ScimUserBody).active).toBe(false);

    // 9. Deleting the group leaves the user in place.
    const groupGone = await fx.handler(
      scimReq("DELETE", `/Groups/${groupBody.id}`, { token: fx.token }),
    );
    expect(groupGone.status).toBe(204);
    expect(
      (await fx.handler(scimReq("GET", `/Groups/${groupBody.id}`, { token: fx.token }))).status,
    ).toBe(404);
  });

  it("scopes every route to the token's organization", async () => {
    const fx = await makeHttpFixture();
    const created = await fx.handler(
      scimReq("POST", "/Users", { token: fx.token, body: { userName: "ada@acme.test" } }),
    );
    const user = (await created.json()) as ScimUserBody;

    // Org B's token is valid, but the resource is not its to see.
    const foreign = await fx.handler(scimReq("GET", `/Users/${user.id}`, { token: fx.otherToken }));
    expect(foreign.status).toBe(404);

    const list = await fx.handler(scimReq("GET", "/Users", { token: fx.otherToken }));
    expect(((await list.json()) as ScimListBody<ScimUserBody>).totalResults).toBe(0);
  });

  it("rejects an unusable filter and unusable pagination with 400", async () => {
    const fx = await makeHttpFixture();

    const badFilter = await fx.handler(
      scimReq("GET", `/Users?filter=${encodeURIComponent('displayName co "a"')}`, {
        token: fx.token,
      }),
    );
    expect(badFilter.status).toBe(400);
    expect(((await badFilter.json()) as ScimErrorBody).scimType).toBe("invalidFilter");

    const badCount = await fx.handler(scimReq("GET", "/Users?count=lots", { token: fx.token }));
    expect(badCount.status).toBe(400);
    expect(((await badCount.json()) as ScimErrorBody).scimType).toBe("invalidValue");
  });

  it("paginates over the wire", async () => {
    const fx = await makeHttpFixture();
    for (const name of ["a", "b", "c"]) {
      await fx.handler(
        scimReq("POST", "/Users", { token: fx.token, body: { userName: `${name}@acme.test` } }),
      );
    }

    const page = await fx.handler(
      scimReq("GET", "/Users?startIndex=2&count=2", { token: fx.token }),
    );
    const body = (await page.json()) as ScimListBody<ScimUserBody>;
    expect(body.totalResults).toBe(3);
    expect(body.startIndex).toBe(2);
    expect(body.itemsPerPage).toBe(2);
    expect(body.Resources.map((r) => r.userName)).toEqual(["b@acme.test", "c@acme.test"]);
  });

  it("replaces a user with PUT", async () => {
    const fx = await makeHttpFixture();
    const created = await fx.handler(
      scimReq("POST", "/Users", {
        token: fx.token,
        body: { userName: "ada@acme.test", displayName: "Ada" },
      }),
    );
    const user = (await created.json()) as ScimUserBody;

    const replaced = await fx.handler(
      scimReq("PUT", `/Users/${user.id}`, {
        token: fx.token,
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
          userName: "ada@acme.test",
          displayName: "Ada Lovelace",
          emails: [{ value: "ada@acme.test", primary: true }],
          active: true,
        },
      }),
    );
    expect(replaced.status).toBe(200);
    expect(((await replaced.json()) as ScimUserBody).displayName).toBe("Ada Lovelace");
  });

  it("serves the three discovery documents without a token", async () => {
    const fx = await makeHttpFixture({ baseUrl: "https://app.test/api/auth/scim/v2" });

    const config = await fx.handler(scimReq("GET", "/ServiceProviderConfig"));
    expect(config.status).toBe(200);
    expect(config.headers.get("content-type")).toContain("application/scim+json");
    const configBody = (await config.json()) as {
      schemas: ReadonlyArray<string>;
      patch: { supported: boolean };
      bulk: { supported: boolean };
      filter: { supported: boolean; maxResults: number };
      authenticationSchemes: ReadonlyArray<{ type: string }>;
    };
    expect(configBody.schemas).toEqual([
      "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
    ]);
    // What is advertised is what is implemented — no aspirational features.
    expect(configBody.patch.supported).toBe(true);
    expect(configBody.bulk.supported).toBe(false);
    expect(configBody.filter).toEqual({ supported: true, maxResults: 100 });
    expect(configBody.authenticationSchemes[0]?.type).toBe("oauthbearertoken");

    const types = await fx.handler(scimReq("GET", "/ResourceTypes"));
    expect(types.status).toBe(200);
    const typesBody = (await types.json()) as ScimListBody<{ id: string; endpoint: string }>;
    expect(typesBody.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    expect(typesBody.Resources.map((r) => r.id)).toEqual(["User", "Group"]);
    expect(typesBody.Resources.map((r) => r.endpoint)).toEqual(["/Users", "/Groups"]);

    const schemas = await fx.handler(scimReq("GET", "/Schemas"));
    expect(schemas.status).toBe(200);
    const schemasBody = (await schemas.json()) as ScimListBody<{
      id: string;
      attributes: ReadonlyArray<{ name: string }>;
    }>;
    expect(schemasBody.Resources.map((r) => r.id)).toEqual([
      "urn:ietf:params:scim:schemas:core:2.0:User",
      "urn:ietf:params:scim:schemas:core:2.0:Group",
    ]);
    expect(schemasBody.Resources[0]?.attributes.map((a) => a.name)).toContain("userName");
  });
});
