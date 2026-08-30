import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as Cipher from "../Cipher.ts";
import { type AuthServices } from "./HttpServer.ts";
import * as HTTPServer from "./HttpServer.ts";
import { SessionStore } from "../session/SessionStore.ts";
import { UserStore } from "../session/UserStore.ts";
import { SessionService } from "../session/SessionService.ts";
import { hashToken } from "../TokenHash.ts";
import { UserServiceStore, UserService } from "../User.ts";
import { Hooks } from "../Hooks.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { EmailPasswordStore } from "../email/EmailPassword.ts";
import { PasswordHasher } from "../password/Password.ts";
import { EmailVerificationService, EmailVerificationStore } from "../email/EmailVerification.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "../password/PasswordReset.ts";
import {
  OrganizationStore,
  type Organization,
  type Member,
  type Invitation,
  type Team,
  type TeamMember,
  OrganizationService,
} from "../Organization.ts";
import { AdminUserStore, AdminService } from "../Admin.ts";
import { APIKeyStore, type APIKey, APIKeyService } from "../APIKey.ts";
import { JWTKeyStore, type JWTKeyPair, JWTService } from "../JWT.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import { RateLimiter, RateLimitStore, type RateLimitEntry } from "../RateLimit.ts";
import type * as Types from "../Types.ts";

const HOUR = 60 * 60 * 1000;

/** Build a handler wired with real org/admin/api-key/jwt services + in-memory stores. */
const makeFixture = () => {
  const usersById = new Map<string, Types.User>();
  const identifierRecords = new Map<string, Identifier>();
  const sessions = new Map<string, Types.Session>();
  const orgs = new Map<string, Organization>();
  const members: Member[] = [];
  const invitations = new Map<string, Invitation>();
  const teams = new Map<string, Team>();
  const teamMembers: TeamMember[] = [];
  const apiKeys = new Map<string, APIKey>();
  const jwtKeys: JWTKeyPair[] = [];

  const seedUser = (id: string, email: string, attributes: Record<string, unknown> = {}) => {
    const now = new Date();
    const user: Types.User = {
      id,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    usersById.set(id, user);
    // The login handle lives in the identifier store (verified email).
    const identifier = makeIdentifier({
      userId: id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
      now,
    });
    identifierRecords.set(identifier.id, identifier);
    return user;
  };

  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).toString(
      "hex",
    );
    const tokenHash = hashToken(rawToken);
    const now = new Date();
    sessions.set(tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: new Date(Date.now() + HOUR),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId: string) => Effect.succeed(null),
  };

  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        return user;
      }),
    delete: (userId: string) => Effect.sync(() => void usersById.delete(userId)),
  };

  const sessionStore = {
    create: (session: Types.Session) =>
      Effect.sync(() => {
        sessions.set(session.id, session);
        return session;
      }),
    get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),
    update: (session: Types.Session) =>
      Effect.sync(() => {
        sessions.set(session.id, session);
        return session;
      }),
    delete: (sessionId: string) => Effect.sync(() => void sessions.delete(sessionId)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
  };

  const orgStore = {
    createOrganization: (o: Organization) => Effect.sync(() => (orgs.set(o.id, o), o)),
    getOrganizationById: (id: string) => Effect.succeed(orgs.get(id) ?? null),
    getOrganizationBySlug: (slug: string) =>
      Effect.succeed([...orgs.values()].find((o) => o.slug === slug) ?? null),
    updateOrganization: (o: Organization) => Effect.sync(() => (orgs.set(o.id, o), o)),
    deleteOrganization: (id: string) =>
      Effect.sync(() => {
        orgs.delete(id);
        for (const [teamId, team] of teams) {
          if (team.organizationId !== id) continue;
          teams.delete(teamId);
          for (let i = teamMembers.length - 1; i >= 0; i--) {
            if (teamMembers[i].teamId === teamId) teamMembers.splice(i, 1);
          }
        }
      }),
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    updateMember: (m: Member) =>
      Effect.sync(() => {
        const i = members.findIndex((x) => x.id === m.id);
        if (i >= 0) members[i] = m;
        return m;
      }),
    deleteMember: (memberId: string) =>
      Effect.sync(() => {
        const i = members.findIndex((x) => x.id === memberId);
        if (i >= 0) members.splice(i, 1);
      }),
    listMembersByOrganization: (organizationId: string) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId)),
    listMembersByUser: (userId: string) =>
      Effect.succeed(members.filter((m) => m.userId === userId)),
    countMembersByOrganization: (organizationId: string) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId).length),
    createInvitation: (inv: Invitation) => Effect.sync(() => (invitations.set(inv.id, inv), inv)),
    getInvitation: (id: string) => Effect.succeed(invitations.get(id) ?? null),
    updateInvitation: (inv: Invitation) => Effect.sync(() => (invitations.set(inv.id, inv), inv)),
    listInvitationsByOrganization: (organizationId: string) =>
      Effect.succeed([...invitations.values()].filter((i) => i.organizationId === organizationId)),
    listInvitationsByEmail: (email: string) =>
      Effect.succeed([...invitations.values()].filter((i) => i.email === email)),
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
          if (teamMembers[i].teamId === teamId) teamMembers.splice(i, 1);
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
    listTeamsForMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        teamMembers
          .filter((m) => m.userId === userId)
          .map((m) => teams.get(m.teamId))
          .filter((t): t is Team => t !== undefined && t.organizationId === organizationId),
      ),
  };

  const adminUserStore = {
    listUsers: (query: { limit?: number; offset?: number; searchEmail?: string }) =>
      Effect.sync(() => {
        let all = [...usersById.values()];
        if (query.searchEmail !== undefined) {
          // Emails live in the identifier store now; search resolves through it.
          const needle = query.searchEmail.toLowerCase();
          const matching = new Set(
            [...identifierRecords.values()]
              .filter((i) => i.type === "email" && i.value.toLowerCase().includes(needle))
              .map((i) => i.userId),
          );
          all = all.filter((u) => matching.has(u.id));
        }
        const total = all.length;
        const offset = query.offset ?? 0;
        const limit = query.limit ?? all.length;
        return { users: all.slice(offset, offset + limit), total };
      }),

    createUser: (input: { name?: string; image?: string; attributes?: Record<string, unknown> }) =>
      Effect.sync(() => {
        const id = `created-${Date.now()}`;
        const user: Types.User = {
          id,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: new Date(),
          updatedAt: new Date(),
          attributes: input.attributes ?? {},
        };
        usersById.set(id, user);
        return user;
      }),

    setPasswordHash: (_userId: string, _hash: string) => Effect.void,
  };

  const apiKeyStore = {
    create: (k: APIKey) => Effect.sync(() => (apiKeys.set(k.id, k), k)),
    get: (id: string) => Effect.succeed(apiKeys.get(id) ?? null),
    getByHash: (keyHash: string) =>
      Effect.succeed([...apiKeys.values()].find((k) => k.keyHash === keyHash) ?? null),
    update: (k: APIKey) => Effect.sync(() => (apiKeys.set(k.id, k), k)),
    delete: (id: string) => Effect.sync(() => void apiKeys.delete(id)),
    listByUserId: (userId: string) =>
      Effect.succeed([...apiKeys.values()].filter((k) => k.userId === userId)),
  };

  const jwtKeyStore = {
    getActive: () => Effect.succeed(jwtKeys[0] ?? null),
    create: (pair: JWTKeyPair) => Effect.sync(() => (jwtKeys.push(pair), pair)),
    list: () => Effect.succeed(jwtKeys),
  };

  // In-memory RateLimitStore: APIKeyService resolves RateLimiter at construction
  // time even though these tests never exercise rate-limited paths.
  const rateLimitEntries = new Map<string, RateLimitEntry>();
  const rateLimitStore = {
    get: (key: string) => Effect.sync(() => rateLimitEntries.get(key) ?? null),
    set: (key: string, entry: RateLimitEntry, _ttl: number) =>
      Effect.sync(() => void rateLimitEntries.set(key, entry)),
    increment: (key: string, _ttl: number) =>
      Effect.sync(() => {
        const entry = rateLimitEntries.get(key);
        const count = (entry?.count ?? 0) + 1;
        if (entry) rateLimitEntries.set(key, { ...entry, count });
        return count;
      }),
    delete: (key: string) => Effect.sync(() => void rateLimitEntries.delete(key)),
  };

  // Stage 0: raw stores + Hooks + dummy layers for AuthServices members these
  // tests never exercise (org/admin/api-key/jwt handlers never touch them).
  const storesLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore as never),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(OrganizationStore)(orgStore),
    Layer.succeed(AdminUserStore)(adminUserStore),
    Layer.succeed(APIKeyStore)(apiKeyStore),
    Layer.succeed(JWTKeyStore)(jwtKeyStore),
    Layer.succeed(RateLimitStore)(rateLimitStore),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(identifierRecords)),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordStore)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(EmailVerificationStore)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(PasswordResetStore)(undefined as never),
    Layer.succeed(PasswordResetUserStore)(undefined as never),
  );

  // Stage 1: services whose construction-time deps are all raw stores.
  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
  }).pipe(Layer.provide(storesLayer));
  const userServiceLayer = UserService.layer().pipe(Layer.provide(storesLayer));
  const rateLimiterLayer = RateLimiter.layer().pipe(Layer.provide(storesLayer));

  const stage1 = Layer.mergeAll(
    storesLayer,
    sessionServiceLayer,
    userServiceLayer,
    rateLimiterLayer,
  );

  // Stage 2: services that depend on stage-1 services (SessionService, etc.).
  const organizationServiceLayer = OrganizationService.layer().pipe(Layer.provide(stage1));
  const adminServiceLayer = AdminService.layer({ adminRoles: ["admin"] }).pipe(
    Layer.provide(stage1),
  );
  const apiKeyServiceLayer = APIKeyService.layer().pipe(Layer.provide(stage1));
  const jwtServiceLayer = JWTService.layer({ issuer: "https://auth.test" }).pipe(
    Layer.provide(stage1),
  );

  const services = Layer.mergeAll(
    stage1,
    organizationServiceLayer,
    adminServiceLayer,
    apiKeyServiceLayer,
    jwtServiceLayer,
  ) as Layer.Layer<AuthServices>;
  const { handler } = HTTPServer.make({ services, cookie: { secure: false } });

  return { handler, seedUser, makeSession, sessions };
};

const withCookie = (sessionId: string) => ({ cookie: `conduit_session=${sessionId}` });

const jsonReq = (path: string, body: unknown, sessionId?: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sessionId !== undefined ? withCookie(sessionId) : {}),
    },
    body: JSON.stringify(body),
  });

const req = (method: string, path: string, sessionId?: string, body?: unknown): Request =>
  new Request(`http://test${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(sessionId !== undefined ? withCookie(sessionId) : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });

describe("HTTP organization endpoints", () => {
  it("runs a full organization lifecycle", async () => {
    const fx = makeFixture();
    fx.seedUser("u1", "owner@test.com");
    const sid = fx.makeSession("u1");

    // Create.
    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, sid),
    );
    expect(created.status).toBe(200);
    const org = (await created.json()) as { id: string; slug: string };
    expect(org.slug).toBe("acme");

    // Full org includes the creator as an owner member.
    const full = await fx.handler(req("GET", `/organization/${org.id}`, sid));
    expect(full.status).toBe(200);
    const fullBody = (await full.json()) as {
      organization: { id: string };
      members: Array<{ userId: string; role: string }>;
    };
    expect(fullBody.members).toEqual([{ ...fullBody.members[0], userId: "u1", role: "owner" }]);

    // List shows the org.
    const list = await fx.handler(req("GET", "/organizations", sid));
    expect(((await list.json()) as Array<{ id: string }>).map((o) => o.id)).toEqual([org.id]);

    // Invite a member.
    const invited = await fx.handler(
      jsonReq(
        `/organization/${org.id}/invitations`,
        { email: "new@test.com", role: "member" },
        sid,
      ),
    );
    expect(invited.status).toBe(200);
    const listInv = await fx.handler(req("GET", `/organization/${org.id}/invitations`, sid));
    expect(((await listInv.json()) as unknown[]).length).toBe(1);

    // Update.
    const updated = await fx.handler(
      req("PATCH", `/organization/${org.id}`, sid, { name: "Acme Inc" }),
    );
    expect(((await updated.json()) as { name: string }).name).toBe("Acme Inc");

    // Set active organization (stored on the session).
    const active = await fx.handler(
      jsonReq("/organization/set-active", { organizationId: org.id }, sid),
    );
    expect(active.status).toBe(200);
    expect(fx.sessions.get(hashToken(sid))?.attributes["activeOrganizationId"]).toBe(org.id);

    // Delete.
    const deleted = await fx.handler(req("DELETE", `/organization/${org.id}`, sid));
    expect(deleted.status).toBe(204);
  });

  it("returns 403 when a non-member tries to update", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("stranger", "stranger@test.com");
    const ownerSid = fx.makeSession("owner");
    const strangerSid = fx.makeSession("stranger");

    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, ownerSid),
    );
    const org = (await created.json()) as { id: string };

    const res = await fx.handler(
      req("PATCH", `/organization/${org.id}`, strangerSid, { name: "Hijack" }),
    );
    expect(res.status).toBe(403);
  });

  it("requires authentication", async () => {
    const fx = makeFixture();
    const res = await fx.handler(jsonReq("/organization/create", { name: "A", slug: "a" }));
    expect(res.status).toBe(401);
  });

  it("runs a full team lifecycle", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, ownerSid),
    );
    const org = (await created.json()) as { id: string };
    await fx.handler(
      jsonReq(`/organization/${org.id}/members`, { userId: "member", role: "member" }, ownerSid),
    );

    // Create.
    const teamRes = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Engineering" }, ownerSid),
    );
    expect(teamRes.status).toBe(200);
    const team = (await teamRes.json()) as { id: string; name: string; organizationId: string };
    expect(team.name).toBe("Engineering");
    expect(team.organizationId).toBe(org.id);

    // Any organization member may list.
    const listed = await fx.handler(req("GET", `/organization/${org.id}/teams`, memberSid));
    expect(((await listed.json()) as Array<{ id: string }>).map((t) => t.id)).toEqual([team.id]);

    // Add + list team members.
    const added = await fx.handler(
      jsonReq(`/teams/${team.id}/members`, { userId: "member" }, ownerSid),
    );
    expect(added.status).toBe(200);
    expect((await added.json()) as { userId: string }).toMatchObject({
      teamId: team.id,
      userId: "member",
    });

    const teamMembersRes = await fx.handler(req("GET", `/teams/${team.id}/members`, memberSid));
    expect(
      ((await teamMembersRes.json()) as Array<{ userId: string }>).map((m) => m.userId),
    ).toEqual(["member"]);

    const forMember = await fx.handler(
      req("GET", `/organization/${org.id}/members/member/teams`, memberSid),
    );
    expect(((await forMember.json()) as Array<{ id: string }>).map((t) => t.id)).toEqual([team.id]);

    // Rename.
    const renamed = await fx.handler(
      req("PATCH", `/teams/${team.id}`, ownerSid, { name: "Platform" }),
    );
    expect(((await renamed.json()) as { name: string }).name).toBe("Platform");

    // Remove the team member, then the team.
    const removed = await fx.handler(req("DELETE", `/teams/${team.id}/members/member`, ownerSid));
    expect(removed.status).toBe(204);
    const emptied = await fx.handler(req("GET", `/teams/${team.id}/members`, ownerSid));
    expect(((await emptied.json()) as unknown[]).length).toBe(0);

    const deleted = await fx.handler(req("DELETE", `/teams/${team.id}`, ownerSid));
    expect(deleted.status).toBe(204);
    const afterDelete = await fx.handler(req("GET", `/organization/${org.id}/teams`, ownerSid));
    expect(((await afterDelete.json()) as unknown[]).length).toBe(0);
  });

  it("returns 403 when a plain member tries to manage teams", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, ownerSid),
    );
    const org = (await created.json()) as { id: string };
    await fx.handler(
      jsonReq(`/organization/${org.id}/members`, { userId: "member", role: "member" }, ownerSid),
    );

    const denied = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Rogue" }, memberSid),
    );
    expect(denied.status).toBe(403);

    const teamRes = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Engineering" }, ownerSid),
    );
    const team = (await teamRes.json()) as { id: string };

    const deniedAdd = await fx.handler(
      jsonReq(`/teams/${team.id}/members`, { userId: "member" }, memberSid),
    );
    expect(deniedAdd.status).toBe(403);

    const deniedDelete = await fx.handler(req("DELETE", `/teams/${team.id}`, memberSid));
    expect(deniedDelete.status).toBe(403);
  });
});

describe("HTTP admin endpoints", () => {
  it("bans a user (revoking their sessions) and rejects non-admins", async () => {
    const fx = makeFixture();
    fx.seedUser("admin", "admin@test.com", { role: "admin" });
    fx.seedUser("victim", "victim@test.com");
    const adminSid = fx.makeSession("admin");
    const victimSid = fx.makeSession("victim");

    // A non-admin cannot ban.
    const denied = await fx.handler(jsonReq("/admin/users/ban", { userId: "admin" }, victimSid));
    expect(denied.status).toBe(403);

    // The admin bans the victim.
    const banned = await fx.handler(
      jsonReq("/admin/users/ban", { userId: "victim", reason: "spam" }, adminSid),
    );
    expect(banned.status).toBe(200);
    expect(((await banned.json()) as { attributes: { banned: boolean } }).attributes.banned).toBe(
      true,
    );

    // The victim's session was revoked.
    const check = await fx.handler(req("GET", "/session", victimSid));
    expect(check.status).toBe(401);
  });

  it("sets a user's role", async () => {
    const fx = makeFixture();
    fx.seedUser("admin", "admin@test.com", { role: "admin" });
    fx.seedUser("u", "u@test.com");
    const adminSid = fx.makeSession("admin");
    const res = await fx.handler(
      jsonReq("/admin/users/set-role", { userId: "u", role: "moderator" }, adminSid),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { attributes: { role: string } }).attributes.role).toBe(
      "moderator",
    );
  });
});

describe("HTTP api-key endpoints", () => {
  it("creates, lists, updates, and deletes keys", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    const created = await fx.handler(jsonReq("/api-keys", { name: "CI" }, sid));
    expect(created.status).toBe(200);
    const body = (await created.json()) as { key: string; apiKey: { id: string; name: string } };
    expect(typeof body.key).toBe("string");
    expect(body.apiKey.name).toBe("CI");
    const keyId = body.apiKey.id;

    const list = await fx.handler(req("GET", "/api-keys", sid));
    expect(((await list.json()) as unknown[]).length).toBe(1);

    const updated = await fx.handler(req("PATCH", `/api-keys/${keyId}`, sid, { enabled: false }));
    expect(((await updated.json()) as { enabled: boolean }).enabled).toBe(false);

    const deleted = await fx.handler(req("DELETE", `/api-keys/${keyId}`, sid));
    expect(deleted.status).toBe(204);
    const empty = await fx.handler(req("GET", "/api-keys", sid));
    expect(((await empty.json()) as unknown[]).length).toBe(0);
  });
});

describe("HTTP JWT endpoints", () => {
  it("issues a token that verifies against the JWKS", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    const tokenRes = await fx.handler(req("GET", "/token", sid));
    expect(tokenRes.status).toBe(200);
    const { token } = (await tokenRes.json()) as { token: string };

    const jwksRes = await fx.handler(req("GET", "/jwks"));
    expect(jwksRes.status).toBe(200);
    const { keys } = (await jwksRes.json()) as { keys: Array<Record<string, unknown>> };
    expect(keys.length).toBe(1);

    // Verify the ES256 signature against the published JWK.
    const [headerSeg, payloadSeg, sigSeg] = token.split(".") as [string, string, string];
    const header = JSON.parse(Buffer.from(headerSeg, "base64url").toString("utf8")) as {
      kid: string;
      alg: string;
    };
    expect(header.alg).toBe("ES256");
    const jwk = keys.find((k) => k["kid"] === header.kid);
    expect(jwk).toBeDefined();
    const valid = Cipher.verifyJws(
      "ES256",
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      Buffer.from(sigSeg, "base64url"),
      jwk!,
    );
    expect(valid).toBe(true);

    const payload = JSON.parse(Buffer.from(payloadSeg, "base64url").toString("utf8")) as {
      sub: string;
      iss: string;
    };
    expect(payload.sub).toBe("u");
    expect(payload.iss).toBe("https://auth.test");
  });
});
