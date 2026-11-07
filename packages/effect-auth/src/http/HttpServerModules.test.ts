import { assert, describe, it, expect } from "vite-plus/test";
import {
  Array as Arr,
  Clock,
  DateTime,
  Effect,
  Layer,
  MutableHashMap,
  MutableHashSet,
  Option,
  Predicate,
  Schema,
} from "effect";
import * as Cipher from "../Cipher.ts";
import { type AuthServices } from "./HttpServer.ts";
import * as HttpServer from "./HttpServer.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import { SessionService } from "../SessionService.ts";
import { hashToken } from "../TokenHash.ts";
import { UserServiceStore, UserService } from "../User.ts";
import { Hooks } from "../Hooks.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { EmailPasswordService, EmailPasswordStore } from "../email/EmailPassword.ts";
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
  type OrgRole,
  OrganizationService,
} from "../Organization.ts";
import { AdminUserStore, AdminService } from "../Admin.ts";
import { ApiKeyStore, type ApiKey, ApiKeyService } from "../ApiKey.ts";
import { JwtKeyStore, type JwtKeyPair, JwtService } from "../Jwt.ts";
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
  const usersById = MutableHashMap.empty<string, Types.User>();
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const sessions = MutableHashMap.empty<string, Types.Session>();
  const orgs = MutableHashMap.empty<string, Organization>();
  const members: Member[] = [];
  const invitations = MutableHashMap.empty<string, Invitation>();
  const teams = MutableHashMap.empty<string, Team>();
  const teamMembers: TeamMember[] = [];
  const removeTeamMembers = (teamId: string): void => {
    const kept = teamMembers.filter((m) => m.teamId !== teamId);
    teamMembers.splice(0, teamMembers.length, ...kept);
  };
  const orgRoles = MutableHashMap.empty<string, OrgRole>();
  const apiKeys = MutableHashMap.empty<string, ApiKey>();
  const jwtKeys: JwtKeyPair[] = [];

  const seedUser = (id: string, email: string, attributes: Types.Attributes = {}) => {
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    const user: Types.User = {
      id,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    MutableHashMap.set(usersById, id, user);
    // The login handle lives in the identifier store (verified email).
    const identifier = makeIdentifier({
      userId: id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
      now,
    });
    MutableHashMap.set(identifierRecords, identifier.id, identifier);
    return user;
  };

  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).toString(
      "hex",
    );
    const tokenHash = hashToken(rawToken);
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(sessions, tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: HOUR })),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore = {
    get: (userId: string) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(usersById, userId))),
  };

  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) =>
      Effect.sync(() => {
        MutableHashMap.set(usersById, user.id, user);
        return user;
      }),
    delete: (userId: string) => Effect.sync(() => void MutableHashMap.remove(usersById, userId)),
  };

  const sessionStore: typeof SessionStore.Service = {
    create: (session: Types.Session) =>
      Effect.sync(() => {
        MutableHashMap.set(sessions, session.id, session);
        return session;
      }),
    get: (sessionId: string) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
    update: (session: Types.Session) =>
      Effect.sync(() => {
        MutableHashMap.set(sessions, session.id, session);
        return session;
      }),
    delete: (sessionId: string) =>
      Effect.sync(() => void MutableHashMap.remove(sessions, sessionId)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        MutableHashMap.forEach(sessions, (s, id) => {
          if (s.userId === userId) MutableHashMap.remove(sessions, id);
        });
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
      ),
  };

  const orgStore = {
    createOrganization: (o: Organization) =>
      Effect.sync(() => (MutableHashMap.set(orgs, o.id, o), o)),
    getOrganizationById: (id: string) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(orgs, id))),
    getOrganizationBySlug: (slug: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgs)).find((o) => o.slug === slug) ?? null,
      ),
    updateOrganization: (o: Organization) =>
      Effect.sync(() => (MutableHashMap.set(orgs, o.id, o), o)),
    deleteOrganization: (id: string) =>
      Effect.sync(() => {
        MutableHashMap.remove(orgs, id);
        MutableHashMap.forEach(orgRoles, (orgRole, key) => {
          if (orgRole.organizationId === id) MutableHashMap.remove(orgRoles, key);
        });
        MutableHashMap.forEach(teams, (team, teamId) => {
          if (team.organizationId !== id) return;
          MutableHashMap.remove(teams, teamId);
          removeTeamMembers(teamId);
        });
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
    createInvitation: (inv: Invitation) =>
      Effect.sync(() => (MutableHashMap.set(invitations, inv.id, inv), inv)),
    getInvitation: (id: string) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(invitations, id))),
    updateInvitation: (inv: Invitation) =>
      Effect.sync(() => (MutableHashMap.set(invitations, inv.id, inv), inv)),
    listInvitationsByOrganization: (organizationId: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(invitations)).filter(
          (i) => i.organizationId === organizationId,
        ),
      ),
    listInvitationsByEmail: (email: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(invitations)).filter((i) => i.email === email),
      ),
    createTeam: (t: Team) => Effect.sync(() => (MutableHashMap.set(teams, t.id, t), t)),
    getTeam: (teamId: string) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(teams, teamId))),
    updateTeam: (t: Team) =>
      Effect.sync(() => {
        if (!MutableHashMap.has(teams, t.id)) return null;
        MutableHashMap.set(teams, t.id, t);
        return t;
      }),
    deleteTeam: (teamId: string) =>
      Effect.sync(() => {
        MutableHashMap.remove(teams, teamId);
        removeTeamMembers(teamId);
      }),
    listTeams: (organizationId: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(teams)).filter(
          (t) => t.organizationId === organizationId,
        ),
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
        const i = teamMembers.findIndex((m) => m.teamId === teamId && m.userId === userId);
        if (i >= 0) teamMembers.splice(i, 1);
      }),
    listTeamMembers: (teamId: string) =>
      Effect.succeed(teamMembers.filter((m) => m.teamId === teamId)),
    listTeamsForMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        teamMembers
          .filter((m) => m.userId === userId)
          .map((m) => Option.getOrUndefined(MutableHashMap.get(teams, m.teamId)))
          .filter((t): t is Team => t !== undefined && t.organizationId === organizationId),
      ),
    upsertOrgRole: (r: OrgRole) =>
      Effect.sync(() => (MutableHashMap.set(orgRoles, `${r.organizationId} ${r.role}`, r), r)),
    getOrgRole: (organizationId: string, role: string) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(orgRoles, `${organizationId} ${role}`))),
    listOrgRoles: (organizationId: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgRoles)).filter(
          (r) => r.organizationId === organizationId,
        ),
      ),
    deleteOrgRole: (organizationId: string, role: string) =>
      Effect.sync(() => void MutableHashMap.remove(orgRoles, `${organizationId} ${role}`)),
  };

  const adminUserStore = {
    listUsers: (query: { limit?: number; offset?: number; searchEmail?: string }) =>
      Effect.sync(() => {
        let all = Arr.fromIterable(MutableHashMap.values(usersById));
        if (query.searchEmail !== undefined) {
          // Emails live in the identifier store now; search resolves through it.
          const needle = query.searchEmail.toLowerCase();
          const matching = MutableHashSet.fromIterable(
            Arr.fromIterable(MutableHashMap.values(identifierRecords))
              .filter((i) => i.type === "email" && i.value.toLowerCase().includes(needle))
              .map((i) => i.userId),
          );
          all = all.filter((u) => MutableHashSet.has(matching, u.id));
        }
        const total = all.length;
        const offset = query.offset ?? 0;
        const limit = query.limit ?? all.length;
        return { users: all.slice(offset, offset + limit), total };
      }),

    createUser: (input: { name?: string; image?: string; attributes?: Types.Attributes }) =>
      Effect.sync(() => {
        const id = `created-${DateTime.toEpochMillis(DateTime.nowUnsafe())}`;
        const user: Types.User = {
          id,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          attributes: input.attributes ?? {},
        };
        MutableHashMap.set(usersById, id, user);
        return { user, created: true };
      }),

    setPasswordHash: (_userId: string, _hash: string) => Effect.void,
  };

  const apiKeyStore = {
    create: (k: ApiKey) => Effect.sync(() => (MutableHashMap.set(apiKeys, k.id, k), k)),
    get: (id: string) => Effect.succeed(Option.getOrNull(MutableHashMap.get(apiKeys, id))),
    getByHash: (keyHash: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(apiKeys)).find((k) => k.keyHash === keyHash) ?? null,
      ),
    update: (k: ApiKey) => Effect.sync(() => (MutableHashMap.set(apiKeys, k.id, k), k)),
    delete: (id: string) => Effect.sync(() => void MutableHashMap.remove(apiKeys, id)),
    listByUserId: (userId: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(apiKeys)).filter((k) => k.userId === userId),
      ),
  };

  const jwtKeyStore = {
    getActive: () => Effect.succeed(jwtKeys[0] ?? null),
    create: (pair: JwtKeyPair) => Effect.sync(() => (jwtKeys.push(pair), pair)),
    list: () => Effect.succeed(jwtKeys),
  };

  // In-memory RateLimitStore: ApiKeyService resolves RateLimiter at construction
  // time even though these tests never exercise rate-limited paths.
  const rateLimitEntries = MutableHashMap.empty<string, RateLimitEntry>();
  const rateLimitStore = {
    get: (key: string) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(rateLimitEntries, key))),
    set: (key: string, entry: RateLimitEntry, _ttl: number) =>
      Effect.sync(() => void MutableHashMap.set(rateLimitEntries, key, entry)),
    increment: (key: string, ttl: number) =>
      // Starts a new window when there is none or it has expired, as the
      // RateLimitStore contract requires (#455).
      Effect.flatMap(Clock.currentTimeMillis, (now) =>
        Effect.sync(() => {
          const entry = Option.getOrUndefined(MutableHashMap.get(rateLimitEntries, key));
          const next: RateLimitEntry =
            entry === undefined || now >= entry.resetAt
              ? { key, count: 1, resetAt: now + ttl * 1000 }
              : { ...entry, count: entry.count + 1 };
          MutableHashMap.set(rateLimitEntries, key, next);
          return next.count;
        }),
      ),
    delete: (key: string) => Effect.sync(() => void MutableHashMap.remove(rateLimitEntries, key)),
  };

  // Stage 0: raw stores + Hooks + dummy layers for AuthServices members these
  // tests never exercise.
  // SAFETY: the `undefined` services complete `AuthServices` for `HttpServer.make`;
  // the org/admin/api-key/jwt handlers these tests drive never touch them.
  const storesLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(OrganizationStore)(orgStore),
    Layer.succeed(AdminUserStore)(adminUserStore),
    Layer.succeed(ApiKeyStore)(apiKeyStore),
    Layer.succeed(JwtKeyStore)(jwtKeyStore),
    Layer.succeed(RateLimitStore)(rateLimitStore),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(identifierRecords)),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
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
  const apiKeyServiceLayer = ApiKeyService.layer().pipe(Layer.provide(stage1));
  const jwtServiceLayer = JwtService.layer({ issuer: "https://auth.test" }).pipe(
    Layer.provide(stage1),
  );

  const services: Layer.Layer<AuthServices> = Layer.mergeAll(
    stage1,
    organizationServiceLayer,
    adminServiceLayer,
    apiKeyServiceLayer,
    jwtServiceLayer,
  );
  const { handler } = HttpServer.make({ services, cookie: { secure: false } });

  return { handler, seedUser, makeSession, sessions };
};

const withCookie = (sessionId: string) => ({ cookie: `conduit_session=${sessionId}` });

/** A JSON request body, as the wire carries it. */
const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A JSON response body, decoded against the shape the test reads from it. */
const jsonBody = async <S extends Schema.ConstraintDecoder<unknown>>(
  response: Response,
  schema: S,
): Promise<S["Type"]> => Schema.decodeUnknownSync(schema)(await response.json());

// The response bodies several tests read.
const IdBody = Schema.Struct({ id: Schema.String });
const IdListBody = Schema.Array(IdBody);
const NameBody = Schema.Struct({ name: Schema.String });
/** A JSON array, read for its length. */
const ListBody = Schema.Array(Schema.Unknown);

// Same raw session token, delivered as `Authorization: Bearer` instead of
// the cookie — the "machine" credential path (`credentialClassFromRequest`).
const jsonReqBearer = (path: string, body: Schema.Json, sessionId: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${sessionId}` },
    body: toJson(body),
  });

const jsonReq = (path: string, body: Schema.Json, sessionId?: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sessionId !== undefined ? withCookie(sessionId) : {}),
    },
    body: toJson(body),
  });

const req = (method: string, path: string, sessionId?: string, body?: Schema.Json): Request =>
  new Request(`http://test${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(sessionId !== undefined ? withCookie(sessionId) : {}),
    },
    ...(body !== undefined ? { body: toJson(body) } : {}),
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
    const org = await jsonBody(created, Schema.Struct({ id: Schema.String, slug: Schema.String }));
    expect(org.slug).toBe("acme");

    // Full org includes the creator as an owner member.
    const full = await fx.handler(req("GET", `/organization/${org.id}`, sid));
    expect(full.status).toBe(200);
    const fullBody = await jsonBody(
      full,
      Schema.Struct({
        organization: Schema.Struct({ id: Schema.String }),
        members: Schema.Array(Schema.Struct({ userId: Schema.String, role: Schema.String })),
      }),
    );
    expect(fullBody.members).toEqual([{ ...fullBody.members[0], userId: "u1", role: "owner" }]);

    // List shows the org.
    const list = await fx.handler(req("GET", "/organizations", sid));
    expect((await jsonBody(list, IdListBody)).map((o) => o.id)).toEqual([org.id]);

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
    expect((await jsonBody(listInv, ListBody)).length).toBe(1);

    // Update.
    const updated = await fx.handler(
      req("PATCH", `/organization/${org.id}`, sid, { name: "Acme Inc" }),
    );
    expect((await jsonBody(updated, NameBody)).name).toBe("Acme Inc");

    // Set active organization (stored on the session).
    const active = await fx.handler(
      jsonReq("/organization/set-active", { organizationId: org.id }, sid),
    );
    expect(active.status).toBe(200);
    expect(
      Option.getOrUndefined(MutableHashMap.get(fx.sessions, hashToken(sid)))?.attributes[
        "activeOrganizationId"
      ],
    ).toBe(org.id);

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
    const org = await jsonBody(created, IdBody);

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
    const org = await jsonBody(created, IdBody);
    await fx.handler(
      jsonReq(`/organization/${org.id}/members`, { userId: "member", role: "member" }, ownerSid),
    );

    // Create.
    const teamRes = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Engineering" }, ownerSid),
    );
    expect(teamRes.status).toBe(200);
    const team = await jsonBody(
      teamRes,
      Schema.Struct({ id: Schema.String, name: Schema.String, organizationId: Schema.String }),
    );
    expect(team.name).toBe("Engineering");
    expect(team.organizationId).toBe(org.id);

    // Any organization member may list.
    const listed = await fx.handler(req("GET", `/organization/${org.id}/teams`, memberSid));
    expect((await jsonBody(listed, IdListBody)).map((t) => t.id)).toEqual([team.id]);

    // Add + list team members.
    const added = await fx.handler(
      jsonReq(`/teams/${team.id}/members`, { userId: "member" }, ownerSid),
    );
    expect(added.status).toBe(200);
    expect(await added.json()).toMatchObject({
      teamId: team.id,
      userId: "member",
    });

    const teamMembersRes = await fx.handler(req("GET", `/teams/${team.id}/members`, memberSid));
    expect(
      (await jsonBody(teamMembersRes, Schema.Array(Schema.Struct({ userId: Schema.String })))).map(
        (m) => m.userId,
      ),
    ).toEqual(["member"]);

    const forMember = await fx.handler(
      req("GET", `/organization/${org.id}/members/member/teams`, memberSid),
    );
    expect((await jsonBody(forMember, IdListBody)).map((t) => t.id)).toEqual([team.id]);

    // Rename.
    const renamed = await fx.handler(
      req("PATCH", `/teams/${team.id}`, ownerSid, { name: "Platform" }),
    );
    expect((await jsonBody(renamed, NameBody)).name).toBe("Platform");

    // Remove the team member, then the team.
    const removed = await fx.handler(req("DELETE", `/teams/${team.id}/members/member`, ownerSid));
    expect(removed.status).toBe(204);
    const emptied = await fx.handler(req("GET", `/teams/${team.id}/members`, ownerSid));
    expect((await jsonBody(emptied, ListBody)).length).toBe(0);

    const deleted = await fx.handler(req("DELETE", `/teams/${team.id}`, ownerSid));
    expect(deleted.status).toBe(204);
    const afterDelete = await fx.handler(req("GET", `/organization/${org.id}/teams`, ownerSid));
    expect((await jsonBody(afterDelete, ListBody)).length).toBe(0);
  });

  it("manages custom organization roles", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, ownerSid),
    );
    const org = await jsonBody(created, IdBody);
    await fx.handler(
      jsonReq(`/organization/${org.id}/members`, { userId: "member", role: "member" }, ownerSid),
    );

    // Define a custom `member` role that may create teams.
    const upserted = await fx.handler(
      req("PUT", `/organization/${org.id}/roles/member`, ownerSid, {
        permissions: ["team:create"],
      }),
    );
    expect(upserted.status).toBe(200);
    expect(await upserted.json()).toMatchObject({
      organizationId: org.id,
      role: "member",
      permissions: ["team:create"],
    });

    // Any member may list the definitions...
    const listed = await fx.handler(req("GET", `/organization/${org.id}/roles`, memberSid));
    expect(listed.status).toBe(200);
    expect(
      (await jsonBody(listed, Schema.Array(Schema.Struct({ role: Schema.String })))).map(
        (r) => r.role,
      ),
    ).toEqual(["member"]);

    // ...and the new permission is live for that member.
    const teamRes = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Engineering" }, memberSid),
    );
    expect(teamRes.status).toBe(200);

    // Deleting the definition restores the static (permission-less) role.
    const deleted = await fx.handler(
      req("DELETE", `/organization/${org.id}/roles/member`, ownerSid),
    );
    expect(deleted.status).toBe(204);
    const afterDelete = await fx.handler(
      jsonReq(`/organization/${org.id}/teams`, { name: "Rogue" }, memberSid),
    );
    expect(afterDelete.status).toBe(403);
  });

  it("returns 403 for role management without role:manage and for the owner role", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("admin", "admin@test.com");
    const ownerSid = fx.makeSession("owner");
    const adminSid = fx.makeSession("admin");

    const created = await fx.handler(
      jsonReq("/organization/create", { name: "Acme", slug: "acme" }, ownerSid),
    );
    const org = await jsonBody(created, IdBody);
    await fx.handler(
      jsonReq(`/organization/${org.id}/members`, { userId: "admin", role: "admin" }, ownerSid),
    );

    // `role:manage` is owner-only by default.
    const adminUpsert = await fx.handler(
      req("PUT", `/organization/${org.id}/roles/auditor`, adminSid, {
        permissions: ["team:create"],
      }),
    );
    expect(adminUpsert.status).toBe(403);
    const adminDelete = await fx.handler(
      req("DELETE", `/organization/${org.id}/roles/auditor`, adminSid),
    );
    expect(adminDelete.status).toBe(403);

    // The owner role is protected even for the owner.
    const ownerRoleUpsert = await fx.handler(
      req("PUT", `/organization/${org.id}/roles/owner`, ownerSid, { permissions: ["*:*"] }),
    );
    expect(ownerRoleUpsert.status).toBe(403);

    // Non-members cannot even list.
    fx.seedUser("stranger", "stranger@test.com");
    const strangerSid = fx.makeSession("stranger");
    const strangerList = await fx.handler(req("GET", `/organization/${org.id}/roles`, strangerSid));
    expect(strangerList.status).toBe(403);
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
    const org = await jsonBody(created, IdBody);
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
    const team = await jsonBody(teamRes, IdBody);

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
    expect(
      (
        await jsonBody(
          banned,
          Schema.Struct({ attributes: Schema.Struct({ banned: Schema.Boolean }) }),
        )
      ).attributes.banned,
    ).toBe(true);

    // The victim's session was revoked.
    const check = await fx.handler(req("GET", "/sessions/current?include=user", victimSid));
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
    expect(
      (await jsonBody(res, Schema.Struct({ attributes: Schema.Struct({ role: Schema.String }) })))
        .attributes.role,
    ).toBe("moderator");
  });
});

describe("HTTP api-key endpoints", () => {
  it("rejects minting a key over a machine (bearer) credential, and allows it over the session cookie", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    // Same valid, unexpired session token — but presented as a bearer
    // credential rather than the cookie. `apiKeyCreate` requires an
    // interactive session, so this is a 403, not a 401: the caller is
    // authenticated, just not with a credential class allowed to mint.
    const deniedOverBearer = await fx.handler(jsonReqBearer("/api-keys", { name: "CI" }, sid));
    expect(deniedOverBearer.status).toBe(403);

    const allowedOverCookie = await fx.handler(jsonReq("/api-keys", { name: "CI" }, sid));
    expect(allowedOverCookie.status).toBe(200);
  });

  it("creates, lists, updates, and deletes keys", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    const created = await fx.handler(jsonReq("/api-keys", { name: "CI" }, sid));
    expect(created.status).toBe(200);
    const body = await jsonBody(
      created,
      Schema.Struct({
        key: Schema.String,
        apiKey: Schema.Struct({ id: Schema.String, name: Schema.String }),
      }),
    );
    expect(Predicate.isString(body.key)).toBe(true);
    expect(body.apiKey.name).toBe("CI");
    const keyId = body.apiKey.id;

    const list = await fx.handler(req("GET", "/api-keys", sid));
    expect((await jsonBody(list, ListBody)).length).toBe(1);

    const updated = await fx.handler(req("PATCH", `/api-keys/${keyId}`, sid, { enabled: false }));
    expect((await jsonBody(updated, Schema.Struct({ enabled: Schema.Boolean }))).enabled).toBe(
      false,
    );

    const deleted = await fx.handler(req("DELETE", `/api-keys/${keyId}`, sid));
    expect(deleted.status).toBe(204);
    const empty = await fx.handler(req("GET", "/api-keys", sid));
    expect((await jsonBody(empty, ListBody)).length).toBe(0);
  });
});

/** The parts of the JWKS, a JWS header and the JWT claims the JWT test reads. */
const Jwks = Schema.Struct({ keys: Schema.Array(Schema.Record(Schema.String, Schema.Json)) });
const JwsHeader = Schema.fromJsonString(Schema.Struct({ kid: Schema.String, alg: Schema.String }));
/** A compact JWS: header, payload and signature. */
const JwsSegments = Schema.Tuple([Schema.String, Schema.String, Schema.String]);
const JwtClaims = Schema.fromJsonString(Schema.Struct({ sub: Schema.String, iss: Schema.String }));

describe("HTTP JWT endpoints", () => {
  it("issues a token that verifies against the JWKS", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    const tokenRes = await fx.handler(req("GET", "/token", sid));
    expect(tokenRes.status).toBe(200);
    const { token } = await jsonBody(tokenRes, Schema.Struct({ token: Schema.String }));

    const jwksRes = await fx.handler(req("GET", "/jwks"));
    expect(jwksRes.status).toBe(200);
    const { keys } = Schema.decodeUnknownSync(Jwks)(await jwksRes.json());
    expect(keys.length).toBe(1);

    // Verify the ES256 signature against the published JWK.
    const [headerSeg, payloadSeg, sigSeg] = Schema.decodeUnknownSync(JwsSegments)(token.split("."));
    const header = Schema.decodeUnknownSync(JwsHeader)(
      Buffer.from(headerSeg, "base64url").toString("utf8"),
    );
    expect(header.alg).toBe("ES256");
    const jwk = keys.find((k) => k["kid"] === header.kid);
    assert(jwk !== undefined, "the token's kid is published");
    const valid = Cipher.verifyJws(
      "ES256",
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      Buffer.from(sigSeg, "base64url"),
      jwk,
    );
    expect(valid).toBe(true);

    const payload = Schema.decodeUnknownSync(JwtClaims)(
      Buffer.from(payloadSeg, "base64url").toString("utf8"),
    );
    expect(payload.sub).toBe("u");
    expect(payload.iss).toBe("https://auth.test");
  });
});
