import { assert, describe, it, expect } from "vite-plus/test";
import { Clock, DateTime, Effect, Layer, MutableHashMap, MutableHashSet } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
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
  type InvitationDelivery,
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
import { expectSpecJson } from "../testing/WireFormat.ts";

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
    getMemberById: (memberId: string) =>
      Effect.succeed(members.find((m) => m.id === memberId) ?? null),
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
    addTeamMember: (teamMember: TeamMember) =>
      Effect.sync(() => (teamMembers.push(teamMember), teamMember)),
    getTeamMemberById: (teamMemberId: string) =>
      Effect.succeed(teamMembers.find((m) => m.id === teamMemberId) ?? null),
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
    getOrgRoleById: (orgRoleId: string) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgRoles)).find((r) => r.id === orgRoleId) ?? null,
      ),
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
  // Invitations the server "emailed", with their secret tokens (newest last).
  const sentInvitations: InvitationDelivery[] = [];
  const organizationServiceLayer = OrganizationService.layer({
    sendInvitationEmail: (delivery) => Effect.sync(() => void sentInvitations.push(delivery)),
  }).pipe(Layer.provide(stage1));
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

  /** The token the invitation's latest email carried. */
  const tokenFor = (invitationId: string): string =>
    Option.match(
      Arr.findLast(sentInvitations, (sent) => sent.invitation.id === invitationId),
      { onNone: () => assert.fail(`no email for ${invitationId}`), onSome: (sent) => sent.token },
    );

  return { handler, seedUser, makeSession, sessions, members, tokenFor };
};

const withCookie = (sessionId: string) => ({ cookie: `conduit_session=${sessionId}` });

/** A JSON request body, as the wire carries it. */
const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A JSON response body, decoded against the shape the test reads from it. */
const jsonBody = async <S extends Schema.ConstraintDecoder<unknown>>(
  response: Response,
  schema: S,
): Promise<S["Type"]> => Schema.decodeUnknownSync(schema)(await response.json());

// Same raw session token, delivered as `Authorization: Bearer` instead of
// the cookie — the "machine" credential path (`credentialClassFromRequest`).
const apiReqBearer = (path: string, body: Schema.Json, sessionId: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/vnd.api+json",
      authorization: `Bearer ${sessionId}`,
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

/** A JSON:API request (`application/vnd.api+json`), signed in as `sessionId` when given. */
const apiReq = (method: string, path: string, body?: Schema.Json, sessionId?: string): Request =>
  new Request(`http://test${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/vnd.api+json" } : {}),
      ...(sessionId !== undefined ? withCookie(sessionId) : {}),
    },
    ...(body !== undefined ? { body: toJson(body) } : {}),
  });

/** One JSON:API resource object, read for its id and the attributes a test names. */
const resourceBody = <F extends Schema.Struct.Fields>(attributes: F) =>
  Schema.Struct({
    data: Schema.Struct({ id: Schema.String, attributes: Schema.Struct(attributes) }),
  });

/** A JSON:API collection, read for each resource's id and the attributes a test names. */
const collectionBody = <F extends Schema.Struct.Fields>(attributes: F) =>
  Schema.Struct({
    data: Schema.Array(Schema.Struct({ id: Schema.String, attributes: Schema.Struct(attributes) })),
  });

/** `POST /organizations` as `sessionId`; answers the new organization's id. */
const createOrganization = async (
  fx: ReturnType<typeof makeFixture>,
  sessionId: string,
  name = "Acme",
  slug = "acme",
): Promise<{ readonly id: string }> => {
  const created = await fx.handler(
    apiReq(
      "POST",
      "/organizations",
      { data: { type: "organizations", attributes: { name, slug } } },
      sessionId,
    ),
  );
  expect(created.status).toBe(201);
  return (await jsonBody(created, resourceBody({}))).data;
};

/** `POST /organizations/:id/members` as `sessionId`; answers the response. */
const addMemberRequest = (
  organizationId: string,
  userId: string,
  role: string,
  sessionId: string,
) =>
  apiReq(
    "POST",
    `/organizations/${organizationId}/members`,
    {
      data: {
        type: "organization-members",
        attributes: { role },
        relationships: { user: { data: { type: "users", id: userId } } },
      },
    },
    sessionId,
  );

/** `PATCH /organization-members/:id` with `attributes`, as `sessionId`. */
const patchMember = (memberId: string, attributes: Schema.Json, sessionId: string) =>
  apiReq(
    "PATCH",
    `/organization-members/${memberId}`,
    { data: { type: "organization-members", id: memberId, attributes } },
    sessionId,
  );

/** `PATCH /invitations/:id` to `status`, as `sessionId`, presenting `token` when given. */
const transitionInvitation = (
  invitationId: string,
  status: string,
  sessionId: string,
  token?: string,
) =>
  apiReq(
    "PATCH",
    `/invitations/${invitationId}`,
    {
      data: {
        type: "invitations",
        id: invitationId,
        attributes: token === undefined ? { status } : { status, token },
      },
    },
    sessionId,
  );

const MemberBody = resourceBody({
  role: Schema.String,
  status: Schema.String,
  previousRole: Schema.optionalKey(Schema.String),
});

/** A linkage to one resource, as a relationship's `data`. */
const Linkage = Schema.Struct({ data: Schema.Struct({ type: Schema.String, id: Schema.String }) });

/** One resource read for its id alone. */
const IdData = Schema.Struct({ data: Schema.Struct({ id: Schema.String }) });

/** A team, a role or a domain: its attributes, and the organization it belongs to. */
const OwnedBody = Schema.Struct({
  data: Schema.Struct({
    id: Schema.String,
    attributes: Schema.Struct({ name: Schema.optionalKey(Schema.String) }),
    relationships: Schema.Struct({ organization: Linkage }),
  }),
});

/** A `team-members` resource: its team and user. */
const TeamMemberBody = Schema.Struct({
  data: Schema.Struct({
    id: Schema.String,
    relationships: Schema.Struct({ team: Linkage, user: Linkage }),
  }),
});

/** `POST /organizations/:id/teams` as `sessionId`. */
const createTeamRequest = (organizationId: string, name: string, sessionId: string) =>
  apiReq(
    "POST",
    `/organizations/${organizationId}/teams`,
    { data: { type: "teams", attributes: { name } } },
    sessionId,
  );

/** `POST /organizations/:id/roles` as `sessionId`. */
const createRoleRequest = (
  organizationId: string,
  role: string,
  permissions: ReadonlyArray<string>,
  sessionId: string,
) =>
  apiReq(
    "POST",
    `/organizations/${organizationId}/roles`,
    { data: { type: "organization-roles", attributes: { role, permissions: [...permissions] } } },
    sessionId,
  );

/** `PATCH /organization-roles/:id` with `attributes`, as `sessionId`. */
const patchRole = (roleId: string, attributes: Schema.Json, sessionId: string) =>
  apiReq(
    "PATCH",
    `/organization-roles/${roleId}`,
    { data: { type: "organization-roles", id: roleId, attributes } },
    sessionId,
  );

describe("HTTP organization endpoints", () => {
  it("runs a full organization lifecycle", async () => {
    const fx = makeFixture();
    fx.seedUser("u1", "owner@test.com");
    const sid = fx.makeSession("u1");

    // Create.
    const created = await fx.handler(
      apiReq(
        "POST",
        "/organizations",
        { data: { type: "organizations", attributes: { name: "Acme", slug: "acme" } } },
        sid,
      ),
    );
    expect(created.status).toBe(201);
    expect(created.headers.get("content-type")).toContain("application/vnd.api+json");
    const org = (
      await jsonBody(
        created,
        resourceBody({
          slug: Schema.String,
          defaultRole: Schema.String,
          jitProvisioning: Schema.Boolean,
        }),
      )
    ).data;
    expect(org.attributes).toEqual({ slug: "acme", defaultRole: "member", jitProvisioning: false });

    // Read it back, and its members: the creator, as an owner.
    const read = await fx.handler(apiReq("GET", `/organizations/${org.id}`, undefined, sid));
    expect((await jsonBody(read, resourceBody({ name: Schema.String }))).data.attributes.name).toBe(
      "Acme",
    );
    const members = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/members`, undefined, sid),
    );
    const memberList = await jsonBody(
      members,
      Schema.Struct({
        data: Schema.Array(
          Schema.Struct({
            id: Schema.String,
            attributes: Schema.Struct({ role: Schema.String }),
            relationships: Schema.Struct({
              user: Schema.Struct({ data: Schema.Struct({ id: Schema.String }) }),
            }),
          }),
        ),
      }),
    );
    expect(memberList.data.map((m) => [m.relationships.user.data.id, m.attributes.role])).toEqual([
      ["u1", "owner"],
    ]);
    // The member id is the stored one.
    expect(memberList.data[0]?.id).toBe(fx.members[0]?.id);

    // An unknown organization answers 404.
    expect((await fx.handler(apiReq("GET", "/organizations/nope", undefined, sid))).status).toBe(
      404,
    );

    // List shows the org.
    const list = await fx.handler(apiReq("GET", "/organizations", undefined, sid));
    expect((await jsonBody(list, collectionBody({}))).data.map((o) => o.id)).toEqual([org.id]);

    // Invite a member.
    const invited = await fx.handler(
      apiReq(
        "POST",
        `/organizations/${org.id}/invitations`,
        { data: { type: "invitations", attributes: { email: "new@test.com", role: "member" } } },
        sid,
      ),
    );
    expect(invited.status).toBe(201);
    const listInv = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/invitations`, undefined, sid),
    );
    expect((await jsonBody(listInv, collectionBody({ status: Schema.String }))).data).toHaveLength(
      1,
    );

    // Update, and the default role (owner-only) in the same document.
    const updated = await fx.handler(
      apiReq(
        "PATCH",
        `/organizations/${org.id}`,
        {
          data: {
            type: "organizations",
            id: org.id,
            attributes: { name: "Acme Inc", jitProvisioning: true, defaultRole: "admin" },
          },
        },
        sid,
      ),
    );
    expect(
      (
        await jsonBody(
          updated,
          resourceBody({
            name: Schema.String,
            jitProvisioning: Schema.Boolean,
            defaultRole: Schema.String,
          }),
        )
      ).data.attributes,
    ).toEqual({ name: "Acme Inc", jitProvisioning: true, defaultRole: "admin" });

    // Set the active organization (stored on the session), then clear it.
    const active = await fx.handler(
      apiReq(
        "PATCH",
        "/organizations/active",
        { data: { type: "organizations", id: org.id } },
        sid,
      ),
    );
    expect(active.status).toBe(204);
    const activeOrganization = () =>
      Option.getOrUndefined(MutableHashMap.get(fx.sessions, hashToken(sid)))?.attributes[
        "activeOrganizationId"
      ];
    expect(activeOrganization()).toBe(org.id);
    const cleared = await fx.handler(apiReq("PATCH", "/organizations/active", { data: null }, sid));
    expect(cleared.status).toBe(204);
    expect(activeOrganization()).toBeNull();

    // Delete.
    const deleted = await fx.handler(apiReq("DELETE", `/organizations/${org.id}`, undefined, sid));
    expect(deleted.status).toBe(204);
  });

  it("returns 403 when a non-member tries to update", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("stranger", "stranger@test.com");
    const ownerSid = fx.makeSession("owner");
    const strangerSid = fx.makeSession("stranger");

    const org = await createOrganization(fx, ownerSid);

    const res = await fx.handler(
      apiReq(
        "PATCH",
        `/organizations/${org.id}`,
        { data: { type: "organizations", id: org.id, attributes: { name: "Hijack" } } },
        strangerSid,
      ),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/vnd.api+json");
  });

  it("requires authentication", async () => {
    const fx = makeFixture();
    const res = await fx.handler(
      apiReq("POST", "/organizations", {
        data: { type: "organizations", attributes: { name: "A", slug: "a" } },
      }),
    );
    expect(res.status).toBe(401);
  });

  it("manages a membership by its id: role, deactivation, reactivation, removal", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("staff", "staff@test.com");
    fx.seedUser("stranger", "stranger@test.com");
    const ownerSid = fx.makeSession("owner");
    const strangerSid = fx.makeSession("stranger");
    const org = await createOrganization(fx, ownerSid);

    const added = await fx.handler(addMemberRequest(org.id, "staff", "admin", ownerSid));
    expect(added.status).toBe(201);
    const member = (await jsonBody(added, MemberBody)).data;
    expect(member.attributes).toMatchObject({ role: "admin", status: "active" });

    // A role change.
    const demoted = await fx.handler(patchMember(member.id, { role: "member" }, ownerSid));
    expect((await jsonBody(demoted, MemberBody)).data.attributes.role).toBe("member");

    // Deactivation keeps the role to restore; reactivation restores it.
    const deactivated = await fx.handler(patchMember(member.id, { status: "inactive" }, ownerSid));
    expect((await jsonBody(deactivated, MemberBody)).data.attributes).toMatchObject({
      status: "inactive",
      previousRole: "member",
    });
    const reactivated = await fx.handler(
      patchMember(member.id, { status: "active", role: "admin" }, ownerSid),
    );
    expect((await jsonBody(reactivated, MemberBody)).data.attributes).toMatchObject({
      status: "active",
      role: "admin",
    });

    // A stranger may neither change nor read back a membership, even by a
    // no-op patch; an unknown id is 404.
    expect((await fx.handler(patchMember(member.id, {}, strangerSid))).status).toBe(403);
    expect((await fx.handler(patchMember(member.id, { role: "owner" }, strangerSid))).status).toBe(
      403,
    );
    expect((await fx.handler(patchMember("unknown", { role: "member" }, ownerSid))).status).toBe(
      404,
    );
    expect(
      (
        await fx.handler(
          apiReq("DELETE", `/organization-members/${member.id}`, undefined, strangerSid),
        )
      ).status,
    ).toBe(403);

    // The last owner can be neither deactivated nor removed.
    const ownerMember = fx.members.find((m) => m.userId === "owner");
    assert(ownerMember !== undefined, "the owner is a member");
    expect(
      (await fx.handler(patchMember(ownerMember.id, { status: "inactive" }, ownerSid))).status,
    ).toBe(403);

    const removed = await fx.handler(
      apiReq("DELETE", `/organization-members/${member.id}`, undefined, ownerSid),
    );
    expect(removed.status).toBe(204);
    expect(fx.members.map((m) => m.userId)).toEqual(["owner"]);
  });

  it("moves invitations through their statuses and re-delivers them", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("invitee", "invitee@test.com");
    const ownerSid = fx.makeSession("owner");
    const inviteeSid = fx.makeSession("invitee");
    const org = await createOrganization(fx, ownerSid);

    const invite = async (email: string) => {
      const res = await fx.handler(
        apiReq(
          "POST",
          `/organizations/${org.id}/invitations`,
          { data: { type: "invitations", attributes: { email, role: "member" } } },
          ownerSid,
        ),
      );
      expect(res.status).toBe(201);
      return (await jsonBody(res, resourceBody({ status: Schema.String }))).data.id;
    };

    // Re-delivery: 202, the same invitation.
    const first = await invite("invitee@test.com");
    const delivered = await fx.handler(
      apiReq("POST", `/invitations/${first}/deliveries`, undefined, ownerSid),
    );
    expect(delivered.status).toBe(202);
    expect((await jsonBody(delivered, resourceBody({ status: Schema.String }))).data).toEqual({
      id: first,
      attributes: { status: "pending" },
    });

    // Only the invitee may accept, and only with the emailed token (#586);
    // the answer carries the new membership.
    const token = fx.tokenFor(first);
    expect(
      (await fx.handler(transitionInvitation(first, "accepted", ownerSid, token))).status,
    ).toBe(400);
    expect((await fx.handler(transitionInvitation(first, "accepted", inviteeSid))).status).toBe(
      400,
    );
    expect(
      (await fx.handler(transitionInvitation(first, "accepted", inviteeSid, "forged"))).status,
    ).toBe(400);
    expect(fx.members.some((m) => m.userId === "invitee")).toBe(false);
    const accepted = await fx.handler(transitionInvitation(first, "accepted", inviteeSid, token));
    expect(accepted.status).toBe(200);
    const acceptedBody = await jsonBody(
      accepted,
      Schema.Struct({
        data: Schema.Struct({ attributes: Schema.Struct({ status: Schema.String }) }),
        meta: Schema.Struct({
          membership: Schema.Struct({
            type: Schema.Literal("organization-members"),
            id: Schema.String,
            attributes: Schema.Struct({ role: Schema.String }),
          }),
        }),
      }),
    );
    expect(acceptedBody.data.attributes.status).toBe("accepted");
    expect(acceptedBody.meta.membership.attributes.role).toBe("member");
    expect(fx.members.find((m) => m.userId === "invitee")?.id).toBe(
      acceptedBody.meta.membership.id,
    );

    // Rejection by the invitee, cancellation by the owner.
    const second = await invite("invitee2@test.com");
    expect((await fx.handler(transitionInvitation(second, "canceled", inviteeSid))).status).toBe(
      403,
    );
    const canceled = await fx.handler(transitionInvitation(second, "canceled", ownerSid));
    expect(
      (await jsonBody(canceled, resourceBody({ status: Schema.String }))).data.attributes,
    ).toEqual({
      status: "canceled",
    });
    const third = await invite("invitee@test.com");
    expect((await fx.handler(transitionInvitation(third, "rejected", inviteeSid))).status).toBe(
      400,
    );
    const rejected = await fx.handler(
      transitionInvitation(third, "rejected", inviteeSid, fx.tokenFor(third)),
    );
    expect(
      (await jsonBody(rejected, resourceBody({ status: Schema.String }))).data.attributes,
    ).toEqual({
      status: "rejected",
    });

    // `pending` is not a transition.
    const fourth = await invite("invitee3@test.com");
    expect((await fx.handler(transitionInvitation(fourth, "pending", ownerSid))).status).toBe(400);
  });

  it("runs a full team lifecycle", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const org = await createOrganization(fx, ownerSid);
    const membership = (
      await jsonBody(
        await fx.handler(addMemberRequest(org.id, "member", "member", ownerSid)),
        MemberBody,
      )
    ).data;

    // Create.
    const teamRes = await fx.handler(createTeamRequest(org.id, "Engineering", ownerSid));
    expect(teamRes.status).toBe(201);
    expect(teamRes.headers.get("content-type")).toContain("application/vnd.api+json");
    const team = (await jsonBody(teamRes, OwnedBody)).data;
    expect(team.attributes.name).toBe("Engineering");
    expect(team.relationships.organization.data.id).toBe(org.id);

    // Any organization member may list.
    const listed = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/teams`, undefined, memberSid),
    );
    expect((await jsonBody(listed, collectionBody({}))).data.map((t) => t.id)).toEqual([team.id]);

    // Add + list team members: each membership has its own id.
    const added = await fx.handler(
      apiReq(
        "POST",
        `/teams/${team.id}/members`,
        {
          data: {
            type: "team-members",
            relationships: { user: { data: { type: "users", id: "member" } } },
          },
        },
        ownerSid,
      ),
    );
    expect(added.status).toBe(201);
    const teamMember = (await jsonBody(added, TeamMemberBody)).data;
    expect(teamMember.relationships).toEqual({
      team: { data: { type: "teams", id: team.id } },
      user: { data: { type: "users", id: "member" } },
    });

    const teamMembersRes = await fx.handler(
      apiReq("GET", `/teams/${team.id}/members`, undefined, memberSid),
    );
    expect((await jsonBody(teamMembersRes, collectionBody({}))).data.map((m) => m.id)).toEqual([
      teamMember.id,
    ]);

    // The member's teams, by the membership's id.
    const forMember = await fx.handler(
      apiReq("GET", `/organization-members/${membership.id}/teams`, undefined, memberSid),
    );
    expect((await jsonBody(forMember, collectionBody({}))).data.map((t) => t.id)).toEqual([
      team.id,
    ]);
    expect(
      (await fx.handler(apiReq("GET", "/organization-members/nope/teams", undefined, memberSid)))
        .status,
    ).toBe(404);

    // Rename.
    const renamed = await fx.handler(
      apiReq(
        "PATCH",
        `/teams/${team.id}`,
        { data: { type: "teams", id: team.id, attributes: { name: "Platform" } } },
        ownerSid,
      ),
    );
    expect(
      (await jsonBody(renamed, resourceBody({ name: Schema.String }))).data.attributes,
    ).toEqual({ name: "Platform" });

    // Remove the team member by its id, then the team.
    expect(
      (await fx.handler(apiReq("DELETE", "/team-members/nope", undefined, ownerSid))).status,
    ).toBe(404);
    const removed = await fx.handler(
      apiReq("DELETE", `/team-members/${teamMember.id}`, undefined, ownerSid),
    );
    expect(removed.status).toBe(204);
    const emptied = await fx.handler(
      apiReq("GET", `/teams/${team.id}/members`, undefined, ownerSid),
    );
    expect((await jsonBody(emptied, collectionBody({}))).data).toHaveLength(0);

    const deleted = await fx.handler(apiReq("DELETE", `/teams/${team.id}`, undefined, ownerSid));
    expect(deleted.status).toBe(204);
    const afterDelete = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/teams`, undefined, ownerSid),
    );
    expect((await jsonBody(afterDelete, collectionBody({}))).data).toHaveLength(0);
  });

  it("manages custom organization roles", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const org = await createOrganization(fx, ownerSid);
    await fx.handler(addMemberRequest(org.id, "member", "member", ownerSid));

    // Define a custom `member` role that may create teams.
    const created = await fx.handler(
      createRoleRequest(org.id, "member", ["team:create"], ownerSid),
    );
    expect(created.status).toBe(201);
    const role = (await jsonBody(created, OwnedBody)).data;
    expect(role.relationships.organization.data.id).toBe(org.id);
    expect(
      (
        await jsonBody(
          await fx.handler(createRoleRequest(org.id, "member", ["*:*"], ownerSid)),
          Schema.Struct({ errors: Schema.Array(Schema.Struct({ status: Schema.String })) }),
        )
      ).errors[0]?.status,
    ).toBe("409");

    // Any member may list the definitions...
    const listed = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/roles`, undefined, memberSid),
    );
    expect(listed.status).toBe(200);
    expect(
      (await jsonBody(listed, collectionBody({ role: Schema.String }))).data.map((r) => [
        r.id,
        r.attributes.role,
      ]),
    ).toEqual([[role.id, "member"]]);

    // ...and the new permission is live for that member.
    expect((await fx.handler(createTeamRequest(org.id, "Engineering", memberSid))).status).toBe(
      201,
    );

    // Changing the permissions keeps the definition's id.
    const updated = await fx.handler(patchRole(role.id, { permissions: [] }, ownerSid));
    expect(
      (await jsonBody(updated, resourceBody({ permissions: Schema.Array(Schema.String) }))).data,
    ).toEqual({ id: role.id, attributes: { permissions: [] } });
    expect((await fx.handler(createTeamRequest(org.id, "Design", memberSid))).status).toBe(403);

    // Deleting the definition restores the static (permission-less) role.
    const deleted = await fx.handler(
      apiReq("DELETE", `/organization-roles/${role.id}`, undefined, ownerSid),
    );
    expect(deleted.status).toBe(204);
    expect(
      (await fx.handler(apiReq("DELETE", `/organization-roles/${role.id}`, undefined, ownerSid)))
        .status,
    ).toBe(404);
    expect((await fx.handler(createTeamRequest(org.id, "Rogue", memberSid))).status).toBe(403);
  });

  it("returns 403 for role management without role:manage and for the owner role", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("admin", "admin@test.com");
    const ownerSid = fx.makeSession("owner");
    const adminSid = fx.makeSession("admin");

    const org = await createOrganization(fx, ownerSid);
    await fx.handler(addMemberRequest(org.id, "admin", "admin", ownerSid));

    // `role:manage` is owner-only by default.
    expect(
      (await fx.handler(createRoleRequest(org.id, "auditor", ["team:create"], adminSid))).status,
    ).toBe(403);
    const auditor = (
      await jsonBody(
        await fx.handler(createRoleRequest(org.id, "auditor", [], ownerSid)),
        OwnedBody,
      )
    ).data;
    expect(
      (await fx.handler(patchRole(auditor.id, { permissions: ["*:*"] }, adminSid))).status,
    ).toBe(403);
    expect((await fx.handler(patchRole(auditor.id, {}, adminSid))).status).toBe(403);
    expect(
      (await fx.handler(apiReq("DELETE", `/organization-roles/${auditor.id}`, undefined, adminSid)))
        .status,
    ).toBe(403);

    // The owner role is protected even for the owner.
    expect((await fx.handler(createRoleRequest(org.id, "owner", ["*:*"], ownerSid))).status).toBe(
      403,
    );

    // Non-members cannot even list.
    fx.seedUser("stranger", "stranger@test.com");
    const strangerSid = fx.makeSession("stranger");
    const strangerList = await fx.handler(
      apiReq("GET", `/organizations/${org.id}/roles`, undefined, strangerSid),
    );
    expect(strangerList.status).toBe(403);
  });

  it("returns 403 when a plain member tries to manage teams", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    fx.seedUser("member", "member@test.com");
    const ownerSid = fx.makeSession("owner");
    const memberSid = fx.makeSession("member");

    const org = await createOrganization(fx, ownerSid);
    await fx.handler(addMemberRequest(org.id, "member", "member", ownerSid));

    expect((await fx.handler(createTeamRequest(org.id, "Rogue", memberSid))).status).toBe(403);

    const team = (
      await jsonBody(await fx.handler(createTeamRequest(org.id, "Engineering", ownerSid)), IdData)
    ).data;

    const deniedAdd = await fx.handler(
      apiReq(
        "POST",
        `/teams/${team.id}/members`,
        {
          data: {
            type: "team-members",
            relationships: { user: { data: { type: "users", id: "member" } } },
          },
        },
        memberSid,
      ),
    );
    expect(deniedAdd.status).toBe(403);

    const deniedDelete = await fx.handler(
      apiReq("DELETE", `/teams/${team.id}`, undefined, memberSid),
    );
    expect(deniedDelete.status).toBe(403);
  });

  it("refuses domain requests when no OrganizationDomainStore is wired", async () => {
    const fx = makeFixture();
    fx.seedUser("owner", "owner@test.com");
    const ownerSid = fx.makeSession("owner");
    const org = await createOrganization(fx, ownerSid);

    // This fixture wires no OrganizationDomainStore: every domain request is
    // refused like any other, and an id cannot be resolved either.
    const claim = await fx.handler(
      apiReq(
        "POST",
        `/organizations/${org.id}/domains`,
        { data: { type: "organization-domains", attributes: { domain: "acme.test" } } },
        ownerSid,
      ),
    );
    expect(claim.status).toBe(403);
    expect(
      (
        await fx.handler(
          apiReq("POST", "/organization-domains/nope/verifications", undefined, ownerSid),
        )
      ).status,
    ).toBe(403);
    expect(
      (await fx.handler(apiReq("DELETE", "/organization-domains/nope", undefined, ownerSid)))
        .status,
    ).toBe(403);
  });
});

/** A `users` resource, read for its id and its `attributes` bag. */
const UserResource = Schema.Struct({
  id: Schema.String,
  attributes: Schema.Struct({ attributes: Schema.Record(Schema.String, Schema.Json) }),
});

/** The session token a response's `Set-Cookie` carries, if any. */
const sessionCookieOf = (response: Response): string | undefined =>
  /conduit_session=([^;]*)/.exec(response.headers.get("set-cookie") ?? "")?.[1];

/** A fixture with an admin and a plain user, each signed in. */
const adminFixture = () => {
  const fx = makeFixture();
  fx.seedUser("admin", "admin@test.com", { role: "admin" });
  fx.seedUser("u", "u@test.com");
  return { fx, adminSid: fx.makeSession("admin"), userSid: fx.makeSession("u") };
};

/** A to-one relationship naming user `userId`, as a write document carries it. */
const userLink = (userId: string) => ({ user: { data: { type: "users", id: userId } } });

describe("HTTP admin endpoints", () => {
  it("lists users, filtered by email and paged, and refuses non-admins", async () => {
    const { fx, adminSid, userSid } = adminFixture();
    fx.seedUser("v", "v@other.test");

    const all = await fx.handler(apiReq("GET", "/admin/users", undefined, adminSid));
    expect(all.status).toBe(200);
    const listed = await jsonBody(
      all,
      Schema.Struct({
        data: Schema.Array(UserResource),
        meta: Schema.Struct({ total: Schema.Finite }),
      }),
    );
    expect(listed.meta.total).toBe(3);

    const page = await fx.handler(
      apiReq(
        "GET",
        "/admin/users?filter%5Bemail%5D=test.com&page%5Boffset%5D=1&page%5Blimit%5D=1",
        undefined,
        adminSid,
      ),
    );
    expect(page.status).toBe(200);
    const paged = await jsonBody(
      page,
      Schema.Struct({
        data: Schema.Array(UserResource),
        meta: Schema.Struct({ total: Schema.Finite }),
      }),
    );
    // Two addresses match; the page holds the second.
    expect(paged.meta.total).toBe(2);
    expect(paged.data.length).toBe(1);

    expect((await fx.handler(apiReq("GET", "/admin/users", undefined, userSid))).status).toBe(403);
    expect((await fx.handler(apiReq("GET", "/admin/users"))).status).toBe(401);
    // The old command endpoint is gone.
    expect((await fx.handler(apiReq("POST", "/admin/users/list", {}, adminSid))).status).toBe(404);
  });

  it("sets a user's role, and answers 400 for an unknown user", async () => {
    const { fx, adminSid } = adminFixture();
    const setRole = (userId: string) =>
      fx.handler(
        apiReq(
          "PATCH",
          `/admin/users/${userId}`,
          { data: { type: "users", id: userId, attributes: { role: "moderator" } } },
          adminSid,
        ),
      );
    const res = await setRole("u");
    expect(res.status).toBe(200);
    const { data } = await jsonBody(res, Schema.Struct({ data: UserResource }));
    expect(data.attributes.attributes["role"]).toBe("moderator");
    expect((await setRole("nobody")).status).toBe(400);
  });

  it("bans a user (revoking their sessions) and lifts the ban", async () => {
    const { fx, adminSid, userSid } = adminFixture();
    const ban = (userId: string, sessionId: string) =>
      fx.handler(
        apiReq(
          "POST",
          "/user-bans",
          {
            data: {
              type: "user-bans",
              attributes: { reason: "spam", expiresIn: HOUR },
              relationships: userLink(userId),
            },
          },
          sessionId,
        ),
      );

    // A non-admin cannot ban, and nobody can ban an administrator.
    expect((await ban("admin", userSid)).status).toBe(403);
    expect((await ban("admin", adminSid)).status).toBe(403);

    const banned = await ban("u", adminSid);
    expect(banned.status).toBe(201);
    const document = await jsonBody(
      banned,
      Schema.Struct({
        data: Schema.Struct({
          id: Schema.String,
          attributes: Schema.Struct({ reason: Schema.String, expiresAt: Schema.Finite }),
        }),
        included: Schema.Array(UserResource),
      }),
    );
    expect(document.data.id).toBe("u");
    expect(document.data.attributes.reason).toBe("spam");
    expect(document.included[0]?.attributes.attributes["banned"]).toBe(true);

    // The banned user's session was revoked.
    expect((await fx.handler(req("GET", "/sessions/current", userSid))).status).toBe(401);

    const lifted = await fx.handler(apiReq("DELETE", "/user-bans/u", undefined, adminSid));
    expect(lifted.status).toBe(204);
    const after = await fx.handler(
      apiReq("GET", "/admin/users?filter%5Bemail%5D=u%40test.com", undefined, adminSid),
    );
    const { data } = await jsonBody(after, Schema.Struct({ data: Schema.Array(UserResource) }));
    expect(data[0]?.attributes.attributes["banned"]).toBe(false);
  });

  it("revokes a user's sessions and removes the user", async () => {
    const { fx, adminSid, userSid } = adminFixture();
    const revoked = await fx.handler(
      apiReq("DELETE", "/admin/users/u/sessions", undefined, adminSid),
    );
    expect(revoked.status).toBe(204);
    expect((await fx.handler(req("GET", "/sessions/current", userSid))).status).toBe(401);

    // An administrator cannot remove themselves.
    expect(
      (await fx.handler(apiReq("DELETE", "/admin/users/admin", undefined, adminSid))).status,
    ).toBe(403);
    const removed = await fx.handler(apiReq("DELETE", "/admin/users/u", undefined, adminSid));
    expect(removed.status).toBe(204);
    const left = await fx.handler(apiReq("GET", "/admin/users", undefined, adminSid));
    expect(
      (await jsonBody(left, Schema.Struct({ meta: Schema.Struct({ total: Schema.Finite }) }))).meta
        .total,
    ).toBe(1);
  });
});

describe("HTTP impersonation endpoints", () => {
  it("starts an impersonation as a session cookie and ends it", async () => {
    const { fx, adminSid, userSid } = adminFixture();
    const impersonate = (sessionId: string) =>
      fx.handler(
        apiReq(
          "POST",
          "/impersonations",
          { data: { type: "impersonations", relationships: userLink("u") } },
          sessionId,
        ),
      );
    expect((await impersonate(userSid)).status).toBe(403);

    const started = await impersonate(adminSid);
    expect(started.status).toBe(201);
    const token = sessionCookieOf(started);
    assert(token !== undefined && token !== "", "the impersonation's session is the cookie");
    const document = await jsonBody(
      started,
      Schema.Struct({
        data: Schema.Struct({
          id: Schema.String,
          relationships: Schema.Struct({
            user: Schema.Struct({ data: Schema.Struct({ id: Schema.String }) }),
            impersonator: Schema.Struct({ data: Schema.Struct({ id: Schema.String }) }),
          }),
        }),
        included: Schema.Array(UserResource),
      }),
    );
    // Named by the stored id, never the token itself.
    expect(document.data.id).toBe(hashToken(token));
    expect(document.data.relationships.user.data.id).toBe("u");
    expect(document.data.relationships.impersonator.data.id).toBe("admin");
    expect(document.included[0]?.id).toBe("u");

    // A session that is not an impersonation has none to end, and only
    // `current` names one.
    expect(
      (await fx.handler(apiReq("DELETE", "/impersonations/current", undefined, adminSid))).status,
    ).toBe(404);
    expect(
      (await fx.handler(apiReq("DELETE", `/impersonations/${document.data.id}`, undefined, token)))
        .status,
    ).toBe(404);

    const ended = await fx.handler(apiReq("DELETE", "/impersonations/current", undefined, token));
    expect(ended.status).toBe(204);
    expect(sessionCookieOf(ended)).toBe("");
    expect((await fx.handler(req("GET", "/sessions/current", token))).status).toBe(401);
    // The administrator's own session is untouched.
    expect((await fx.handler(req("GET", "/sessions/current", adminSid))).status).toBe(200);
  });
});

/** An `api-keys` resource, read for what the API-key tests check. */
const ApiKeyResource = Schema.Struct({
  id: Schema.String,
  attributes: Schema.Struct({ name: Schema.String, enabled: Schema.Boolean }),
  relationships: Schema.Struct({
    user: Schema.Struct({ data: Schema.Struct({ id: Schema.String }) }),
  }),
});

describe("HTTP api-key endpoints", () => {
  const createKey = { data: { type: "api-keys", attributes: { name: "CI" } } };

  it("rejects minting a key over a machine (bearer) credential, and allows it over the session cookie", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    const sid = fx.makeSession("u");

    // Same valid, unexpired session token — but presented as a bearer
    // credential rather than the cookie. Minting requires an interactive
    // session, so this is a 403, not a 401: the caller is authenticated, just
    // not with a credential class allowed to mint.
    const deniedOverBearer = await fx.handler(apiReqBearer("/api-keys", createKey, sid));
    expect(deniedOverBearer.status).toBe(403);

    const allowedOverCookie = await fx.handler(apiReq("POST", "/api-keys", createKey, sid));
    expect(allowedOverCookie.status).toBe(201);
  });

  it("creates, lists, updates, and deletes keys, the plaintext only at creation", async () => {
    const fx = makeFixture();
    fx.seedUser("u", "u@test.com");
    fx.seedUser("other", "other@test.com");
    const sid = fx.makeSession("u");
    const otherSid = fx.makeSession("other");

    const created = await fx.handler(apiReq("POST", "/api-keys", createKey, sid));
    expect(created.status).toBe(201);
    const body = await jsonBody(
      created,
      Schema.Struct({ data: ApiKeyResource, meta: Schema.Struct({ key: Schema.String }) }),
    );
    expect(body.meta.key.length).toBeGreaterThan(0);
    expect(body.data.attributes.name).toBe("CI");
    expect(body.data.relationships.user.data.id).toBe("u");
    const keyId = body.data.id;

    const list = await fx.handler(apiReq("GET", "/api-keys", undefined, sid));
    const listed = await list.text();
    // The plaintext never comes back after creation.
    expect(listed).not.toContain(body.meta.key);
    expect(
      Schema.decodeSync(
        Schema.fromJsonString(Schema.Struct({ data: Schema.Array(ApiKeyResource) })),
      )(listed).data.length,
    ).toBe(1);

    const patch = (sessionId: string) =>
      fx.handler(
        apiReq(
          "PATCH",
          `/api-keys/${keyId}`,
          { data: { type: "api-keys", id: keyId, attributes: { enabled: false } } },
          sessionId,
        ),
      );
    // Another user's key is refused like an unknown one.
    expect((await patch(otherSid)).status).toBe(400);
    const updated = await patch(sid);
    expect(
      (await jsonBody(updated, Schema.Struct({ data: ApiKeyResource }))).data.attributes.enabled,
    ).toBe(false);

    const deleted = await fx.handler(apiReq("DELETE", `/api-keys/${keyId}`, undefined, sid));
    expect(deleted.status).toBe(204);
    const empty = await fx.handler(apiReq("GET", "/api-keys", undefined, sid));
    expect((await jsonBody(empty, collectionBody({}))).data.length).toBe(0);
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

    // Minting a JWT is a write: `GET /token` is gone.
    expect((await fx.handler(req("GET", "/token", sid))).status).toBe(404);
    expect((await fx.handler(apiReq("POST", "/tokens"))).status).toBe(401);

    const tokenRes = await fx.handler(apiReq("POST", "/tokens", undefined, sid));
    expect(tokenRes.status).toBe(201);
    const document = await jsonBody(
      tokenRes,
      resourceBody({ token: Schema.String, expiresAt: Schema.Finite }),
    );
    const { token } = document.data.attributes;
    // The resource is named by the token's digest, never the token.
    expect(document.data.id).toBe(hashToken(token));
    expect(document.data.attributes.expiresAt).toBeGreaterThan(0);

    const jwksRes = await fx.handler(req("GET", "/jwks"));
    expect(jwksRes.status).toBe(200);
    // RFC 7517 JSON, served as `application/json`, never a JSON:API document.
    const { keys } = Schema.decodeUnknownSync(Jwks)(
      await expectSpecJson(jwksRes, "application/json", ["keys"]),
    );
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
