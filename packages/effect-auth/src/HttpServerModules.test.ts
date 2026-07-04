import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import { SessionStore, UserStore, SessionManager } from "./Session.js";
import { UserServiceStore, UserService } from "./User.js";
import { Hooks } from "./Hooks.js";
import { AuthLifecycleService } from "./AuthLifecycle.js";
import { EmailPasswordStore } from "./EmailPassword.js";
import { PasswordHasher } from "./Password.js";
import { EmailVerificationService, EmailVerificationStore } from "./EmailVerification.js";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./PasswordReset.js";
import {
  OrganizationStore,
  type Organization,
  type Member,
  type Invitation,
  OrganizationService,
} from "./Organization.js";
import { AdminUserStore, AdminService } from "./Admin.js";
import { ApiKeyStore, type ApiKey, ApiKeyService } from "./ApiKey.js";
import { JwtKeyStore, type JwtKeyPair, JwtService } from "./Jwt.js";
import type * as Types from "./Types.js";

const HOUR = 60 * 60 * 1000;

/** Build a handler wired with real org/admin/api-key/jwt services + in-memory stores. */
const makeFixture = () => {
  const usersById = new Map<string, Types.User>();
  const usersByEmail = new Map<string, Types.User>();
  const sessions = new Map<string, Types.Session>();
  const orgs = new Map<string, Organization>();
  const members: Member[] = [];
  const invitations = new Map<string, Invitation>();
  const apiKeys = new Map<string, ApiKey>();
  const jwtKeys: JwtKeyPair[] = [];

  const seedUser = (id: string, email: string, attributes: Record<string, unknown> = {}) => {
    const now = new Date();
    const user: Types.User = {
      id,
      email,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    usersById.set(id, user);
    usersByEmail.set(email, user);
    return user;
  };

  const makeSession = (userId: string): string => {
    const id = crypto.randomBytes(16).toString("hex");
    const now = new Date();
    sessions.set(id, {
      id,
      userId,
      expiresAt: new Date(Date.now() + HOUR),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return id;
  };

  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId: string) => Effect.succeed(null),
  };

  const userServiceStore = {
    get: userStore.get,
    getByEmail: (email: string) => Effect.succeed(usersByEmail.get(email) ?? null),
    update: (user: Types.User) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        usersByEmail.set(user.email, user);
        return user;
      }),
    delete: (userId: string) =>
      Effect.sync(() => {
        const u = usersById.get(userId);
        if (u) {
          usersById.delete(userId);
          usersByEmail.delete(u.email);
        }
      }),
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
    deleteOrganization: (id: string) => Effect.sync(() => void orgs.delete(id)),
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
  };

  const adminUserStore = {
    listUsers: (query: { limit?: number; offset?: number; searchEmail?: string }) =>
      Effect.sync(() => {
        let all = [...usersById.values()];
        if (query.searchEmail !== undefined) {
          const needle = query.searchEmail.toLowerCase();
          all = all.filter((u) => u.email.toLowerCase().includes(needle));
        }
        const total = all.length;
        const offset = query.offset ?? 0;
        const limit = query.limit ?? all.length;
        return { users: all.slice(offset, offset + limit), total };
      }),
  };

  const apiKeyStore = {
    create: (k: ApiKey) => Effect.sync(() => (apiKeys.set(k.id, k), k)),
    get: (id: string) => Effect.succeed(apiKeys.get(id) ?? null),
    getByHash: (keyHash: string) =>
      Effect.succeed([...apiKeys.values()].find((k) => k.keyHash === keyHash) ?? null),
    update: (k: ApiKey) => Effect.sync(() => (apiKeys.set(k.id, k), k)),
    delete: (id: string) => Effect.sync(() => void apiKeys.delete(id)),
    listByUserId: (userId: string) =>
      Effect.succeed([...apiKeys.values()].filter((k) => k.userId === userId)),
  };

  const jwtKeyStore = {
    getActive: () => Effect.succeed(jwtKeys[0] ?? null),
    create: (pair: JwtKeyPair) => Effect.sync(() => (jwtKeys.push(pair), pair)),
    list: () => Effect.succeed(jwtKeys),
  };

  const base = Layer.mergeAll(
    SessionManager.layer({ sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR } }).pipe(
      Layer.provide(
        Layer.mergeAll(
          Layer.succeed(SessionStore)(sessionStore as never),
          Layer.succeed(UserStore)(userStore),
        ),
      ),
    ),
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    // Admin handlers use the user store directly, so expose it in the context too.
    Layer.succeed(UserServiceStore)(userServiceStore),
    Hooks.Default,
    // Unused base services (org/admin/api-key/jwt handlers never touch them).
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordStore)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(EmailVerificationStore)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(PasswordResetStore)(undefined as never),
    Layer.succeed(PasswordResetUserStore)(undefined as never),
  );

  const modules = Layer.mergeAll(
    OrganizationService.layer(),
    Layer.succeed(OrganizationStore)(orgStore),
    AdminService.layer({ adminRoles: ["admin"] }),
    Layer.succeed(AdminUserStore)(adminUserStore),
    ApiKeyService.layer(),
    Layer.succeed(ApiKeyStore)(apiKeyStore),
    JwtService.layer({ issuer: "https://auth.test" }),
    Layer.succeed(JwtKeyStore)(jwtKeyStore),
  );

  const services = Layer.mergeAll(base, modules) as Layer.Layer<AuthServices>;
  const { handler } = makeAuthWebHandler({ services, cookie: { secure: false } });

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
    expect(fx.sessions.get(sid)?.attributes["activeOrganizationId"]).toBe(org.id);

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
    const key = crypto.createPublicKey({
      key: jwk as crypto.JsonWebKeyInput["key"],
      format: "jwk",
    });
    const valid = crypto.verify(
      "sha256",
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(sigSeg, "base64url"),
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
