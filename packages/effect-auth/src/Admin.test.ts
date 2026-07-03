import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect, Layer } from "effect";
import {
  AdminUserStore,
  AdminUserStoreTag,
  BannedUserPlugin,
  isAdmin,
  isBanned,
  makeAdminService,
  type AdminConfig,
  type AdminService,
  type ListUsersQuery,
} from "./Admin.js";
import { Hooks } from "./Hooks.js";
import {
  makeSessionManager,
  SessionManager,
  SessionManagerTag,
  SessionStore,
  UserStore,
} from "./Session.js";
import type { Session, SessionConfig, User } from "./Types.js";
import { UserServiceStore, UserServiceStoreTag } from "./User.js";

const users = new Map<string, User>();
const sessions = new Map<string, Session>();

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),

  update: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      sessions.delete(sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const getUser = (userId: string) => Effect.sync(() => users.get(userId) ?? null);

// Session's UserStore (used by SessionManager.validateSession)
const sessionUserStore = {
  get: getUser,
  getCredentials: (_userId: string) => Effect.succeed(null),
};

const userServiceStore = {
  get: getUser,

  getByEmail: (email: string) =>
    Effect.sync(() => Array.from(users.values()).find((user) => user.email === email) ?? null),

  update: (user: User) =>
    Effect.sync(() => {
      users.set(user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      users.delete(userId);
    }),
};

const adminUserStore = {
  listUsers: (query: ListUsersQuery) =>
    Effect.sync(() => {
      const search = query.searchEmail?.toLowerCase();
      const matching = Array.from(users.values())
        .filter((user) => (search ? user.email.toLowerCase().includes(search) : true))
        .sort((a, b) => a.email.localeCompare(b.email));
      const offset = query.offset ?? 0;
      const limit = query.limit ?? matching.length;
      return { users: matching.slice(offset, offset + limit), total: matching.length };
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      makeSessionManager(sessionConfig),
      Context.merge(
        Context.make(SessionStore, sessionStore),
        Context.make(UserStore, sessionUserStore),
      ),
    ),
  );

  return Context.make(SessionManager, sessionManager).pipe(
    Context.add(SessionStore, sessionStore),
    Context.add(UserStore, sessionUserStore),
    Context.add(UserServiceStore, userServiceStore),
    Context.add(AdminUserStore, adminUserStore),
  );
};

const seedUser = (id: string, email: string, attributes: Record<string, unknown> = {}): User => {
  const user: User = {
    id,
    email,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes,
  };
  users.set(id, user);
  return user;
};

type TestContext = Awaited<ReturnType<typeof makeTestContext>>;

const runService = <A, E>(
  testContext: TestContext,
  config: AdminConfig,
  program: (
    service: AdminService,
  ) => Effect.Effect<A, E, UserServiceStoreTag | AdminUserStoreTag | SessionManagerTag | Hooks>,
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* makeAdminService(config);
        return yield* program(service);
      }),
      testContext,
    ).pipe(Effect.provide(Hooks.Default)),
  );

describe("AdminService", () => {
  beforeEach(() => {
    users.clear();
    sessions.clear();
  });

  it("rejects non-admin actors on every method", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");
    seedUser("user-2", "other@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const list = yield* Effect.result(service.listUsers(regular));
        const setRole = yield* Effect.result(service.setRole(regular, "user-2", "admin"));
        const ban = yield* Effect.result(service.banUser(regular, "user-2"));
        const remove = yield* Effect.result(service.removeUser(regular, "user-2"));
        const revoke = yield* Effect.result(service.revokeUserSessions(regular, "user-2"));
        const impersonate = yield* Effect.result(service.impersonateUser(regular, "user-2"));
        return { list, setRole, ban, remove, revoke, impersonate };
      }),
    );

    for (const outcome of Object.values(result)) {
      expect(outcome._tag).toBe("Failure");
      if (outcome._tag === "Failure") {
        expect(outcome.failure._tag).toBe("AdminError");
      }
    }
  });

  it("grants admin via attributes.role, adminRoles, and adminUserIds", async () => {
    const roleAdmin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const superuser = seedUser("super-1", "super@example.com", { role: "superuser" });
    const byId = seedUser("root-1", "root@example.com");

    expect(isAdmin(roleAdmin)).toBe(true);
    expect(isAdmin(superuser)).toBe(false);
    expect(isAdmin(superuser, { adminRoles: ["superuser"] })).toBe(true);
    expect(isAdmin(byId)).toBe(false);
    expect(isAdmin(byId, { adminUserIds: ["root-1"] })).toBe(true);

    const testContext = await makeTestContext();
    const listed = await runService(testContext, { adminUserIds: ["root-1"] }, (service) =>
      service.listUsers(byId),
    );
    expect(listed.total).toBe(3);
  });

  it("sets a user's role via attributes.role", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com", { theme: "dark" });

    const updated = await runService(testContext, {}, (service) =>
      service.setRole(admin, "user-1", "admin"),
    );

    expect(updated.attributes["role"]).toBe("admin");
    expect(updated.attributes["theme"]).toBe("dark");
    expect(isAdmin(users.get("user-1")!)).toBe(true);
  });

  it("bans a user, revokes their sessions, and blocks re-banning edge cases", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const otherAdmin = seedUser("admin-2", "admin2@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionManagerTag;
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-1");
        const sessionsBefore = sessions.size;

        const banned = yield* service.banUser(admin, "user-1", { reason: "Spamming" });
        const sessionsAfter = sessions.size;

        const banSelf = yield* Effect.result(service.banUser(admin, "admin-1"));
        const banAdmin = yield* Effect.result(service.banUser(admin, otherAdmin.id));

        return { sessionsBefore, banned, sessionsAfter, banSelf, banAdmin };
      }),
    );

    expect(result.sessionsBefore).toBe(2);
    expect(result.sessionsAfter).toBe(0);
    expect(result.banned.attributes["banned"]).toBe(true);
    expect(result.banned.attributes["banReason"]).toBe("Spamming");
    expect(result.banned.attributes["banExpires"]).toBeUndefined();
    expect(isBanned(result.banned)).toBe(true);
    expect(result.banSelf._tag).toBe("Failure");
    expect(result.banAdmin._tag).toBe("Failure");
    expect(isBanned(users.get("admin-2")!)).toBe(false);
  });

  it("applies the default ban reason and defaultBanExpiresIn", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const banned = await runService(
      testContext,
      { defaultBanExpiresIn: 60 * 60 * 1000 },
      (service) => service.banUser(admin, "user-1"),
    );

    expect(banned.attributes["banReason"]).toBe("No reason");
    const banExpires = banned.attributes["banExpires"];
    expect(typeof banExpires).toBe("number");
    expect(banExpires as number).toBeGreaterThan(Date.now());
    expect(isBanned(banned)).toBe(true);
  });

  it("treats an expired ban as not banned and unbans cleanly", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const expired = yield* service.banUser(admin, "user-1", { expiresIn: -1000 });
        const bannedWhileExpired = isBanned(expired);

        const permanent = yield* service.banUser(admin, "user-1");
        const bannedPermanent = isBanned(permanent);

        const unbanned = yield* service.unbanUser(admin, "user-1");
        return { bannedWhileExpired, bannedPermanent, unbanned };
      }),
    );

    expect(result.bannedWhileExpired).toBe(false);
    expect(result.bannedPermanent).toBe(true);
    expect(result.unbanned.attributes["banned"]).toBe(false);
    expect(result.unbanned.attributes["banReason"]).toBeUndefined();
    expect(result.unbanned.attributes["banExpires"]).toBeUndefined();
    expect(isBanned(result.unbanned)).toBe(false);
  });

  it("BannedUserPlugin blocks session validation for banned users", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const hooksWithPlugin = BannedUserPlugin.pipe(Layer.provide(Hooks.Default));

    const program = Effect.gen(function* () {
      const service = yield* makeAdminService({});
      const sessionManager = yield* SessionManagerTag;

      // Ban first (revokes existing sessions), then mint a fresh session to
      // prove the plugin blocks validation even when a session exists.
      yield* service.banUser(admin, "user-1");
      const bannedSession = yield* sessionManager.createSession("user-1");
      const blocked = yield* Effect.result(sessionManager.validateSession(bannedSession.id));

      yield* service.unbanUser(admin, "user-1");
      const allowed = yield* sessionManager.validateSession(bannedSession.id);

      // A ban that has already lapsed does not block validation
      yield* service.banUser(admin, "user-1", { expiresIn: -1000 });
      const lapsedSession = yield* sessionManager.createSession("user-1");
      const lapsed = yield* Effect.result(sessionManager.validateSession(lapsedSession.id));

      return { blocked, allowed, lapsed };
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(hooksWithPlugin)),
    );

    expect(result.blocked._tag).toBe("Failure");
    if (result.blocked._tag === "Failure") {
      expect(result.blocked.failure._tag).toBe("AuthError");
      expect(result.blocked.failure.message).toBe("User is banned");
    }
    expect(result.allowed.user.id).toBe("user-1");
    expect(result.lapsed._tag).toBe("Success");
  });

  it("removes a user along with their sessions, but never the actor", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionManagerTag;
        yield* sessionManager.createSession("user-1");

        const removeSelf = yield* Effect.result(service.removeUser(admin, "admin-1"));
        yield* service.removeUser(admin, "user-1");

        return { removeSelf };
      }),
    );

    expect(result.removeSelf._tag).toBe("Failure");
    expect(users.has("admin-1")).toBe(true);
    expect(users.has("user-1")).toBe(false);
    expect(sessions.size).toBe(0);
  });

  it("revokes a user's sessions without touching others", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");
    seedUser("user-2", "user2@example.com");

    await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionManagerTag;
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-2");
        yield* service.revokeUserSessions(admin, "user-1");
      }),
    );

    const remaining = Array.from(sessions.values());
    expect(remaining).toHaveLength(1);
    expect(remaining[0].userId).toBe("user-2");
  });

  it("creates impersonation sessions with the expected attributes", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const before = Date.now();
    const session = await runService(
      testContext,
      { impersonationSessionDuration: 15 * 60 * 1000 },
      (service) => service.impersonateUser(admin, "user-1"),
    );

    expect(session.userId).toBe("user-1");
    expect(session.attributes["impersonatedBy"]).toBe("admin-1");
    const impersonationExpiresAt = session.attributes["impersonationExpiresAt"];
    expect(typeof impersonationExpiresAt).toBe("number");
    expect(impersonationExpiresAt as number).toBeGreaterThanOrEqual(before + 15 * 60 * 1000);
    expect(sessions.has(session.id)).toBe(true);

    const missingTarget = await runService(testContext, {}, (service) =>
      Effect.result(service.impersonateUser(admin, "ghost")),
    );
    expect(missingTarget._tag).toBe("Failure");
    if (missingTarget._tag === "Failure") {
      expect(missingTarget.failure._tag).toBe("UserNotFoundError");
    }
  });

  it("lists users with pagination and email search", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "alice@example.com");
    seedUser("user-2", "bob@example.com");
    seedUser("user-3", "carol@example.com");
    seedUser("user-4", "dave@other.org");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const all = yield* service.listUsers(admin);
        const page = yield* service.listUsers(admin, { limit: 2, offset: 1 });
        const searched = yield* service.listUsers(admin, { searchEmail: "example.com" });
        const searchedPage = yield* service.listUsers(admin, {
          searchEmail: "example.com",
          limit: 1,
          offset: 3,
        });
        return { all, page, searched, searchedPage };
      }),
    );

    expect(result.all.total).toBe(5);
    expect(result.all.users).toHaveLength(5);
    // Store sorts by email: admin, alice, bob, carol, dave
    expect(result.page.users.map((user) => user.email)).toEqual([
      "alice@example.com",
      "bob@example.com",
    ]);
    expect(result.page.total).toBe(5);
    expect(result.searched.total).toBe(4);
    expect(result.searched.users.every((user) => user.email.endsWith("example.com"))).toBe(true);
    expect(result.searchedPage.users.map((user) => user.email)).toEqual(["carol@example.com"]);
    expect(result.searchedPage.total).toBe(4);
  });
});
