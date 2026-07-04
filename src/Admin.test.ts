import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect, Layer } from "effect";
import {
  AdminUserStore,
  BannedUserPlugin,
  isAdmin,
  isBanned,
  makeAdminService,
  type AdminConfig,
  type AdminServiceShape,
  type ListUsersQuery,
} from "./Admin.js";
import { Hooks } from "./Hooks.js";
import { IdentifierStore, type Identifier } from "./Identifier.js";
import { PasswordHasher, type PasswordHasherShape } from "./Password.js";
import { makeSessionManager, SessionManager, SessionStore, UserStore } from "./Session.js";
import { hashToken } from "./TokenHash.js";
import type { Session, SessionConfig, User } from "./Types.js";
import { UserServiceStore } from "./User.js";

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const identifiers = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();

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

  createUser: (input: {
    email: string;
    name?: string;
    image?: string;
    attributes?: Record<string, unknown>;
  }) =>
    Effect.sync(() => {
      const id = `user-${users.size + 1}`;
      const user: User = {
        id,
        email: input.email,
        emailVerified: false,
        name: input.name,
        image: input.image,
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: input.attributes ?? {},
      };
      users.set(id, user);
      return user;
    }),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const identifierStore = {
  getByValue: (type: string, value: string) =>
    Effect.sync(() => {
      return (
        Array.from(identifiers.values()).find((id) => id.type === type && id.value === value) ??
        null
      );
    }),

  listByUser: (userId: string) =>
    Effect.sync(() => Array.from(identifiers.values()).filter((id) => id.userId === userId)),

  create: (identifier: Identifier) =>
    Effect.sync(() => {
      identifiers.set(identifier.id, identifier);
      return identifier;
    }),

  setVerified: (id: string, verifiedAt: Date) =>
    Effect.sync(() => {
      const ident = identifiers.get(id);
      if (ident === undefined) return null;
      const updated = { ...ident, verified: true, verifiedAt };
      identifiers.set(id, updated);
      return updated;
    }),

  delete: (id: string) =>
    Effect.sync(() => {
      identifiers.delete(id);
    }),

  deleteByUser: (userId: string) =>
    Effect.sync(() => {
      for (const [id, ident] of identifiers.entries()) {
        if (ident.userId === userId) {
          identifiers.delete(id);
        }
      }
    }),
};

/** Fast test-only password hasher (not cryptographically secure). */
const testHasher: PasswordHasherShape = {
  algorithm: "test",
  hash: (password: string) =>
    Effect.succeed({ hash: `test$${password}`, algorithm: "test" as const }),
  verify: (password: string, hash: string) => Effect.succeed(hash === `test$${password}`),
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
    Context.add(IdentifierStore, identifierStore),
    Context.add(PasswordHasher, testHasher),
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
    service: AdminServiceShape,
  ) => Effect.Effect<
    A,
    E,
    UserServiceStore | AdminUserStore | SessionManager | Hooks | IdentifierStore | PasswordHasher
  >,
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
    identifiers.clear();
    passwordHashes.clear();
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
        const createUser = yield* Effect.result(
          service.createUser(regular, { email: "new@example.com" }),
        );
        const setPassword = yield* Effect.result(
          service.setUserPassword(regular, "user-2", "newpass"),
        );
        const listSessions = yield* Effect.result(service.listUserSessions(regular, "user-2"));
        return {
          list,
          setRole,
          ban,
          remove,
          revoke,
          impersonate,
          createUser,
          setPassword,
          listSessions,
        };
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
        const sessionManager = yield* SessionManager;
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
      const sessionManager = yield* SessionManager;

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
      expect(result.blocked.failure._tag).toBe("UserBannedError");
      expect(result.blocked.failure.message).toBe("Your account has been suspended");
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
        const sessionManager = yield* SessionManager;
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
        const sessionManager = yield* SessionManager;
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
    expect(sessions.has(hashToken(session.id))).toBe(true);

    const missingTarget = await runService(testContext, {}, (service) =>
      Effect.result(service.impersonateUser(admin, "ghost")),
    );
    expect(missingTarget._tag).toBe("Failure");
    if (missingTarget._tag === "Failure") {
      expect(missingTarget.failure._tag).toBe("UserNotFoundError");
    }
  });

  it("createUser: creates a user with role, identifiers, and hashed password", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        // Minimal: email only
        const minimal = yield* service.createUser(admin, { email: "alice@example.com" });

        // Full: role, password, and identifier records
        const full = yield* service.createUser(admin, {
          email: "bob@example.com",
          name: "Bob",
          role: "moderator",
          password: "s3cr3t",
          attributes: { theme: "dark" },
          identifiers: [
            { type: "email", value: "bob@example.com", verified: true },
            { type: "username", value: "bobthemod" },
          ],
        });

        return { minimal, full };
      }),
    );

    // Minimal user
    expect(result.minimal.email).toBe("alice@example.com");
    expect(result.minimal.attributes["role"]).toBeUndefined();
    expect(passwordHashes.has(result.minimal.id)).toBe(false);

    // Full user: role merged into attributes
    expect(result.full.email).toBe("bob@example.com");
    expect(result.full.name).toBe("Bob");
    expect(result.full.attributes["role"]).toBe("moderator");
    expect(result.full.attributes["theme"]).toBe("dark");

    // Password was hashed and stored
    expect(passwordHashes.get(result.full.id)).toBe("test$s3cr3t");

    // Identifier records created
    const idents = Array.from(identifiers.values()).filter((id) => id.userId === result.full.id);
    expect(idents).toHaveLength(2);
    const emailIdent = idents.find((id) => id.type === "email");
    const usernameIdent = idents.find((id) => id.type === "username");
    expect(emailIdent?.value).toBe("bob@example.com");
    expect(emailIdent?.verified).toBe(true);
    expect(usernameIdent?.value).toBe("bobthemod");
    expect(usernameIdent?.verified).toBe(false);
  });

  it("createUser: authorization failure for non-admin", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.createUser(regular, { email: "new@example.com" })),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("AdminError");
    }
  });

  it("setUserPassword: admin resets a user's password without current-password check", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    await runService(testContext, {}, (service) =>
      service.setUserPassword(admin, "user-1", "newpassword"),
    );

    expect(passwordHashes.get("user-1")).toBe("test$newpassword");
  });

  it("setUserPassword: optionally revokes all user sessions after reset", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");
    seedUser("user-2", "user2@example.com");

    await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionManager;
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-2");

        // Without revoke: sessions survive
        yield* service.setUserPassword(admin, "user-1", "pass1");
        const afterNoRevoke = sessions.size;

        // With revoke: user-1's sessions are revoked, user-2's remain
        yield* service.setUserPassword(admin, "user-1", "pass2", { revokeOtherSessions: true });
        return { afterNoRevoke };
      }),
    );

    expect(sessions.size).toBe(1);
    const remaining = Array.from(sessions.values());
    expect(remaining[0]?.userId).toBe("user-2");
  });

  it("setUserPassword: fails with UserNotFoundError for unknown user", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.setUserPassword(admin, "ghost", "pass")),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("UserNotFoundError");
    }
  });

  it("setUserPassword: authorization failure for non-admin", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");
    seedUser("user-2", "other@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.setUserPassword(regular, "user-2", "pass")),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("AdminError");
    }
  });

  it("listUserSessions: returns only non-expired sessions for the target user", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");
    seedUser("user-2", "user2@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionManager;
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-1");
        yield* sessionManager.createSession("user-2");

        // Inject an already-expired session directly into the store
        const expiredSession = {
          id: "expired-hash",
          userId: "user-1",
          expiresAt: new Date(Date.now() - 1000),
          createdAt: new Date(),
          lastActivityAt: new Date(),
          attributes: {},
        };
        sessions.set("expired-hash", expiredSession);

        return yield* service.listUserSessions(admin, "user-1");
      }),
    );

    // Only non-expired sessions for user-1 are returned
    expect(result.length).toBe(2);
    expect(result.every((s) => s.userId === "user-1")).toBe(true);
    expect(result.every((s) => s.expiresAt.getTime() > Date.now())).toBe(true);
  });

  it("listUserSessions: authorization failure for non-admin", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.listUserSessions(regular, "user-1")),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("AdminError");
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
