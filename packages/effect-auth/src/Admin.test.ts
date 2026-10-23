import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Array as Arr, Context, Crypto, Effect, Layer, Order, Predicate, Result } from "effect";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  AdminUserStore,
  BannedUserPlugin,
  isAdmin,
  isBanned,
  type AdminConfig,
  type AdminService,
  type ListUsersQuery,
} from "./Admin.ts";
import * as Admin from "./Admin.ts";
import * as Ladder from "./Ladder.ts";
import { Hooks } from "./Hooks.ts";
import { AuthError } from "./Errors.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { PasswordHasher } from "./password/Password.ts";
import { make, SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { type NewUserIdentifier, UserStore } from "./UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import type { Attributes, Session, SessionConfig, User } from "./Types.ts";
import { UserServiceStore } from "./User.ts";

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const identifiers = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
/** The `identifier` each `createUser` call was given. */
const createdWith: Array<NewUserIdentifier | undefined> = [];

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

// Session's UserStore (used by SessionService.validateSession)
const sessionUserStore = {
  get: getUser,
};

const userServiceStore = {
  get: getUser,

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

/** Earliest email identifier value for a user, mirroring how a SQL store
 * would resolve the email-of-record from its identifier records. */
const emailOf = (userId: string): string =>
  Arr.sort(
    Array.from(identifiers.values()).filter(
      (identifier) => identifier.userId === userId && identifier.type === "email",
    ),
    Order.mapInput(Order.Number, (identifier: Identifier) => identifier.createdAt.getTime()),
  )[0]?.value ?? "";

/** `localeCompare` as an `Order`. */
const localeOrder = Order.make<string>((a, b) => {
  const c = a.localeCompare(b);
  return c < 0 ? -1 : c > 0 ? 1 : 0;
});

const adminUserStore = {
  listUsers: (query: ListUsersQuery) =>
    Effect.sync(() => {
      const search = query.searchEmail?.toLowerCase();
      const matching = Arr.sort(
        Array.from(users.values()).filter((user) =>
          search ? emailOf(user.id).toLowerCase().includes(search) : true,
        ),
        Order.mapInput(localeOrder, (user: User) => emailOf(user.id)),
      );
      const offset = query.offset ?? 0;
      const limit = query.limit ?? matching.length;
      return { users: matching.slice(offset, offset + limit), total: matching.length };
    }),

  createUser: (input: {
    name?: string;
    image?: string;
    attributes?: Attributes;
    identifier?: NewUserIdentifier | undefined;
  }) =>
    Effect.sync(() => {
      createdWith.push(input.identifier);
      const id = `user-${users.size + 1}`;
      const user: User = {
        id,
        name: input.name,
        image: input.image,
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: input.attributes ?? {},
      };
      users.set(id, user);
      return { user, created: true };
    }),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const identifierStore = memoryIdentifierStore(identifiers);

/** Fast test-only password hasher (not cryptographically secure). */
const testHasher: typeof PasswordHasher.Service = {
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

const makeTestContext = async (
  hooksLayer: Layer.Layer<Hooks> = Hooks.Default,
  store: typeof AdminUserStore.Service = adminUserStore,
) => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(
          Context.make(SessionStore, sessionStore),
          Context.make(UserStore, sessionUserStore),
        ),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(hooksLayer)),
  );

  return Context.make(SessionService, sessionManager).pipe(
    Context.add(SessionStore, sessionStore),
    Context.add(UserStore, sessionUserStore),
    Context.add(UserServiceStore, userServiceStore),
    Context.add(AdminUserStore, store),
    Context.add(IdentifierStore, identifierStore),
    Context.add(PasswordHasher, testHasher),
    Context.add(Crypto.Crypto, PlatformCrypto.instance),
  );
};

const seedUser = (id: string, email: string, attributes: Attributes = {}): User => {
  const user: User = {
    id,
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes,
  };
  users.set(id, user);
  const identifier = makeIdentifier({
    userId: id,
    type: "email",
    value: email,
    verified: true,
    verifiedAt: new Date(),
  });
  identifiers.set(identifier.id, identifier);
  return user;
};

type TestContext = Awaited<ReturnType<typeof makeTestContext>>;

const runService = <A, E>(
  testContext: TestContext,
  config: AdminConfig,
  program: (
    service: typeof AdminService.Service,
  ) => Effect.Effect<
    A,
    E,
    UserServiceStore | AdminUserStore | SessionService | Hooks | IdentifierStore | PasswordHasher
  >,
): Promise<A> =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* Admin.make(config);
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
    createdWith.length = 0;
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
      assert(Predicate.isTagged(outcome, "Failure"));
      expect(outcome.failure._tag).toBe("AdminError");
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
    const stored = users.get("user-1");
    assert(stored !== undefined, "user-1 is seeded");
    expect(isAdmin(stored)).toBe(true);
  });

  it("refuses a role off the configured ladder, writing nothing (#193)", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com", { role: "user" });
    const roles = Ladder.make(["user", "moderator", "admin"]);

    const refused = await runService(testContext, { roles }, (service) =>
      Effect.flip(service.setRole(admin, "user-1", "superadmin")),
    );
    expect(refused._tag).toBe("AdminError");
    expect(users.get("user-1")?.attributes["role"]).toBe("user");

    const promoted = await runService(testContext, { roles }, (service) =>
      service.setRole(admin, "user-1", "moderator"),
    );
    expect(promoted.attributes["role"]).toBe("moderator");
  });

  it("checks createUser's role whichever door it comes in by (#193)", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const roles = Ladder.make(["user", "admin"]);

    for (const input of [
      { email: "a@example.com", role: "root" },
      { email: "b@example.com", attributes: { role: "root" } },
      { email: "c@example.com", attributes: { role: 7 } },
    ]) {
      const refused = await runService(testContext, { roles }, (service) =>
        Effect.flip(service.createUser(admin, input)),
      );
      expect(refused._tag, input.email).toBe("AdminError");
    }
  });

  it("bans a user, revokes their sessions, and blocks re-banning edge cases", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const otherAdmin = seedUser("admin-2", "admin2@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionService;
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
    const storedAdmin = users.get("admin-2");
    assert(storedAdmin !== undefined, "admin-2 is seeded");
    expect(isBanned(storedAdmin)).toBe(false);
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
    assert(Predicate.isNumber(banExpires));
    expect(banExpires).toBeGreaterThan(Date.now());
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
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    // SessionService now resolves Hooks once, at construction time, so the
    // plugin must be baked in when building the SessionService instance used
    // by this test rather than layered over the whole program afterward.
    const hooksWithPlugin = BannedUserPlugin.pipe(Layer.provide(Hooks.Default));
    const testContext = await makeTestContext(hooksWithPlugin);

    const program = Effect.gen(function* () {
      const service = yield* Admin.make({});
      const sessionManager = yield* SessionService;

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

    const result = await Effect.runPromise(Effect.provide(program, testContext));

    expect(result.blocked._tag).toBe("Failure");
    assert(Result.isFailure(result.blocked));
    expect(result.blocked.failure._tag).toBe("UserBannedError");
    expect(result.blocked.failure.message).toBe("Your account has been suspended");
    expect(result.allowed.user.id).toBe("user-1");
    expect(result.lapsed._tag).toBe("Success");
  });

  it("removes a user along with their sessions, but never the actor", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionService;
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
        const sessionManager = yield* SessionService;
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
    assert(Predicate.isNumber(impersonationExpiresAt));
    expect(impersonationExpiresAt).toBeGreaterThanOrEqual(before + 15 * 60 * 1000);
    expect(sessions.has(hashToken(session.id))).toBe(true);

    const missingTarget = await runService(testContext, {}, (service) =>
      Effect.result(service.impersonateUser(admin, "ghost")),
    );
    expect(missingTarget._tag).toBe("Failure");
    assert(Result.isFailure(missingTarget));
    expect(missingTarget.failure._tag).toBe("UserNotFoundError");
  });

  it("createUser: creates a user with role, identifiers, and hashed password", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        // Minimal: email only
        const minimal = yield* service.createUser(admin, { email: "alice@example.com" });

        // Full: role, password, and an extra identifier record
        const full = yield* service.createUser(admin, {
          email: "bob@example.com",
          emailVerified: true,
          name: "Bob",
          role: "moderator",
          password: "s3cr3t",
          attributes: { theme: "dark" },
          identifiers: [{ type: "username", value: "bobthemod" }],
        });

        return { minimal, full };
      }),
    );

    // Minimal user: the primary email identifier is claimed (unverified by default)
    const minimalEmail = Array.from(identifiers.values()).find(
      (id) => id.type === "email" && id.value === "alice@example.com",
    );
    expect(minimalEmail?.userId).toBe(result.minimal.id);
    expect(minimalEmail?.verified).toBe(false);
    expect(result.minimal.attributes["role"]).toBeUndefined();
    expect(passwordHashes.has(result.minimal.id)).toBe(false);

    // Full user: role merged into attributes
    expect(result.full.name).toBe("Bob");
    expect(result.full.attributes["role"]).toBe("moderator");
    expect(result.full.attributes["theme"]).toBe("dark");

    // Password was hashed and stored
    expect(passwordHashes.get(result.full.id)).toBe("test$s3cr3t");

    // Identifier records created: the primary email plus the extra username
    const idents = Array.from(identifiers.values()).filter((id) => id.userId === result.full.id);
    expect(idents).toHaveLength(2);
    const emailIdent = idents.find((id) => id.type === "email");
    const usernameIdent = idents.find((id) => id.type === "username");
    expect(emailIdent?.value).toBe("bob@example.com");
    expect(emailIdent?.verified).toBe(true);
    expect(usernameIdent?.value).toBe("bobthemod");
    expect(usernameIdent?.verified).toBe(false);

    // The store was handed each primary address to create the user with (#380).
    expect(createdWith).toEqual([
      { type: "email", value: "alice@example.com", verified: false },
      { type: "email", value: "bob@example.com", verified: true, verifiedAt: expect.any(Date) },
    ]);
  });

  it("createUser: rejects an email already claimed by another user", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "taken@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.createUser(admin, { email: "taken@example.com" })),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("AdminError");
  });

  it("createUser: normalises the primary email before it is created and claimed", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "taken@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const created = yield* service.createUser(admin, { email: "  Carol@Example.COM " });
        const duplicate = yield* Effect.result(
          service.createUser(admin, { email: "Taken@Example.com" }),
        );
        return { created, duplicate };
      }),
    );

    const claimed = Array.from(identifiers.values()).find(
      (identifier) => identifier.userId === result.created.id,
    );
    expect(claimed?.value).toBe("carol@example.com");
    expect(createdWith[0]).toEqual({ type: "email", value: "carol@example.com", verified: false });
    // A case variant of a held address is the same address.
    expect(result.duplicate._tag).toBe("Failure");
    assert(Result.isFailure(result.duplicate));
    expect(result.duplicate.failure._tag).toBe("AdminError");
  });

  it("createUser: normalises each extra identifier for its type before it is claimed (#408)", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "taken@example.com");

    const result = await runService(
      testContext,
      { normalizePhoneNumber: (raw) => Effect.succeed(raw.replace(/[^+0-9]/g, "")) },
      (service) =>
        Effect.gen(function* () {
          const created = yield* service.createUser(admin, {
            email: "dana@example.com",
            identifiers: [
              { type: "email", value: "  Dana.Work@Example.COM " },
              { type: "username", value: " DanaD " },
              { type: "phone", value: " +61 (400) 000-000 " },
            ],
          });
          // A case variant of an address another user holds is that address.
          const duplicate = yield* Effect.result(
            service.createUser(admin, {
              email: "erin@example.com",
              identifiers: [{ type: "email", value: "Taken@Example.com" }],
            }),
          );
          return { created, duplicate };
        }),
    );

    const values = Array.from(identifiers.values())
      .filter((identifier) => identifier.userId === result.created.id)
      .map((identifier) => [identifier.type, identifier.value]);
    expect(values).toEqual([
      ["email", "dana@example.com"],
      ["email", "dana.work@example.com"],
      ["username", "danad"],
      ["phone", "+61400000000"],
    ]);
    expect(result.duplicate._tag).toBe("Failure");
  });

  it("createUser: a failing phone normaliser writes nothing (#408)", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const usersBefore = users.size;

    const result = await runService(
      testContext,
      { normalizePhoneNumber: () => Effect.fail(new AuthError({ message: "not E.164" })) },
      (service) =>
        Effect.result(
          service.createUser(admin, {
            email: "frank@example.com",
            identifiers: [{ type: "phone", value: "not a number" }],
          }),
        ),
    );

    expect(result._tag).toBe("Failure");
    expect(users.size).toBe(usersBefore);
    expect(
      Array.from(identifiers.values()).some(
        (identifier) => identifier.value === "frank@example.com",
      ),
    ).toBe(false);
  });

  it("createUser: refuses when the store's writer returns the existing owner, and leaves the owner untouched (#380)", async () => {
    // A writer that finds or creates on the address: it returns the user who
    // already holds it and reports that it inserted nothing.
    const findOrCreateStore: typeof AdminUserStore.Service = {
      ...adminUserStore,
      createUser: (input) =>
        Effect.gen(function* () {
          const held =
            input.identifier === undefined
              ? null
              : yield* identifierStore.getByValue(input.identifier.type, input.identifier.value);
          const owner = held === null ? undefined : users.get(held.userId);
          if (owner !== undefined) return { user: owner, created: false };
          return yield* adminUserStore.createUser(input);
        }),
    };
    const testContext = await makeTestContext(Hooks.Default, findOrCreateStore);
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const owner: User = {
      id: "owner",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(owner.id, owner);
    const ownerEmail = makeIdentifier({
      userId: owner.id,
      type: "email",
      value: "owner@example.com",
      verified: false,
    });
    identifiers.set(ownerEmail.id, ownerEmail);
    passwordHashes.set(owner.id, "owner-hash");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(
        service.createUser(admin, {
          email: "owner@example.com",
          emailVerified: true,
          password: "attacker-password",
          identifiers: [{ type: "username", value: "attacker" }],
        }),
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("AdminError");
    // No password, no extra identifier, and the owner's address is still unverified.
    expect(passwordHashes.get(owner.id)).toBe("owner-hash");
    expect(Array.from(identifiers.values()).filter((i) => i.userId === owner.id)).toEqual([
      ownerEmail,
    ]);
    expect(Array.from(identifiers.values()).some((i) => i.value === "attacker")).toBe(false);
  });

  it("createUser: authorization failure for non-admin", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.createUser(regular, { email: "new@example.com" })),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("AdminError");
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
        const sessionManager = yield* SessionService;
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
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("UserNotFoundError");
  });

  it("setUserPassword: authorization failure for non-admin", async () => {
    const testContext = await makeTestContext();
    const regular = seedUser("user-1", "user@example.com");
    seedUser("user-2", "other@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.result(service.setUserPassword(regular, "user-2", "pass")),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("AdminError");
  });

  it("listUserSessions: returns only non-expired sessions for the target user", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");
    seedUser("user-2", "user2@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const sessionManager = yield* SessionService;
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
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("AdminError");
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
    expect(result.page.users.map((user) => emailOf(user.id))).toEqual([
      "alice@example.com",
      "bob@example.com",
    ]);
    expect(result.page.total).toBe(5);
    expect(result.searched.total).toBe(4);
    expect(result.searched.users.every((user) => emailOf(user.id).endsWith("example.com"))).toBe(
      true,
    );
    expect(result.searchedPage.users.map((user) => emailOf(user.id))).toEqual([
      "carol@example.com",
    ]);
    expect(result.searchedPage.total).toBe(4);
  });
});
