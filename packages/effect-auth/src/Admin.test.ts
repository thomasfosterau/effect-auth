import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { TestClock } from "effect/testing";
import { Context, DateTime, Effect, Layer, MutableHashMap, Order, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import { SecureRandom } from "effect/crypto";
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

const users = MutableHashMap.empty<string, User>();
const sessions = MutableHashMap.empty<string, Session>();
const identifiers = MutableHashMap.empty<string, Identifier>();
const passwordHashes = MutableHashMap.empty<string, string>();
/** The `identifier` each `createUser` call was given. */
const createdWith: Array<NewUserIdentifier | undefined> = [];

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),

  update: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(sessions, sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(sessions, (session, id) => {
        if (session.userId === userId) {
          MutableHashMap.remove(sessions, id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(sessions)).filter((session) => session.userId === userId),
    ),
};

const getUser = (userId: string) =>
  Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId)));

// Session's UserStore (used by SessionService.validateSession)
const sessionUserStore = {
  get: getUser,
};

const userServiceStore = {
  get: getUser,

  update: (user: User) =>
    Effect.sync(() => {
      MutableHashMap.set(users, user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(users, userId);
    }),
};

/** Earliest email identifier value for a user, mirroring how a SQL store
 * would resolve the email-of-record from its identifier records. */
const emailOf = (userId: string): string =>
  Arr.sort(
    Array.from(MutableHashMap.values(identifiers)).filter(
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
        Array.from(MutableHashMap.values(users)).filter((user) =>
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
      const id = `user-${MutableHashMap.size(users) + 1}`;
      const user: User = {
        id,
        name: input.name,
        image: input.image,
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: input.attributes ?? {},
      };
      MutableHashMap.set(users, id, user);
      return { user, created: true };
    }),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      MutableHashMap.set(passwordHashes, userId, hash);
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
        Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
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
    Context.add(SecureRandom.SecureRandom, PlatformCrypto.instance),
  );
};

const seedUser = (id: string, email: string, attributes: Attributes = {}): User => {
  const user: User = {
    id,
    createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    attributes,
  };
  MutableHashMap.set(users, id, user);
  const identifier = makeIdentifier({
    userId: id,
    type: "email",
    value: email,
    verified: true,
    verifiedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifiers, identifier.id, identifier);
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
    MutableHashMap.clear(users);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(identifiers);
    MutableHashMap.clear(passwordHashes);
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

    Arr.forEach(R.values(result), (outcome) => {
      expect(outcome._tag).toBe("Failure");
      assert(P.isTagged(outcome, "Failure"));
      expect(outcome.failure._tag).toBe("AdminError");
    });
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

  it("answers isAdmin under its own config, the rule the HTTP admin gates ask (#680)", async () => {
    const roleAdmin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const superuser = seedUser("super-1", "super@example.com", { role: "superuser" });
    const byId = seedUser("root-1", "root@example.com");

    const testContext = await makeTestContext();
    const answers = await runService(
      testContext,
      { adminRoles: ["superuser"], adminUserIds: ["root-1"] },
      (service) =>
        Effect.succeed([roleAdmin, superuser, byId].map((user) => service.isAdmin(user))),
    );
    expect(answers).toEqual([false, true, true]);
    const defaults = await runService(testContext, {}, (service) =>
      Effect.succeed([roleAdmin, superuser, byId].map((user) => service.isAdmin(user))),
    );
    expect(defaults).toEqual([true, false, false]);
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
    const stored = Option.getOrUndefined(MutableHashMap.get(users, "user-1"));
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
    expect(Option.getOrUndefined(MutableHashMap.get(users, "user-1"))?.attributes["role"]).toBe(
      "user",
    );

    const promoted = await runService(testContext, { roles }, (service) =>
      service.setRole(admin, "user-1", "moderator"),
    );
    expect(promoted.attributes["role"]).toBe("moderator");
  });

  it("checks createUser's role whichever door it comes in by (#193)", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const roles = Ladder.make(["user", "admin"]);

    await Arr.reduce(
      [
        { email: "a@example.com", role: "root" },
        { email: "b@example.com", attributes: { role: "root" } },
        { email: "c@example.com", attributes: { role: 7 } },
      ],
      Promise.resolve(),
      async (previous, input) => {
        await previous;
        const refused = await runService(testContext, { roles }, (service) =>
          Effect.flip(service.createUser(admin, input)),
        );
        expect(refused._tag, input.email).toBe("AdminError");
      },
    );
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
        const sessionsBefore = MutableHashMap.size(sessions);

        const banned = yield* service.banUser(admin, "user-1", { reason: "Spamming" });
        const sessionsAfter = MutableHashMap.size(sessions);

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
    expect(Effect.runSync(isBanned(result.banned))).toBe(true);
    expect(result.banSelf._tag).toBe("Failure");
    expect(result.banAdmin._tag).toBe("Failure");
    const storedAdmin = Option.getOrUndefined(MutableHashMap.get(users, "admin-2"));
    assert(storedAdmin !== undefined, "admin-2 is seeded");
    expect(Effect.runSync(isBanned(storedAdmin))).toBe(false);
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
    assert(P.isNumber(banExpires));
    expect(banExpires).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
    expect(Effect.runSync(isBanned(banned))).toBe(true);
  });

  it("reads ban expiry from the Clock, so TestClock decides when a ban lapses", async () => {
    const user: User = {
      id: "user-clock",
      createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      updatedAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      attributes: { banned: true, banExpires: 10_000 },
    };
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        yield* TestClock.setTime(9_999);
        const before = yield* isBanned(user);
        yield* TestClock.setTime(10_000);
        const at = yield* isBanned(user);
        return { before, at };
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(result).toEqual({ before: true, at: false });
  });

  it("treats an expired ban as not banned and unbans cleanly", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const result = await runService(testContext, {}, (service) =>
      Effect.gen(function* () {
        const expired = yield* service.banUser(admin, "user-1", { expiresIn: -1000 });
        const bannedWhileExpired = yield* isBanned(expired);

        const permanent = yield* service.banUser(admin, "user-1");
        const bannedPermanent = yield* isBanned(permanent);

        const unbanned = yield* service.unbanUser(admin, "user-1");
        return { bannedWhileExpired, bannedPermanent, unbanned };
      }),
    );

    expect(result.bannedWhileExpired).toBe(false);
    expect(result.bannedPermanent).toBe(true);
    expect(result.unbanned.attributes["banned"]).toBe(false);
    expect(result.unbanned.attributes["banReason"]).toBeUndefined();
    expect(result.unbanned.attributes["banExpires"]).toBeUndefined();
    expect(Effect.runSync(isBanned(result.unbanned))).toBe(false);
  });

  it("BannedUserPlugin blocks session validation for banned users", async () => {
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    // SessionService now resolves Hooks once, at construction time, so the
    // plugin must be baked in when building the SessionService instance used
    // by this test rather than layered over the whole program afterward.
    const hooksWithPlugin = BannedUserPlugin.pipe(Layer.provide(Hooks.Default));
    const testContext = await makeTestContext(hooksWithPlugin);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* Admin.make({});
          const sessionManager = yield* SessionService;

          // Ban first (revokes existing sessions), then mint a fresh session to
          // prove the plugin blocks validation even when a session exists.
          yield* service.banUser(admin, "user-1");
          const bannedSession = yield* sessionManager.createSession("user-1");
          const blocked = yield* Effect.result(sessionManager.validateSession(bannedSession.token));

          yield* service.unbanUser(admin, "user-1");
          const allowed = yield* sessionManager.validateSession(bannedSession.token);

          // A ban that has already lapsed does not block validation
          yield* service.banUser(admin, "user-1", { expiresIn: -1000 });
          const lapsedSession = yield* sessionManager.createSession("user-1");
          const lapsed = yield* Effect.result(sessionManager.validateSession(lapsedSession.token));

          return { blocked, allowed, lapsed };
        }),
        testContext,
      ),
    );

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
    expect(MutableHashMap.has(users, "admin-1")).toBe(true);
    expect(MutableHashMap.has(users, "user-1")).toBe(false);
    expect(MutableHashMap.size(sessions)).toBe(0);
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

    const remaining = Array.from(MutableHashMap.values(sessions));
    expect(remaining).toHaveLength(1);
    expect(remaining[0].userId).toBe("user-2");
  });

  it("creates impersonation sessions with the expected attributes", async () => {
    const testContext = await makeTestContext();
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    seedUser("user-1", "user@example.com");

    const before = DateTime.toEpochMillis(DateTime.nowUnsafe());
    const { session, token } = await runService(
      testContext,
      { impersonationSessionDuration: 15 * 60 * 1000 },
      (service) => service.impersonateUser(admin, "user-1"),
    );
    // The record carries the stored id; the token travels beside it (#581).
    expect(session.id).toBe(hashToken(token));

    expect(session.userId).toBe("user-1");
    expect(session.attributes["impersonatedBy"]).toBe("admin-1");
    const impersonationExpiresAt = session.attributes["impersonationExpiresAt"];
    assert(P.isNumber(impersonationExpiresAt));
    expect(impersonationExpiresAt).toBeGreaterThanOrEqual(before + 15 * 60 * 1000);
    expect(MutableHashMap.has(sessions, session.id)).toBe(true);

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
    const minimalEmail = Array.from(MutableHashMap.values(identifiers)).find(
      (id) => id.type === "email" && id.value === "alice@example.com",
    );
    expect(minimalEmail?.userId).toBe(result.minimal.id);
    expect(minimalEmail?.verified).toBe(false);
    expect(result.minimal.attributes["role"]).toBeUndefined();
    expect(MutableHashMap.has(passwordHashes, result.minimal.id)).toBe(false);

    // Full user: role merged into attributes
    expect(result.full.name).toBe("Bob");
    expect(result.full.attributes["role"]).toBe("moderator");
    expect(result.full.attributes["theme"]).toBe("dark");

    // Password was hashed and stored
    expect(Option.getOrUndefined(MutableHashMap.get(passwordHashes, result.full.id))).toBe(
      "test$s3cr3t",
    );

    // Identifier records created: the primary email plus the extra username
    const idents = Array.from(MutableHashMap.values(identifiers)).filter(
      (id) => id.userId === result.full.id,
    );
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

    const claimed = Array.from(MutableHashMap.values(identifiers)).find(
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

    const values = Array.from(MutableHashMap.values(identifiers))
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
    const usersBefore = MutableHashMap.size(users);

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
    expect(MutableHashMap.size(users)).toBe(usersBefore);
    expect(
      Array.from(MutableHashMap.values(identifiers)).some(
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
          const owner =
            held === null
              ? undefined
              : Option.getOrUndefined(MutableHashMap.get(users, held.userId));
          if (owner !== undefined) return { user: owner, created: false };
          return yield* adminUserStore.createUser(input);
        }),
    };
    const testContext = await makeTestContext(Hooks.Default, findOrCreateStore);
    const admin = seedUser("admin-1", "admin@example.com", { role: "admin" });
    const owner: User = {
      id: "owner",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, owner.id, owner);
    const ownerEmail = makeIdentifier({
      userId: owner.id,
      type: "email",
      value: "owner@example.com",
      verified: false,
      now: DateTime.toDateUtc(DateTime.nowUnsafe()),
    });
    MutableHashMap.set(identifiers, ownerEmail.id, ownerEmail);
    MutableHashMap.set(passwordHashes, owner.id, "owner-hash");

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
    expect(Option.getOrUndefined(MutableHashMap.get(passwordHashes, owner.id))).toBe("owner-hash");
    expect(
      Array.from(MutableHashMap.values(identifiers)).filter((i) => i.userId === owner.id),
    ).toEqual([ownerEmail]);
    expect(Array.from(MutableHashMap.values(identifiers)).some((i) => i.value === "attacker")).toBe(
      false,
    );
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

    expect(Option.getOrUndefined(MutableHashMap.get(passwordHashes, "user-1"))).toBe(
      "test$newpassword",
    );
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
        const afterNoRevoke = MutableHashMap.size(sessions);

        // With revoke: user-1's sessions are revoked, user-2's remain
        yield* service.setUserPassword(admin, "user-1", "pass2", { revokeOtherSessions: true });
        return { afterNoRevoke };
      }),
    );

    expect(MutableHashMap.size(sessions)).toBe(1);
    const remaining = Array.from(MutableHashMap.values(sessions));
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
          expiresAt: DateTime.toDateUtc(
            DateTime.subtract(yield* DateTime.now, { milliseconds: 1000 }),
          ),
          createdAt: yield* DateTime.nowAsDate,
          lastActivityAt: yield* DateTime.nowAsDate,
          attributes: {},
        };
        MutableHashMap.set(sessions, "expired-hash", expiredSession);

        return yield* service.listUserSessions(admin, "user-1");
      }),
    );

    // Only non-expired sessions for user-1 are returned
    expect(result.length).toBe(2);
    expect(result.every((s) => s.userId === "user-1")).toBe(true);
    expect(
      result.every((s) => s.expiresAt.getTime() > DateTime.toEpochMillis(DateTime.nowUnsafe())),
    ).toBe(true);
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
