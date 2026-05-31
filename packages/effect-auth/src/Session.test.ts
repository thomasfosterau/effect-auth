import { describe, it, expect } from "vite-plus/test";
import { Effect, Context } from "effect";
import { Hooks } from "./Hooks.js";
import { makeSessionManager, SessionStore, UserStore } from "./Session.js";
import type { Session, User, SessionConfig } from "./Types.js";
import { SessionNotFoundError, UserNotFoundError } from "./Errors.js";

// Mock implementations for testing
const mockSessionStore = {
  sessions: new Map<string, Session>(),

  create: (session: Session) =>
    Effect.sync(() => {
      mockSessionStore.sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.gen(function* () {
      const session = mockSessionStore.sessions.get(sessionId);
      if (!session) {
        return yield* Effect.fail(
          new SessionNotFoundError({
            message: "Session not found",
            sessionId,
          }),
        );
      }
      return session;
    }),

  update: (session: Session) =>
    Effect.sync(() => {
      mockSessionStore.sessions.set(session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      mockSessionStore.sessions.delete(sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [id, session] of mockSessionStore.sessions.entries()) {
        if (session.userId === userId) {
          mockSessionStore.sessions.delete(id);
        }
      }
    }),
};

const mockUserStore = {
  users: new Map<string, User>([
    ["user1", { id: "user1", attributes: { name: "Test User" } }],
    ["user2", { id: "user2", attributes: { name: "Another User" } }],
  ]),

  get: (userId: string) =>
    Effect.gen(function* () {
      const user = mockUserStore.users.get(userId);
      if (!user) {
        return yield* Effect.fail(
          new UserNotFoundError({
            message: "User not found",
            userId,
          }),
        );
      }
      return user;
    }),

  getCredentials: (userId: string) => Effect.succeed("hashed-password"),
};

const SessionStoreTest = Context.make(SessionStore, mockSessionStore);
const UserStoreTest = Context.make(UserStore, mockUserStore);

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days
  },
};

describe("SessionManager", () => {
  it("should create a new session", async () => {
    const program = Effect.gen(function* () {
      const manager = yield* makeSessionManager(sessionConfig);
      return yield* manager.createSession("user1", { ip: "127.0.0.1" });
    });

    const session = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Hooks.Default),
      ),
    );

    expect(session.id).toBeDefined();
    expect(session.userId).toBe("user1");
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.attributes.ip).toBe("127.0.0.1");
  });

  it("should validate a valid session", async () => {
    // Clear mock store
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* makeSessionManager(sessionConfig);
      const session = yield* manager.createSession("user1");
      return yield* manager.validateSession(session.id);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Hooks.Default),
      ),
    );

    expect(result.session.userId).toBe("user1");
    expect(result.user.id).toBe("user1");
    expect(result.user.attributes.name).toBe("Test User");
  });

  it("should fail to validate expired session", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* makeSessionManager({
        sessionExpiresIn: {
          activePeriod: -1000, // Already expired
          idlePeriod: -1000,
        },
      });
      const session = yield* manager.createSession("user1");
      return yield* manager.validateSession(session.id);
    });

    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
          Effect.provide(Hooks.Default),
        ),
      ),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("SessionExpiredError");
    }
  });

  it("should invalidate a session", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* makeSessionManager(sessionConfig);
      const session = yield* manager.createSession("user1");
      yield* manager.invalidateSession(session.id);
      return yield* manager.validateSession(session.id);
    });

    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
          Effect.provide(Hooks.Default),
        ),
      ),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("SessionNotFoundError");
    }
  });

  it("should invalidate all user sessions", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* makeSessionManager(sessionConfig);
      const session1 = yield* manager.createSession("user1");
      const session2 = yield* manager.createSession("user1");
      const session3 = yield* manager.createSession("user2");

      yield* manager.invalidateUserSessions("user1");

      const result1 = yield* Effect.result(manager.validateSession(session1.id));
      const result2 = yield* Effect.result(manager.validateSession(session2.id));
      const result3 = yield* manager.validateSession(session3.id);

      return { result1, result2, result3 };
    });

    const results = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Hooks.Default),
      ),
    );

    // User1 sessions should be invalidated
    expect(results.result1._tag).toBe("Failure");
    expect(results.result2._tag).toBe("Failure");
    // User2 session should still be valid
    expect(results.result3.user.id).toBe("user2");
  });
});
