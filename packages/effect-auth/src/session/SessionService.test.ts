import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Context, Layer } from "effect";
import { Hooks } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { make } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { hashToken } from "../TokenHash.ts";
import type { Session, User, SessionConfig } from "../Types.ts";

// Mock implementations for testing
const mockSessionStore = {
  sessions: new Map<string, Session>(),

  create: (session: Session) =>
    Effect.sync(() => {
      mockSessionStore.sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) => Effect.sync(() => mockSessionStore.sessions.get(sessionId) ?? null),

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

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(mockSessionStore.sessions.values()).filter((session) => session.userId === userId),
    ),
};

const mockUserStore = {
  users: new Map<string, User>([
    [
      "user1",
      {
        id: "user1",
        email: "user1@example.com",
        emailVerified: false,
        name: "Test User",
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      },
    ],
    [
      "user2",
      {
        id: "user2",
        email: "user2@example.com",
        emailVerified: false,
        name: "Another User",
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      },
    ],
  ]),

  get: (userId: string) => Effect.sync(() => mockUserStore.users.get(userId) ?? null),

  getCredentials: (_userId: string) => Effect.succeed("hashed-password"),
};

const SessionStoreTest = Context.make(SessionStore, mockSessionStore);
const UserStoreTest = Context.make(UserStore, mockUserStore);

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days
  },
};

describe("SessionService", () => {
  it("should create a new session", async () => {
    const program = Effect.gen(function* () {
      const manager = yield* make(sessionConfig);
      return yield* manager.createSession("user1", { ip: "127.0.0.1" });
    });

    const session = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
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
      const manager = yield* make(sessionConfig);
      const session = yield* manager.createSession("user1");
      return yield* manager.validateSession(session.id);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
      ),
    );

    expect(result.session.userId).toBe("user1");
    expect(result.user.id).toBe("user1");
    expect(result.user.name).toBe("Test User");
  });

  it("should fail to validate expired session", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* make({
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
          Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
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
      const manager = yield* make(sessionConfig);
      const session = yield* manager.createSession("user1");
      yield* manager.invalidateSession(session.id);
      return yield* manager.validateSession(session.id);
    });

    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
          Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
        ),
      ),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("SessionNotFoundError");
    }
  });

  it("create→validate round-trip: store keyed by hash, cookie carries raw token", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* make(sessionConfig);
      const session = yield* manager.createSession("user1");

      const rawToken = session.id;
      const storedKeys = Array.from(mockSessionStore.sessions.keys());

      // The store must not contain the raw token — only its hash.
      const validated = yield* manager.validateSession(rawToken);

      return { rawToken, storedKeys, validated };
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.merge(SessionStoreTest, UserStoreTest)).pipe(
        Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
      ),
    );

    // Raw token is not a key in the store — only the hash is.
    expect(result.storedKeys).not.toContain(result.rawToken);
    expect(result.storedKeys).toHaveLength(1);
    expect(result.storedKeys[0]).toBe(hashToken(result.rawToken));
    // Validation succeeds and returns the raw token as session.id.
    expect(result.validated.session.id).toBe(result.rawToken);
    expect(result.validated.user.id).toBe("user1");
  });

  describe("updateAge write-throttle", () => {
    beforeEach(() => {
      mockSessionStore.sessions.clear();
    });

    it("writes to the store when no updateAge is configured (default: always write)", async () => {
      let updateCallCount = 0;
      const trackingStore = {
        ...mockSessionStore,
        update: (session: Session) => {
          updateCallCount++;
          return mockSessionStore.update(session);
        },
      };

      const program = Effect.gen(function* () {
        const manager = yield* make(sessionConfig);
        const session = yield* manager.createSession("user1");
        yield* manager.validateSession(session.id);
        yield* manager.validateSession(session.id);
      });

      await Effect.runPromise(
        Effect.provide(
          program,
          Context.merge(
            Context.make(SessionStore, trackingStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(2);
    });

    it("skips the store write when the session was refreshed within updateAge", async () => {
      let updateCallCount = 0;
      const trackingStore = {
        ...mockSessionStore,
        update: (session: Session) => {
          updateCallCount++;
          return mockSessionStore.update(session);
        },
      };

      const configWithUpdateAge: SessionConfig = {
        sessionExpiresIn: {
          activePeriod: 1000 * 60 * 60 * 24 * 30,
          idlePeriod: 1000 * 60 * 60 * 24 * 14,
          updateAge: 1000 * 60 * 60 * 24, // 1 day threshold
        },
      };

      const program = Effect.gen(function* () {
        const manager = yield* make(configWithUpdateAge);
        const session = yield* manager.createSession("user1");
        // First validate: session was just created (lastActivityAt = now), so
        // timeSinceUpdate ≈ 0 which is < updateAge → write is skipped.
        yield* manager.validateSession(session.id);
        // Second validate immediately: still within updateAge → write skipped.
        yield* manager.validateSession(session.id);
      });

      await Effect.runPromise(
        Effect.provide(
          program,
          Context.merge(
            Context.make(SessionStore, trackingStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(0);
    });

    it("writes to the store once the updateAge window has elapsed", async () => {
      let updateCallCount = 0;
      const sessions = new Map<string, Session>();
      const timedStore = {
        create: (session: Session) =>
          Effect.sync(() => {
            sessions.set(session.id, session);
            return session;
          }),
        get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),
        update: (session: Session) =>
          Effect.sync(() => {
            updateCallCount++;
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
              if (session.userId === userId) sessions.delete(id);
            }
          }),
        listByUserId: (userId: string) =>
          Effect.sync(() => Array.from(sessions.values()).filter((s) => s.userId === userId)),
      };

      const configWithShortUpdateAge: SessionConfig = {
        sessionExpiresIn: {
          activePeriod: 1000 * 60 * 60 * 24 * 30,
          idlePeriod: 1000 * 60 * 60 * 24 * 14,
          updateAge: 100, // 100ms threshold — easy to exceed in a test
        },
      };

      const program = Effect.gen(function* () {
        const manager = yield* make(configWithShortUpdateAge);
        const session = yield* manager.createSession("user1");
        // First validate: created just now, timeSinceUpdate ≈ 0 < 100ms → skip.
        yield* manager.validateSession(session.id);
        return session.id;
      });

      const rawToken = await Effect.runPromise(
        Effect.provide(
          program,
          Context.merge(
            Context.make(SessionStore, timedStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(0);

      // Manually age the session's lastActivityAt beyond the updateAge threshold.
      const tokenHash = hashToken(rawToken);
      const stored = sessions.get(tokenHash)!;
      sessions.set(tokenHash, {
        ...stored,
        lastActivityAt: new Date(stored.lastActivityAt.getTime() - 200),
      });

      const program2 = Effect.gen(function* () {
        const manager = yield* make(configWithShortUpdateAge);
        yield* manager.validateSession(rawToken);
      });

      await Effect.runPromise(
        Effect.provide(
          program2,
          Context.merge(
            Context.make(SessionStore, timedStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(1);
    });

    it("still enforces expiry even when write is throttled", async () => {
      const sessions = new Map<string, Session>();
      const timedStore = {
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
              if (session.userId === userId) sessions.delete(id);
            }
          }),
        listByUserId: (userId: string) =>
          Effect.sync(() => Array.from(sessions.values()).filter((s) => s.userId === userId)),
      };

      // updateAge is very long (1 year), so writes are always throttled.
      // But the session itself has a tiny activePeriod so it expires immediately.
      const program = Effect.gen(function* () {
        const manager = yield* make({
          sessionExpiresIn: {
            activePeriod: -1000, // already expired
            idlePeriod: -1000,
            updateAge: 365 * 24 * 60 * 60 * 1000, // 1 year — throttle always active
          },
        });
        const session = yield* manager.createSession("user1");
        return yield* manager.validateSession(session.id);
      });

      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            program,
            Context.merge(
              Context.make(SessionStore, timedStore),
              Context.make(UserStore, mockUserStore),
            ),
          ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
        ),
      );

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("SessionExpiredError");
      }
    });
  });

  it("should invalidate all user sessions", async () => {
    mockSessionStore.sessions.clear();

    const program = Effect.gen(function* () {
      const manager = yield* make(sessionConfig);
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
        Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer)),
      ),
    );

    // User1 sessions should be invalidated
    expect(results.result1._tag).toBe("Failure");
    expect(results.result2._tag).toBe("Failure");
    // User2 session should still be valid
    expect(results.result3.user.id).toBe("user2");
  });
});
