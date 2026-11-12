import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, DateTime, Effect, Layer, MutableHashMap, Result } from "effect";
import * as Option from "effect/Option";
import { Hooks, makePlugin, type SessionRef } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { make } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import type { Session, User, SessionConfig } from "./Types.ts";

// Mock implementations for testing
const mockSessionStore = {
  sessions: MutableHashMap.empty<string, Session>(),

  create: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(mockSessionStore.sessions, session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(mockSessionStore.sessions, sessionId))),

  update: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(mockSessionStore.sessions, session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(mockSessionStore.sessions, sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(mockSessionStore.sessions, (session, id) => {
        if (session.userId === userId) {
          MutableHashMap.remove(mockSessionStore.sessions, id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(mockSessionStore.sessions)).filter(
        (session) => session.userId === userId,
      ),
    ),
};

const mockUserStore = {
  users: MutableHashMap.fromIterable<string, User>([
    [
      "user1",
      {
        id: "user1",
        name: "Test User",
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: {},
      },
    ],
    [
      "user2",
      {
        id: "user2",
        name: "Another User",
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: {},
      },
    ],
  ]),

  get: (userId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(mockUserStore.users, userId))),
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
    const { session, token } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          return yield* manager.createSession("user1", { ip: "127.0.0.1" });
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    // The record carries the stored id; the token travels beside it (#581).
    expect(session.id).toBe(hashToken(token));
    expect(token).toMatch(/^[0-9a-f]{40}$/);
    expect(session.userId).toBe("user1");
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.attributes.ip).toBe("127.0.0.1");
  });

  it("should validate a valid session", async () => {
    // Clear mock store
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const session = yield* manager.createSession("user1");
          return yield* manager.validateSession(session.token);
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    expect(result.session.userId).toBe("user1");
    expect(result.user.id).toBe("user1");
    expect(result.user.name).toBe("Test User");
  });

  it("should fail to validate expired session", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make({
              sessionExpiresIn: {
                activePeriod: -1000, // Already expired
                idlePeriod: -1000,
              },
            });
            const session = yield* manager.createSession("user1");
            return yield* manager.validateSession(session.token);
          }),
          Context.merge(SessionStoreTest, UserStoreTest),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      ),
    );

    expect(result._tag).toBe("Failure");

    assert(Result.isFailure(result));

    expect(result.failure._tag).toBe("SessionExpiredError");
  });

  it("should invalidate a session", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.result(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make(sessionConfig);
            const session = yield* manager.createSession("user1");
            yield* manager.invalidateSession(session.token);
            return yield* manager.validateSession(session.token);
          }),
          Context.merge(SessionStoreTest, UserStoreTest),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      ),
    );

    expect(result._tag).toBe("Failure");

    assert(Result.isFailure(result));

    expect(result.failure._tag).toBe("SessionNotFoundError");
  });

  it("create→validate round-trip: store keyed by hash, only the token is the credential", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const { session, token } = yield* manager.createSession("user1");
          const storedKeys = Array.from(MutableHashMap.keys(mockSessionStore.sessions));
          const validated = yield* manager.validateSession(token);
          // The stored id is not a credential: presenting it finds nothing.
          const byStoredId = yield* Effect.result(manager.validateSession(session.id));
          return { token, session, storedKeys, validated, byStoredId };
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    // The raw token is not a key in the store, only its hash is.
    expect(result.storedKeys).not.toContain(result.token);
    expect(result.storedKeys).toEqual([hashToken(result.token)]);
    // Validation answers the session under its stored id, never the token (#581).
    expect(result.validated.session.id).toBe(hashToken(result.token));
    expect(result.validated.session.id).toBe(result.session.id);
    expect(result.validated.user.id).toBe("user1");
    expect(Result.isFailure(result.byStoredId)).toBe(true);
  });

  it("revokeOtherSessions keeps the session with the given stored id", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const kept = yield* manager.createSession("user1");
          const other = yield* manager.createSession("user1");
          yield* manager.revokeOtherSessions("user1", kept.session.id);
          return {
            kept: yield* Effect.result(manager.validateSession(kept.token)),
            other: yield* Effect.result(manager.validateSession(other.token)),
          };
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    expect(Result.isSuccess(result.kept)).toBe(true);
    expect(Result.isFailure(result.other)).toBe(true);
  });

  it("setSessionAttributes addresses the session by its stored id", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const { session, token } = yield* manager.createSession("user1");
          const updated = yield* manager.setSessionAttributes(session.id, { theme: "dark" });
          const byToken = yield* Effect.result(
            manager.setSessionAttributes(token, { theme: "light" }),
          );
          return { session, updated, byToken };
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    expect(result.updated.id).toBe(result.session.id);
    expect(result.updated.attributes["theme"]).toBe("dark");
    // The raw token names no stored session.
    assert(Result.isFailure(result.byToken));
    expect(result.byToken.failure._tag).toBe("SessionNotFoundError");
  });

  it("afterSignOut observes the stored id, never the token", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);
    const seen: Array<string> = [];
    const hooks = makePlugin({
      afterSignOut: Hooks.tap((ref: SessionRef) =>
        Effect.sync(() => void seen.push(ref.sessionId)),
      ),
    }).pipe(Layer.provide(Hooks.Default));

    const { session, token } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const issued = yield* manager.createSession("user1");
          yield* manager.invalidateSession(issued.token);
          return issued;
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(hooks, PlatformCrypto.layer))),
    );

    expect(seen).toEqual([session.id]);
    expect(seen).not.toContain(token);
  });

  describe("updateAge write-throttle", () => {
    beforeEach(() => {
      MutableHashMap.clear(mockSessionStore.sessions);
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

      await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make(sessionConfig);
            const session = yield* manager.createSession("user1");
            yield* manager.validateSession(session.token);
            yield* manager.validateSession(session.token);
          }),
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

      await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make(configWithUpdateAge);
            const session = yield* manager.createSession("user1");
            // First validate: session was just created (lastActivityAt = now), so
            // timeSinceUpdate ≈ 0 which is < updateAge → write is skipped.
            yield* manager.validateSession(session.token);
            // Second validate immediately: still within updateAge → write skipped.
            yield* manager.validateSession(session.token);
          }),
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
      const sessions = MutableHashMap.empty<string, Session>();
      const timedStore = {
        create: (session: Session) =>
          Effect.sync(() => {
            MutableHashMap.set(sessions, session.id, session);
            return session;
          }),
        get: (sessionId: string) =>
          Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
        update: (session: Session) =>
          Effect.sync(() => {
            updateCallCount++;
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
              if (session.userId === userId) MutableHashMap.remove(sessions, id);
            });
          }),
        listByUserId: (userId: string) =>
          Effect.sync(() =>
            Array.from(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
          ),
      };

      const configWithShortUpdateAge: SessionConfig = {
        sessionExpiresIn: {
          activePeriod: 1000 * 60 * 60 * 24 * 30,
          idlePeriod: 1000 * 60 * 60 * 24 * 14,
          updateAge: 100, // 100ms threshold — easy to exceed in a test
        },
      };

      const rawToken = await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make(configWithShortUpdateAge);
            const session = yield* manager.createSession("user1");
            // First validate: created just now, timeSinceUpdate ≈ 0 < 100ms → skip.
            yield* manager.validateSession(session.token);
            return session.token;
          }),
          Context.merge(
            Context.make(SessionStore, timedStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(0);

      // Manually age the session's lastActivityAt beyond the updateAge threshold.
      const tokenHash = hashToken(rawToken);
      const stored = Option.getOrUndefined(MutableHashMap.get(sessions, tokenHash));
      assert(stored !== undefined, "the session is stored");

      MutableHashMap.set(sessions, tokenHash, {
        ...stored,
        lastActivityAt: DateTime.toDateUtc(
          DateTime.makeUnsafe(stored.lastActivityAt.getTime() - 200),
        ),
      });

      await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const manager = yield* make(configWithShortUpdateAge);
            yield* manager.validateSession(rawToken);
          }),
          Context.merge(
            Context.make(SessionStore, timedStore),
            Context.make(UserStore, mockUserStore),
          ),
        ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
      );

      expect(updateCallCount).toBe(1);
    });

    it("still enforces expiry even when write is throttled", async () => {
      const sessions = MutableHashMap.empty<string, Session>();
      const timedStore = {
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
              if (session.userId === userId) MutableHashMap.remove(sessions, id);
            });
          }),
        listByUserId: (userId: string) =>
          Effect.sync(() =>
            Array.from(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
          ),
      };

      // updateAge is very long (1 year), so writes are always throttled.
      // But the session itself has a tiny activePeriod so it expires immediately.

      const result = await Effect.runPromise(
        Effect.result(
          Effect.provide(
            Effect.gen(function* () {
              const manager = yield* make({
                sessionExpiresIn: {
                  activePeriod: -1000, // already expired
                  idlePeriod: -1000,
                  updateAge: 365 * 24 * 60 * 60 * 1000, // 1 year — throttle always active
                },
              });
              const session = yield* manager.createSession("user1");
              return yield* manager.validateSession(session.token);
            }),
            Context.merge(
              Context.make(SessionStore, timedStore),
              Context.make(UserStore, mockUserStore),
            ),
          ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
        ),
      );

      expect(result._tag).toBe("Failure");

      assert(Result.isFailure(result));

      expect(result.failure._tag).toBe("SessionExpiredError");
    });
  });

  it("should invalidate all user sessions", async () => {
    MutableHashMap.clear(mockSessionStore.sessions);

    const results = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const manager = yield* make(sessionConfig);
          const session1 = yield* manager.createSession("user1");
          const session2 = yield* manager.createSession("user1");
          const session3 = yield* manager.createSession("user2");

          yield* manager.invalidateUserSessions("user1");

          const result1 = yield* Effect.result(manager.validateSession(session1.token));
          const result2 = yield* Effect.result(manager.validateSession(session2.token));
          const result3 = yield* manager.validateSession(session3.token);

          return { result1, result2, result3 };
        }),
        Context.merge(SessionStoreTest, UserStoreTest),
      ).pipe(Effect.provide(Layer.merge(Hooks.Default, PlatformCrypto.layer))),
    );

    // User1 sessions should be invalidated
    expect(results.result1._tag).toBe("Failure");
    expect(results.result2._tag).toBe("Failure");
    // User2 session should still be valid
    expect(results.result3.user.id).toBe("user2");
  });
});
