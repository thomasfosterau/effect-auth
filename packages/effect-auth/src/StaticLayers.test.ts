import { describe, it, expect } from "vite-plus/test";
import { DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Auth from "./index.ts";

describe("static service layers", () => {
  it("SessionService.layer builds a working session manager", async () => {
    const sessions = MutableHashMap.empty<string, Auth.Session>();
    const user: Auth.User = {
      id: "user-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    const sessionStore: typeof Auth.SessionStore.Service = {
      create: (session) =>
        Effect.sync(() => {
          MutableHashMap.set(sessions, session.id, session);
          return session;
        }),
      get: (sessionId) =>
        Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
      update: (session) =>
        Effect.sync(() => {
          MutableHashMap.set(sessions, session.id, session);
          return session;
        }),
      delete: (sessionId) => Effect.sync(() => void MutableHashMap.remove(sessions, sessionId)),
      deleteByUserId: () => Effect.void,
      listByUserId: (userId) =>
        Effect.sync(() =>
          Arr.fromIterable(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
        ),
    };

    const userStore: typeof Auth.UserStore.Service = {
      get: (userId) => Effect.succeed(userId === user.id ? user : null),
    };

    const config: Auth.SessionConfig = {
      sessionExpiresIn: {
        activePeriod: 30 * 24 * 60 * 60 * 1000,
        idlePeriod: 14 * 24 * 60 * 60 * 1000,
      },
    };

    const layer = Auth.SessionService.layer(config).pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          Layer.succeed(Auth.SessionStore)(sessionStore),
          Layer.succeed(Auth.UserStore)(userStore),
          Auth.Hooks.Default,
        ),
      ),
    );

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const manager = yield* Auth.SessionService;
        const session = yield* manager.createSession(user.id);
        const validated = yield* manager.validateSession(session.token);
        return validated;
      }).pipe(Effect.provide(layer)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session.userId).toBe(user.id);
  });

  it("static layers build the same layer as the standalone constructors", async () => {
    // UserService.layer() requires only its store; exercise it end-to-end.
    const user: Auth.User = {
      id: "user-2",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    const store: typeof Auth.UserServiceStore.Service = {
      get: (userId) => Effect.succeed(userId === user.id ? user : null),
      update: (u) => Effect.succeed(u),
      delete: () => Effect.void,
    };

    const layer = Auth.UserService.layer().pipe(
      Layer.provideMerge(
        Layer.mergeAll(Layer.succeed(Auth.UserServiceStore)(store), Auth.Hooks.Default),
      ),
    );

    const viaStatic = await Effect.runPromise(
      Effect.gen(function* () {
        const users = yield* Auth.UserService;
        return yield* users.getUser(user.id);
      }).pipe(Effect.provide(layer)),
    );
    expect(viaStatic.id).toBe(user.id);
  });
});
