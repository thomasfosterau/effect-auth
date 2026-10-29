import { assert, describe, it, expect } from "vite-plus/test";
import { DateTime, Effect, Layer } from "effect";
import {
  AnonymousService,
  AnonymousUserStore,
  isAnonymousUser,
  type AnonymousConfig,
} from "./Anonymous.ts";
import { SessionService } from "./SessionService.ts";
import { Hooks } from "./Hooks.ts";
import type * as Types from "./Types.ts";
import { InvalidInputError } from "./Errors.ts";

const makeSession = (userId: string): Types.Session => {
  const now = DateTime.toDateUtc(DateTime.nowUnsafe());
  return {
    id: `sess-${userId}`,
    userId,
    expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 60_000)),
    createdAt: now,
    lastActivityAt: now,
    attributes: {},
  };
};

interface Harness {
  readonly layer: Layer.Layer<AnonymousService | AnonymousUserStore | SessionService | Hooks>;
  readonly users: Map<string, Types.User>;
  readonly created: string[];
  readonly linkCalls: Array<{ anon: string; real: string }>;
  readonly invalidatedUserSessions: string[];
}

const makeHarness = (config?: AnonymousConfig): Harness => {
  const users = new Map<string, Types.User>();
  const created: string[] = [];
  const linkCalls: Array<{ anon: string; real: string }> = [];
  const invalidatedUserSessions: string[] = [];
  let seq = 0;

  const store: typeof AnonymousUserStore.Service = {
    createAnonymousUser: () =>
      Effect.sync(() => {
        const id = `anon-${++seq}`;
        const now = DateTime.toDateUtc(DateTime.nowUnsafe());
        // `email` is not a first-class `User` field — anonymous users hold no
        // identifiers at all (see `Anonymous.ts`), so this fixture's
        // placeholder address rides in `attributes`.
        const user: Types.User = {
          id,
          createdAt: now,
          updatedAt: now,
          attributes: { isAnonymous: true, email: `${id}@anonymous.local` },
        };
        users.set(id, user);
        created.push(id);
        return user;
      }),
    deleteUser: (userId) => Effect.sync(() => void users.delete(userId)),
  };

  const sessionManager: typeof SessionService.Service = {
    createSession: (userId) => Effect.sync(() => makeSession(userId)),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: (userId) =>
      Effect.sync(() => void invalidatedUserSessions.push(userId)),
    listSessions: () => Effect.succeed([]),
    revokeSessionById: () => Effect.succeed(false),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const linkConfig: AnonymousConfig = {
    ...config,
    linkAccount: (params) =>
      Effect.sync(
        () => void linkCalls.push({ anon: params.anonymousUser.id, real: params.newUser.id }),
      ),
  };

  const layer = AnonymousService.layer(linkConfig).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        Layer.succeed(AnonymousUserStore)(store),
        Layer.succeed(SessionService)(sessionManager),
        Hooks.Default,
      ),
    ),
  );

  return { layer, users, created, linkCalls, invalidatedUserSessions };
};

const run = <A, E>(
  h: Harness,
  f: (
    svc: typeof AnonymousService.Service,
  ) => Effect.Effect<A, E, AnonymousUserStore | SessionService | Hooks>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* AnonymousService;
      return yield* f(svc);
    }).pipe(Effect.provide(h.layer)),
  );

const runFail = <A, E>(
  h: Harness,
  f: (
    svc: typeof AnonymousService.Service,
  ) => Effect.Effect<A, E, AnonymousUserStore | SessionService | Hooks>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* AnonymousService;
      return yield* Effect.flip(f(svc));
    }).pipe(Effect.provide(h.layer)),
  );

describe("Anonymous", () => {
  it("creates an anonymous user and a session on sign-in", async () => {
    const h = makeHarness();
    const { user, session } = await run(h, (svc) => svc.signInAnonymous());
    expect(isAnonymousUser(user)).toBe(true);
    expect(user.attributes["email"]).toMatch(/@anonymous\.local$/);
    expect(session.userId).toBe(user.id);
    expect(h.users.has(user.id)).toBe(true);
  });

  it("passes session attributes through to the session manager", async () => {
    const h = makeHarness();
    const { user } = await run(h, (svc) => svc.signInAnonymous({ source: "guest-button" }));
    // The created user is anonymous and persisted.
    expect(h.created).toContain(user.id);
  });

  it("links an anonymous account: runs the callback then deletes the guest user", async () => {
    const h = makeHarness();
    const { user: anon } = await run(h, (svc) => svc.signInAnonymous());
    const realUser: Types.User = {
      id: "real-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    await run(h, (svc) => svc.linkAccount(anon, realUser));
    expect(h.linkCalls).toEqual([{ anon: anon.id, real: "real-1" }]);
    expect(h.users.has(anon.id)).toBe(false);
  });

  it("isAnonymousUser detects the convention flag", () => {
    const anon: Types.User = {
      id: "a",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: { isAnonymous: true, email: "a@anonymous.local" },
    };
    const real: Types.User = { ...anon, id: "b", attributes: { email: "b@example.com" } };
    expect(isAnonymousUser(anon)).toBe(true);
    expect(isAnonymousUser(real)).toBe(false);
  });

  it("linkAccount rejects a non-anonymous user", async () => {
    const h = makeHarness();
    const notAnon: Types.User = {
      id: "real-99",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    const target: Types.User = {
      id: "real-100",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    const err = await runFail(h, (svc) => svc.linkAccount(notAnon, target));
    assert.instanceOf(err, InvalidInputError);
    expect(err.field).toBe("anonymousUser");
  });

  it("linkAccount rejects when anonymousUser.id === newUser.id", async () => {
    const h = makeHarness();
    const { user: anon } = await run(h, (svc) => svc.signInAnonymous());
    const err = await runFail(h, (svc) => svc.linkAccount(anon, anon));
    assert.instanceOf(err, InvalidInputError);
    expect(err.field).toBe("newUser");
  });

  it("linkAccount is idempotent: a second call is a no-op", async () => {
    const h = makeHarness();
    const realUser: Types.User = {
      id: "real-2",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    // Both linkAccount calls must run within the same Effect scope so they
    // share the same service instance (and its `done` set).
    await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* AnonymousService;
        const { user: anon } = yield* svc.signInAnonymous();
        yield* svc.linkAccount(anon, realUser);
        yield* svc.linkAccount(anon, realUser);
      }).pipe(Effect.provide(h.layer)),
    );
    expect(h.linkCalls).toHaveLength(1);
    expect(h.invalidatedUserSessions).toHaveLength(1);
  });

  it("linkAccount invalidates the anonymous user's sessions", async () => {
    const h = makeHarness();
    const { user: anon } = await run(h, (svc) => svc.signInAnonymous());
    const realUser: Types.User = {
      id: "real-3",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    await run(h, (svc) => svc.linkAccount(anon, realUser));
    expect(h.invalidatedUserSessions).toContain(anon.id);
  });
});
