import { assert, describe, it, expect } from "vite-plus/test";
import { Array as Arr, DateTime, Effect, Exit, Layer, Option, Redacted } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/http-api";
import type * as Types from "../Types.ts";
import { SessionService } from "../SessionService.ts";
import { Hooks } from "../Hooks.ts";
import * as Errors from "../Errors.ts";
import {
  AuthMiddleware,
  CurrentSession,
  CurrentUser,
  MaybeCurrentSession,
  OptionalAuthMiddleware,
} from "./HttpMiddleware.ts";
import * as HttpMiddleware from "./HttpMiddleware.ts";
import * as SessionContext from "../SessionContext.ts";
import * as Entity from "../Entity.ts";
import * as Policy from "../Policy.ts";
import { Authorizer, CurrentPrincipal } from "../Authorizer.ts";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const RAW_TOKEN = "validrawtoken1234567890abcdef123456";
const USER_ID = "user-42";
const now = DateTime.toDateUtc(DateTime.nowUnsafe());

// `email` is not a first-class `User` field (login handles are `Identifier`
// records); it rides along in `attributes` here purely so the assertions can
// check that a non-trivial user payload survives the middleware.
const testUser: Types.User = {
  id: USER_ID,
  createdAt: now,
  updatedAt: now,
  attributes: { email: "user@example.com", emailVerified: true },
};

const testSession: Types.Session = {
  id: RAW_TOKEN,
  userId: USER_ID,
  expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 60 * 60 * 1000)),
  createdAt: now,
  lastActivityAt: now,
  attributes: {},
};

const mockSessionService: typeof SessionService.Service = {
  createSession: () => Effect.die("unused"),
  validateSession: (id: string) =>
    id === RAW_TOKEN
      ? Effect.succeed({ session: testSession, user: testUser })
      : Effect.fail(
          new Errors.SessionNotFoundError({ message: "session not found", sessionId: id }),
        ),
  invalidateSession: () => Effect.die("unused"),
  invalidateUserSessions: () => Effect.die("unused"),
  listSessions: () => Effect.die("unused"),
  revokeOtherSessions: () => Effect.die("unused"),
  setSessionAttributes: () => Effect.die("unused"),
};

const baseLayer = Layer.mergeAll(Layer.succeed(SessionService, mockSessionService), Hooks.Default);

const makeWebRequest = (opts: { cookie?: string; authorization?: string } = {}) => {
  const headers: Record<string, string> = {};
  if (opts.cookie !== undefined) headers["cookie"] = `conduit_session=${opts.cookie}`;
  if (opts.authorization !== undefined) headers["authorization"] = opts.authorization;
  return HttpServerRequest.fromWeb(new Request("http://localhost/", { headers }));
};

const ok = HttpServerResponse.empty({ status: 200 });

type Cell<T> = { value: T | undefined };
const cell = <T>(): Cell<T> => ({ value: undefined });

/**
 * `HttpApiMiddleware.Service` types its scheme handlers against the whole
 * `HttpApi` surface, which these unit tests deliberately do not build: the
 * handlers are called with a stand-in endpoint and group, which they ignore.
 * Their result also requires everything `HttpRouter.Provided` names, of which
 * the middleware reads only `HttpServerRequest`, so the result is narrowed to
 * that. The narrowed type keeps the effect's requirements honest (the
 * middleware leaves `SessionService`, `Hooks` and — on the cookie path —
 * `HttpServerRequest` to be provided below).
 */
type MiddlewareResult<A, R> = Effect.Effect<A, unknown, R>;
type PerRequestServices = SessionService | Hooks;

/**
 * The endpoint and group a middleware is told it wraps. The middleware never
 * reads them, so one stand-in pair serves every call; `HttpApi.reflect` hands
 * them over typed as the middleware's options expect.
 */
const standIn = ((): {
  readonly endpoint: HttpApiEndpoint.Top;
  readonly group: HttpApiGroup.Top;
} => {
  const pairs: Array<{ readonly endpoint: HttpApiEndpoint.Top; readonly group: HttpApiGroup.Top }> =
    [];
  HttpApi.reflect(
    HttpApi.make("standIn").add(
      HttpApiGroup.make("standIn").add(HttpApiEndpoint.get("standIn", "/")),
    ),
    {
      onGroup: () => undefined,
      onEndpoint: ({ endpoint, group }) => pairs.push({ endpoint, group }),
    },
  );
  return Option.match(Arr.head(pairs), {
    onNone: () => assert.fail("HttpApi.reflect reported no endpoint"),
    onSome: (pair) => pair,
  });
})();

/** What a test handler may read: whatever `AuthMiddleware` provides. */
type AuthHandler = Effect.Effect<
  typeof ok,
  never,
  CurrentSession | CurrentUser | CurrentPrincipal | MaybeCurrentSession
>;

// ---------------------------------------------------------------------------
// AuthMiddleware – conduit_session handler
// ---------------------------------------------------------------------------

describe("HttpMiddleware.layer – conduit_session handler", () => {
  const authLayer = HttpMiddleware.layer({ secure: false });

  const runCookiePath = (request: HttpServerRequest.HttpServerRequest, handler: AuthHandler) =>
    Effect.gen(function* () {
      const svc = yield* AuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores,
      // and reads only `HttpServerRequest` of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc.conduit_session(handler, {
        ...standIn,
        credential: Redacted.make(""),
      }) as MiddlewareResult<typeof ok, PerRequestServices | HttpServerRequest.HttpServerRequest>;
      return yield* applied.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
      );
    }).pipe(Effect.provide(Layer.mergeAll(authLayer, baseLayer)));

  it("valid session cookie → CurrentSession and CurrentUser are provided", async () => {
    const sessionCell = cell<Types.Session>();
    const userCell = cell<Types.User>();

    const exit = await Effect.runPromiseExit(
      runCookiePath(
        makeWebRequest({ cookie: RAW_TOKEN }),
        Effect.gen(function* () {
          sessionCell.value = yield* CurrentSession;
          userCell.value = yield* CurrentUser;
          return ok;
        }),
      ),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(sessionCell.value?.id).toBe(RAW_TOKEN);
    expect(sessionCell.value?.userId).toBe(USER_ID);
    expect(userCell.value?.id).toBe(USER_ID);
    expect(userCell.value?.attributes.email).toBe("user@example.com");
  });

  it("no session cookie → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(runCookiePath(makeWebRequest(), Effect.succeed(ok)));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("invalid session cookie → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest({ cookie: "bad-token-xyz" }), Effect.succeed(ok)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('valid session cookie → CurrentPrincipal is provided as User::"<id>"', async () => {
    const principalCell = cell<Entity.EntityRef>();

    const exit = await Effect.runPromiseExit(
      runCookiePath(
        makeWebRequest({ cookie: RAW_TOKEN }),
        Effect.gen(function* () {
          principalCell.value = yield* CurrentPrincipal;
          return ok;
        }),
      ),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(principalCell.value).toEqual(Entity.ref("User", USER_ID));
  });

  it("the provided principal drives an end-to-end Authorizer.check", async () => {
    const allowedCell = cell<boolean>();
    const deniedCell = cell<boolean>();
    const authorizerLayer = Authorizer.layer({
      policies: [
        Policy.permit({
          id: "self-read",
          action: Policy.eq(Entity.ref("Action", "profile:read")),
          resource: Policy.eq(Entity.ref("User", USER_ID)),
        }),
      ],
    });

    const handler = Effect.gen(function* () {
      const authorizer = yield* Authorizer;
      allowedCell.value = yield* authorizer.check({
        action: "profile:read",
        resource: Entity.ref("User", USER_ID),
      });
      deniedCell.value = yield* authorizer.check({
        action: "profile:read",
        resource: Entity.ref("User", "someone-else"),
      });
      return ok;
      // The policy layer cannot fail to build here; were it to, the test fails all the same.
    }).pipe(Effect.provide(authorizerLayer), Effect.orDie);

    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest({ cookie: RAW_TOKEN }), handler),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(allowedCell.value).toBe(true);
    expect(deniedCell.value).toBe(false);
  });

  it("Bearer Authorization header is also checked in conduit_session path", async () => {
    const userCell = cell<Types.User>();

    const exit = await Effect.runPromiseExit(
      runCookiePath(
        makeWebRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
        Effect.gen(function* () {
          userCell.value = yield* CurrentUser;
          return ok;
        }),
      ),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(userCell.value?.id).toBe(USER_ID);
  });
});

// ---------------------------------------------------------------------------
// AuthMiddleware – bearer handler
// ---------------------------------------------------------------------------

describe("HttpMiddleware.layer – bearer handler", () => {
  const authLayer = HttpMiddleware.layer({ secure: false });

  const runBearerPath = (token: string, handler: AuthHandler) =>
    Effect.gen(function* () {
      const svc = yield* AuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores;
      // the bearer path reads nothing of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc.bearer(handler, {
        ...standIn,
        credential: Redacted.make(token),
      }) as MiddlewareResult<typeof ok, PerRequestServices>;
      return yield* applied;
    }).pipe(Effect.provide(Layer.mergeAll(authLayer, baseLayer)));

  it("valid Bearer token → CurrentSession and CurrentUser are provided", async () => {
    const sessionCell = cell<Types.Session>();
    const userCell = cell<Types.User>();

    const exit = await Effect.runPromiseExit(
      runBearerPath(
        RAW_TOKEN,
        Effect.gen(function* () {
          sessionCell.value = yield* CurrentSession;
          userCell.value = yield* CurrentUser;
          return ok;
        }),
      ),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(sessionCell.value?.userId).toBe(USER_ID);
    expect(userCell.value?.id).toBe(USER_ID);
  });

  it("valid Bearer token → CurrentPrincipal is provided", async () => {
    const principalCell = cell<Entity.EntityRef>();

    const exit = await Effect.runPromiseExit(
      runBearerPath(
        RAW_TOKEN,
        Effect.gen(function* () {
          principalCell.value = yield* CurrentPrincipal;
          return ok;
        }),
      ),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(principalCell.value).toEqual(Entity.ref("User", USER_ID));
  });

  it("invalid Bearer token → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(runBearerPath("bad-token-xyz", Effect.succeed(ok)));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("empty Bearer token → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(runBearerPath("", Effect.succeed(ok)));
    expect(Exit.isFailure(exit)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware
// ---------------------------------------------------------------------------

describe("HttpMiddleware.optionalLayer", () => {
  const optionalLayer = HttpMiddleware.optionalLayer({ secure: false });

  const runOptional = (request: HttpServerRequest.HttpServerRequest) => {
    const maybeCell = cell<Option.Option<Types.SessionWithUser>>();
    const effect = Effect.gen(function* () {
      const svc = yield* OptionalAuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores,
      // and reads only `HttpServerRequest` of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc(
        Effect.gen(function* () {
          maybeCell.value = yield* MaybeCurrentSession;
          return ok;
        }),
        standIn,
      ) as MiddlewareResult<typeof ok, PerRequestServices | HttpServerRequest.HttpServerRequest>;
      yield* applied.pipe(Effect.provideService(HttpServerRequest.HttpServerRequest, request));
    }).pipe(Effect.provide(Layer.mergeAll(optionalLayer, baseLayer)));
    return { maybeCell, effect };
  };

  it("valid session cookie → Option.some with session and user", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest({ cookie: RAW_TOKEN }));
    await Effect.runPromise(effect);
    const maybe = maybeCell.value;
    assert(maybe !== undefined && Option.isSome(maybe), "the session resolved");
    const resolved = maybe.value;
    expect(resolved.session.id).toBe(RAW_TOKEN);
    expect(resolved.user.id).toBe(USER_ID);
  });

  it("valid Authorization Bearer header → Option.some", async () => {
    const { maybeCell, effect } = runOptional(
      makeWebRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
    );
    await Effect.runPromise(effect);
    const maybe = maybeCell.value;
    assert(maybe !== undefined && Option.isSome(maybe), "the session resolved");
    const resolved = maybe.value;
    expect(resolved.user.id).toBe(USER_ID);
  });

  it("no session token → Option.none (unauthenticated, no failure)", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest());
    await Effect.runPromise(effect);
    assert(maybeCell.value !== undefined, "the handler ran");
    expect(Option.isNone(maybeCell.value)).toBe(true);
  });

  it("invalid session token → Option.none (not a failure)", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest({ cookie: "bad-token-xyz" }));
    const exit = await Effect.runPromiseExit(effect);
    expect(Exit.isSuccess(exit)).toBe(true);
    assert(maybeCell.value !== undefined, "the handler ran");
    expect(Option.isNone(maybeCell.value)).toBe(true);
  });

  // `CurrentPrincipal` is conditional here — present only when a session
  // resolved — so handlers read it with `Effect.serviceOption`.
  const runOptionalPrincipal = (request: HttpServerRequest.HttpServerRequest) => {
    const principalCell = cell<Option.Option<Entity.EntityRef>>();
    const effect = Effect.gen(function* () {
      const svc = yield* OptionalAuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores,
      // and reads only `HttpServerRequest` of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc(
        Effect.gen(function* () {
          principalCell.value = yield* Effect.serviceOption(CurrentPrincipal);
          return ok;
        }),
        standIn,
      ) as MiddlewareResult<typeof ok, PerRequestServices | HttpServerRequest.HttpServerRequest>;
      yield* applied.pipe(Effect.provideService(HttpServerRequest.HttpServerRequest, request));
    }).pipe(Effect.provide(Layer.mergeAll(optionalLayer, baseLayer)));
    return { principalCell, effect };
  };

  it("valid session → CurrentPrincipal is in context", async () => {
    const { principalCell, effect } = runOptionalPrincipal(makeWebRequest({ cookie: RAW_TOKEN }));
    await Effect.runPromise(effect);
    const principal = principalCell.value;
    assert(principal !== undefined && Option.isSome(principal), "a principal is in context");
    expect(principal.value).toEqual(Entity.ref("User", USER_ID));
  });

  it("no session → CurrentPrincipal is absent (anonymous, not a failure)", async () => {
    const { principalCell, effect } = runOptionalPrincipal(makeWebRequest());
    const exit = await Effect.runPromiseExit(effect);
    expect(Exit.isSuccess(exit)).toBe(true);
    assert(principalCell.value !== undefined, "the handler ran");
    expect(Option.isNone(principalCell.value)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// One effect, three contexts (#185)
// ---------------------------------------------------------------------------

/**
 * A read-path effect written against `MaybeCurrentSession` — the shape an
 * app's zero-IO guard has. The point of the test is that this *exact value*
 * runs under required auth, under optional auth, and under
 * `SessionContext.authenticatedLayer` with no HTTP request in sight.
 */
const viewerRole = Effect.map(
  SessionContext.currentUserOption,
  Option.match({
    onNone: () => "anonymous",
    onSome: (user) => String(user.attributes.email),
  }),
);

describe("MaybeCurrentSession is provided by both middlewares", () => {
  const authLayer = HttpMiddleware.layer({ secure: false });
  const optionalLayer = HttpMiddleware.optionalLayer({ secure: false });

  it("AuthMiddleware provides it as Option.some, so read-path code runs under required auth", async () => {
    const roleCell = cell<string>();

    const effect = Effect.gen(function* () {
      const svc = yield* AuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores,
      // and reads only `HttpServerRequest` of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc.conduit_session(
        Effect.gen(function* () {
          roleCell.value = yield* viewerRole;
          return ok;
        }),
        {
          ...standIn,
          credential: Redacted.make(""),
        },
      ) as MiddlewareResult<typeof ok, PerRequestServices | HttpServerRequest.HttpServerRequest>;
      yield* applied.pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          makeWebRequest({ cookie: RAW_TOKEN }),
        ),
      );
    }).pipe(Effect.provide(Layer.mergeAll(authLayer, baseLayer)));

    await Effect.runPromise(effect);
    expect(roleCell.value).toBe("user@example.com");
  });

  it("OptionalAuthMiddleware runs the same effect and answers anonymous", async () => {
    const roleCell = cell<string>();

    const effect = Effect.gen(function* () {
      const svc = yield* OptionalAuthMiddleware;
      // SAFETY: the handler is called with the stand-in endpoint, which it ignores,
      // and reads only `HttpServerRequest` of `HttpRouter.Provided` (see `MiddlewareResult`).
      const applied = svc(
        Effect.gen(function* () {
          roleCell.value = yield* viewerRole;
          return ok;
        }),
        standIn,
      ) as MiddlewareResult<typeof ok, PerRequestServices | HttpServerRequest.HttpServerRequest>;
      yield* applied.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, makeWebRequest()),
      );
    }).pipe(Effect.provide(Layer.mergeAll(optionalLayer, baseLayer)));

    await Effect.runPromise(effect);
    expect(roleCell.value).toBe("anonymous");
  });

  it("SessionContext.authenticatedLayer runs the same effect with no request at all", async () => {
    const role = await Effect.runPromise(
      viewerRole.pipe(
        Effect.provide(SessionContext.authenticatedLayer({ session: testSession, user: testUser })),
      ),
    );
    expect(role).toBe("user@example.com");
  });
});
