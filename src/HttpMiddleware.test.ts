import { describe, it, expect } from "vite-plus/test";
import { Effect, Exit, Layer, Option, Redacted } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import type * as Types from "./Types.js";
import { SessionService, type SessionService as SessionServiceShape } from "./SessionService.js";
import { Hooks } from "./Hooks.js";
import * as Errors from "./Errors.js";
import {
  AuthMiddleware,
  CurrentSession,
  CurrentUser,
  MaybeCurrentSession,
  OptionalAuthMiddleware,
  makeAuthMiddlewareLayer,
  makeOptionalAuthMiddlewareLayer,
} from "./HttpMiddleware.js";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const RAW_TOKEN = "validrawtoken1234567890abcdef123456";
const USER_ID = "user-42";
const now = new Date();

const testUser: Types.User = {
  id: USER_ID,
  email: "user@example.com",
  emailVerified: true,
  createdAt: now,
  updatedAt: now,
  attributes: {},
};

const testSession: Types.Session = {
  id: RAW_TOKEN,
  userId: USER_ID,
  expiresAt: new Date(now.getTime() + 60 * 60 * 1000),
  createdAt: now,
  lastActivityAt: now,
  attributes: {},
};

const mockSessionService: SessionServiceShape = {
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

// ---------------------------------------------------------------------------
// AuthMiddleware – conduit_session handler
// ---------------------------------------------------------------------------

describe("makeAuthMiddlewareLayer – conduit_session handler", () => {
  const authLayer = makeAuthMiddlewareLayer({ secure: false });

  const runCookiePath = (
    request: HttpServerRequest.HttpServerRequest,
    handler: Effect.Effect<typeof ok, never, CurrentSession | CurrentUser>,
  ) =>
    Effect.gen(function* () {
      const svc = yield* AuthMiddleware;
      return yield* (svc.conduit_session as any)(handler, undefined).pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
      );
    }).pipe(Effect.provide(authLayer), Effect.provide(baseLayer));

  it("valid session cookie → CurrentSession and CurrentUser are provided", async () => {
    const sessionCell = cell<Types.Session>();
    const userCell = cell<Types.User>();
    const handler = Effect.gen(function* () {
      sessionCell.value = yield* CurrentSession;
      userCell.value = yield* CurrentUser;
      return ok;
    });

    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest({ cookie: RAW_TOKEN }), handler),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(sessionCell.value?.id).toBe(RAW_TOKEN);
    expect(sessionCell.value?.userId).toBe(USER_ID);
    expect(userCell.value?.id).toBe(USER_ID);
    expect(userCell.value?.email).toBe("user@example.com");
  });

  it("no session cookie → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest(), Effect.succeed(ok) as any),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("invalid session cookie → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest({ cookie: "bad-token-xyz" }), Effect.succeed(ok) as any),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("Bearer Authorization header is also checked in conduit_session path", async () => {
    const userCell = cell<Types.User>();
    const handler = Effect.gen(function* () {
      userCell.value = yield* CurrentUser;
      return ok;
    });

    const exit = await Effect.runPromiseExit(
      runCookiePath(makeWebRequest({ authorization: `Bearer ${RAW_TOKEN}` }), handler),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(userCell.value?.id).toBe(USER_ID);
  });
});

// ---------------------------------------------------------------------------
// AuthMiddleware – bearer handler
// ---------------------------------------------------------------------------

describe("makeAuthMiddlewareLayer – bearer handler", () => {
  const authLayer = makeAuthMiddlewareLayer({ secure: false });

  const runBearerPath = (
    token: string,
    handler: Effect.Effect<typeof ok, never, CurrentSession | CurrentUser>,
  ) =>
    Effect.gen(function* () {
      const svc = yield* AuthMiddleware;
      return yield* (svc.bearer as any)(handler, {
        credential: Redacted.make(token),
        endpoint: undefined,
        group: undefined,
      });
    }).pipe(Effect.provide(authLayer), Effect.provide(baseLayer));

  it("valid Bearer token → CurrentSession and CurrentUser are provided", async () => {
    const sessionCell = cell<Types.Session>();
    const userCell = cell<Types.User>();
    const handler = Effect.gen(function* () {
      sessionCell.value = yield* CurrentSession;
      userCell.value = yield* CurrentUser;
      return ok;
    });

    const exit = await Effect.runPromiseExit(runBearerPath(RAW_TOKEN, handler));

    expect(Exit.isSuccess(exit)).toBe(true);
    expect(sessionCell.value?.userId).toBe(USER_ID);
    expect(userCell.value?.id).toBe(USER_ID);
  });

  it("invalid Bearer token → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(
      runBearerPath("bad-token-xyz", Effect.succeed(ok) as any),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("empty Bearer token → Unauthorized failure", async () => {
    const exit = await Effect.runPromiseExit(runBearerPath("", Effect.succeed(ok) as any));
    expect(Exit.isFailure(exit)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware
// ---------------------------------------------------------------------------

describe("makeOptionalAuthMiddlewareLayer", () => {
  const optionalLayer = makeOptionalAuthMiddlewareLayer({ secure: false });

  const runOptional = (request: HttpServerRequest.HttpServerRequest) => {
    const maybeCell = cell<Option.Option<Types.SessionWithUser>>();
    const handler = Effect.gen(function* () {
      maybeCell.value = yield* MaybeCurrentSession;
      return ok;
    });
    const effect = Effect.gen(function* () {
      const svc = yield* OptionalAuthMiddleware;
      yield* (svc as any)(handler, undefined).pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
      );
    }).pipe(Effect.provide(optionalLayer), Effect.provide(baseLayer));
    return { maybeCell, effect };
  };

  it("valid session cookie → Option.some with session and user", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest({ cookie: RAW_TOKEN }));
    await Effect.runPromise(effect);
    expect(Option.isSome(maybeCell.value!)).toBe(true);
    const resolved = (maybeCell.value as Option.Some<Types.SessionWithUser>).value;
    expect(resolved.session.id).toBe(RAW_TOKEN);
    expect(resolved.user.id).toBe(USER_ID);
  });

  it("valid Authorization Bearer header → Option.some", async () => {
    const { maybeCell, effect } = runOptional(
      makeWebRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
    );
    await Effect.runPromise(effect);
    expect(Option.isSome(maybeCell.value!)).toBe(true);
    const resolved = (maybeCell.value as Option.Some<Types.SessionWithUser>).value;
    expect(resolved.user.id).toBe(USER_ID);
  });

  it("no session token → Option.none (unauthenticated, no failure)", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest());
    await Effect.runPromise(effect);
    expect(Option.isNone(maybeCell.value!)).toBe(true);
  });

  it("invalid session token → Option.none (not a failure)", async () => {
    const { maybeCell, effect } = runOptional(makeWebRequest({ cookie: "bad-token-xyz" }));
    const exit = await Effect.runPromiseExit(effect);
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(Option.isNone(maybeCell.value!)).toBe(true);
  });
});
