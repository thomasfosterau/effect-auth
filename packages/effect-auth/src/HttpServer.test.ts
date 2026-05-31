import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import { makeAuthClient } from "./HttpClient.js";
import { SessionManagerTag } from "./Session.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { EmailPasswordStoreTag } from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import { Hooks } from "./Hooks.js";
import {
  AuthError,
  InvalidCredentialsError,
  SessionNotFoundError,
  UserNotFoundError,
} from "./Errors.js";
import type * as Types from "./Types.js";

const SESSION_TTL = 1000 * 60 * 60;

/**
 * An in-memory implementation of every service the auth handlers need. The
 * orchestration-service interfaces declare store dependencies in their `R`
 * channel, so all six tags must be present (a few are never exercised by these
 * stubs and are provided as no-ops purely to satisfy the types).
 */
const makeTestServices = (): Layer.Layer<AuthServices> => {
  const usersById = new Map<string, Types.User>();
  const credsByEmail = new Map<string, { id: string; password: string }>();
  const sessions = new Map<string, Types.Session>();
  let seq = 0;

  const newSession = (userId: string): Types.Session => {
    const now = new Date();
    const session: Types.Session = {
      id: `sess-${++seq}`,
      userId,
      expiresAt: new Date(now.getTime() + SESSION_TTL),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    };
    sessions.set(session.id, session);
    return session;
  };

  const sessionManager = {
    createSession: (userId: string) => Effect.sync(() => newSession(userId)),
    validateSession: (sessionId: string) =>
      Effect.gen(function* () {
        const session = sessions.get(sessionId);
        if (session === undefined || session.expiresAt.getTime() < Date.now()) {
          return yield* new SessionNotFoundError({ message: "Session not found", sessionId });
        }
        const user = usersById.get(session.userId);
        if (user === undefined) {
          return yield* new UserNotFoundError({
            message: "User not found",
            userId: session.userId,
          });
        }
        return { session, user };
      }),
    invalidateSession: (sessionId: string) => Effect.sync(() => void sessions.delete(sessionId)),
    invalidateUserSessions: (userId: string) =>
      Effect.sync(() => {
        for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
      }),
  };

  const lifecycle = {
    signUp: (input: {
      readonly email: string;
      readonly password: string;
      readonly name?: string;
      readonly attributes?: Record<string, unknown>;
    }) =>
      Effect.gen(function* () {
        if (credsByEmail.has(input.email)) {
          return yield* new AuthError({ message: "User already exists" });
        }
        const id = `user-${++seq}`;
        const user: Types.User = {
          id,
          attributes: { email: input.email, ...input.attributes },
        };
        usersById.set(id, user);
        credsByEmail.set(input.email, { id, password: input.password });
        return { user, session: newSession(id), needsEmailVerification: false };
      }),
    signIn: (input: { readonly email: string; readonly password: string }) =>
      Effect.gen(function* () {
        const rec = credsByEmail.get(input.email);
        if (rec === undefined || rec.password !== input.password) {
          return yield* new InvalidCredentialsError({ message: "Invalid email or password" });
        }
        return {
          user: usersById.get(rec.id)!,
          session: newSession(rec.id),
          needsEmailVerification: false,
        };
      }),
    verifyEmail: () => Effect.die("verifyEmail is not used in these tests"),
  };

  return Layer.mergeAll(
    Layer.succeed(SessionManagerTag)(sessionManager),
    Layer.succeed(AuthLifecycleServiceTag)(lifecycle),
    Layer.succeed(EmailPasswordStoreTag)(undefined as never),
    Layer.succeed(PasswordHasherTag)(undefined as never),
    Layer.succeed(EmailVerificationServiceTag)(undefined as never),
    Layer.succeed(EmailVerificationStoreTag)(undefined as never),
    Hooks.Default,
  );
};

const handlerFor = () =>
  makeAuthWebHandler({ services: makeTestServices(), cookie: { secure: false } }).handler;

const jsonRequest = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

const sessionIdFromSetCookie = (setCookie: string | null): string => {
  const match = /conduit_session=([^;]+)/.exec(setCookie ?? "");
  if (match === null) throw new Error(`no session cookie in: ${setCookie}`);
  return match[1];
};

describe("HTTP auth protocol", () => {
  it("signs up, sets a session cookie, and returns the user", async () => {
    const handler = handlerFor();
    const res = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));

    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
    const body = (await res.json()) as {
      user: { attributes: { email: string } };
      needsEmailVerification: boolean;
    };
    expect(body.user.attributes.email).toBe("a@b.com");
    expect(body.needsEmailVerification).toBe(false);
  });

  it("resolves the current session from the cookie", async () => {
    const handler = handlerFor();
    const signUp = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));
    const sid = sessionIdFromSetCookie(signUp.headers.get("set-cookie"));

    const res = await handler(
      new Request("http://test/session", { headers: { cookie: `conduit_session=${sid}` } }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { attributes: { email: string } } };
    expect(body.user.attributes.email).toBe("a@b.com");
  });

  it("resolves the current session from an Authorization header", async () => {
    const handler = handlerFor();
    const signUp = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));
    const sid = sessionIdFromSetCookie(signUp.headers.get("set-cookie"));

    const res = await handler(
      new Request("http://test/session", { headers: { authorization: `Bearer ${sid}` } }),
    );
    expect(res.status).toBe(200);
  });

  it("returns 401 for /session without a session", async () => {
    const handler = handlerFor();
    const res = await handler(new Request("http://test/session"));
    expect(res.status).toBe(401);
  });

  it("returns 401 for invalid sign-in credentials", async () => {
    const handler = handlerFor();
    await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));
    const res = await handler(jsonRequest("/sign-in", { email: "a@b.com", password: "wrong" }));
    expect(res.status).toBe(401);
    const body = (await res.json()) as { _tag: string };
    expect(body._tag).toBe("Unauthorized");
  });

  it("signs in an existing user and returns a fresh cookie", async () => {
    const handler = handlerFor();
    await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));
    const res = await handler(jsonRequest("/sign-in", { email: "a@b.com", password: "pw" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("signs out, clears the cookie, and invalidates the session", async () => {
    const handler = handlerFor();
    const signUp = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: "pw" }));
    const sid = sessionIdFromSetCookie(signUp.headers.get("set-cookie"));

    const out = await handler(
      jsonRequest("/sign-out", undefined, { cookie: `conduit_session=${sid}` }),
    );
    expect(out.status).toBe(204);
    expect(out.headers.get("set-cookie")).toContain("conduit_session=");

    const after = await handler(
      new Request("http://test/session", { headers: { cookie: `conduit_session=${sid}` } }),
    );
    expect(after.status).toBe(401);
  });

  it("routes under a mount prefix", async () => {
    const handler = makeAuthWebHandler({
      services: makeTestServices(),
      cookie: { secure: false },
      prefix: "/api/auth",
    }).handler;
    const res = await handler(
      jsonRequest("/api/auth/sign-up", { email: "a@b.com", password: "pw" }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("works through the derived typed client (in-memory)", async () => {
    const { handler } = makeAuthWebHandler({
      services: makeTestServices(),
      cookie: { secure: false },
    });
    const fetchImpl = ((input: Request | string | URL, init?: RequestInit) =>
      handler(new Request(input as never, init))) as typeof globalThis.fetch;
    const ClientLayer = FetchHttpClient.layer.pipe(
      Layer.provide(Layer.succeed(FetchHttpClient.Fetch)(fetchImpl)),
    );

    const program = Effect.gen(function* () {
      const client = yield* makeAuthClient("http://test");
      return yield* client.auth.signUp({ payload: { email: "c@d.com", password: "pw" } });
    }).pipe(Effect.provide(ClientLayer));

    const result = await Effect.runPromise(program);
    expect(result.user.attributes.email).toBe("c@d.com");
    expect(result.needsEmailVerification).toBe(false);
  });
});
