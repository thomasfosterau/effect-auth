import { assert, describe, it, expect } from "vite-plus/test";
import { Effect, Exit, Option, Schema } from "effect";
import { HttpClient } from "effect/http";
import * as RemoteSession from "./RemoteSession.ts";
import * as SessionResolution from "../SessionResolution.ts";
import * as SessionContext from "../SessionContext.ts";
import { CurrentUser } from "../SessionContext.ts";

// ---------------------------------------------------------------------------
// A stand-in auth service
// ---------------------------------------------------------------------------

const NOW = 1_760_000_000_000;

const sessionBody = {
  session: {
    id: "session-1",
    userId: "user-42",
    expiresAt: NOW + 3_600_000,
    createdAt: NOW,
    lastActivityAt: NOW,
    attributes: { ip: "203.0.113.4" },
  },
  user: {
    id: "user-42",
    // Derived on the wire, not a `Types.User` field.
    email: "user@example.com",
    emailVerified: true,
    name: "Ada",
    createdAt: NOW,
    updatedAt: NOW,
    attributes: { role: "admin" },
  },
};

/** A JSON request or response body, as the wire carries it. */
const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

interface Recorded {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/** A fetcher that records what it was asked, and answers a canned response. */
const spy = (respond: (request: Request) => Response | Promise<Response>) => {
  const calls: Array<Recorded> = [];
  const fetcher = async (request: Request): Promise<Response> => {
    calls.push({
      url: request.url,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries()),
      body: request.body === null ? "" : await request.clone().text(),
    });
    return respond(request);
  };
  return { calls, fetcher };
};

const okSession = (setCookie: ReadonlyArray<string> = []) =>
  new Response(toJson(sessionBody), {
    status: 200,
    headers: [
      ["content-type", "application/json"],
      ...setCookie.map((value): [string, string] => ["set-cookie", value]),
    ],
  });

const inbound = (headers: Record<string, string> = {}, init?: RequestInit) =>
  new Request("https://app.example.com/api/things", {
    headers: { ...headers },
    ...init,
  });

const SESSION_COOKIE = "cookie";
const withSession = { [SESSION_COOKIE]: "__Host-conduit_session=raw-token" };

// ---------------------------------------------------------------------------
// Resolving the session over a non-fetch transport
// ---------------------------------------------------------------------------

describe("RemoteSession session reads", () => {
  it("a consuming Worker resolves the session over a binding, library code only", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(client.read(inbound(withSession)));

    assert(Option.isSome(result.session));
    const resolved = result.session.value;
    expect(resolved.session.id).toBe("session-1");
    expect(resolved.user.id).toBe("user-42");
    expect(resolved.user.attributes.role).toBe("admin");
    // Epoch millis on the wire come back as real Dates, so the result drops
    // straight into SessionContext without hand-reviving anything.
    expect(resolved.session.expiresAt).toBeInstanceOf(Date);
    expect(resolved.session.expiresAt.getTime()).toBe(NOW + 3_600_000);

    expect(calls).toHaveLength(1);
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/session");
    expect(call.method).toBe("GET");
  });

  it("the resolved session runs gated code through SessionContext", async () => {
    const { fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    const userId = await Effect.runPromise(
      Effect.gen(function* () {
        const { session } = yield* client.read(inbound(withSession));
        if (Option.isNone(session)) return "anonymous";
        return yield* Effect.map(CurrentUser, (user) => user.id).pipe(
          Effect.provide(SessionContext.authenticatedLayer(session.value)),
        );
      }),
    );

    expect(userId).toBe("user-42");
  });

  it("a bodyless session read forwards no content-type or content-length", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    // The inbound request is the app's own JSON:API dispatch. Forwarding its
    // content headers onto a bodyless GET is what makes a router believe the
    // request has a body and reject it with 415.
    await Effect.runPromise(
      client.read(
        inbound({
          ...withSession,
          "content-type": "application/vnd.api+json",
          "content-length": "42",
        }),
      ),
    );

    const call = calls[0];
    assert(call !== undefined);
    expect(call.headers["content-type"]).toBeUndefined();
    expect(call.headers["content-length"]).toBeUndefined();
    expect(call.headers["cookie"]).toBe("__Host-conduit_session=raw-token");
  });

  it("forwards the caller's identity and origin, so CSRF and rate limits see the browser", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    await Effect.runPromise(
      client.read(
        inbound({
          ...withSession,
          origin: "https://app.example.com",
          "cf-connecting-ip": "203.0.113.4",
          "accept-language": "en-AU",
        }),
      ),
    );

    const call = calls[0];
    assert(call !== undefined);
    expect(call.headers["origin"]).toBe("https://app.example.com");
    expect(call.headers["cf-connecting-ip"]).toBe("203.0.113.4");
    expect(call.headers["accept-language"]).toBe("en-AU");
  });

  it("carries the Set-Cookie lines that keep the cookie cache refreshing", async () => {
    const { fetcher } = spy(() =>
      okSession(["__Host-conduit_session_data=refreshed; Path=/; HttpOnly"]),
    );
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(client.read(inbound(withSession)));
    expect(result.setCookie).toStrictEqual([
      "__Host-conduit_session_data=refreshed; Path=/; HttpOnly",
    ]);
  });

  it("401 is 'nobody was signed in', not a fault — and still carries its cookies", async () => {
    const { fetcher } = spy(
      () =>
        new Response(toJson({ message: "Not authenticated" }), {
          status: 401,
          headers: [["set-cookie", "__Host-conduit_session=; Max-Age=0"]],
        }),
    );
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(client.read(inbound(withSession)));
    expect(Option.isNone(result.session)).toBe(true);
    expect(result.setCookie).toStrictEqual(["__Host-conduit_session=; Max-Age=0"]);
  });

  it("an unexpected status is a RemoteSessionError", async () => {
    const { fetcher } = spy(() => new Response("nope", { status: 503 }));
    const client = RemoteSession.make({ fetcher });

    const error = await Effect.runPromise(Effect.flip(client.read(inbound(withSession))));
    expect(error._tag).toBe("RemoteSessionError");
    expect(error.status).toBe(503);
  });

  it("an instant outside the Date range is a RemoteSessionError, not an Invalid Date", async () => {
    const outOfRange = {
      ...sessionBody,
      session: { ...sessionBody.session, expiresAt: 9e15 },
    };
    const { fetcher } = spy(
      () =>
        new Response(toJson(outOfRange), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const client = RemoteSession.make({ fetcher });

    const error = await Effect.runPromise(Effect.flip(client.read(inbound(withSession))));
    expect(error._tag).toBe("RemoteSessionError");
    expect(error.message).toMatch(/did not decode/);
  });

  it("honours a custom baseUrl and prefix", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({
      fetcher,
      baseUrl: "https://auth.svc.local",
      prefix: "/auth",
    });
    await Effect.runPromise(client.read(inbound(withSession)));
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.svc.local/auth/session");
  });
});

// ---------------------------------------------------------------------------
// The edge, end to end
// ---------------------------------------------------------------------------

describe("RemoteSession.resolveAtEdge", () => {
  it("a cookieless request never reaches the binding", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(
      RemoteSession.resolveAtEdge({ client, request: inbound() }),
    );

    expect(result.outcome).toBe("skipped");
    expect(calls).toHaveLength(0);
  });

  it("a cookie-bearing request resolves", async () => {
    const { fetcher } = spy(() => okSession(["__Host-conduit_session_data=x"]));
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(
      RemoteSession.resolveAtEdge({ client, request: inbound(withSession) }),
    );

    expect(result.outcome).toBe("resolved");
    expect(Option.isSome(result.session)).toBe(true);
    expect(result.credentialClass).toBe("interactive");
    // The cookies survive the outcome wrapper — that is why the generic
    // `resolveWith` exists rather than calling the transport twice.
    expect(result.setCookie).toStrictEqual(["__Host-conduit_session_data=x"]);
  });

  it("fails closed by default", async () => {
    const { fetcher } = spy(() => new Response("", { status: 500 }));
    const client = RemoteSession.make({ fetcher });

    const exit = await Effect.runPromiseExit(
      RemoteSession.resolveAtEdge({ client, request: inbound(withSession) }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("resolveAtEdgeFailOpen degrades an unreachable binding to anonymous", async () => {
    const fetcher = () => Promise.reject(new TypeError("Network connection lost."));
    const client = RemoteSession.make({ fetcher });
    let degraded = false;

    const result = await Effect.runPromise(
      RemoteSession.resolveAtEdgeFailOpen({
        client,
        request: inbound(withSession),
        onDegraded: () => Effect.sync(() => void (degraded = true)),
      }),
    );

    expect(result.outcome).toBe("degraded");
    expect(Option.isNone(result.session)).toBe(true);
    expect(degraded).toBe(true);
  });

  it("a machine caller is not cookieless, so its key still resolves", async () => {
    const { calls, fetcher } = spy(() => okSession());
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(
      RemoteSession.resolveAtEdge({ client, request: inbound({ "x-api-key": "key_live_1" }) }),
    );

    expect(result.outcome).toBe("resolved");
    expect(calls).toHaveLength(1);
    const call = calls[0];
    assert(call !== undefined);
    expect(call.headers["x-api-key"]).toBe("key_live_1");
    // And it is carried as a machine credential, so the policy kernel sees the
    // same class the HTTP middleware would have provided.
    expect(result.credentialClass).toBe("machine");
  });
});

// ---------------------------------------------------------------------------
// The Set-Cookie relay
// ---------------------------------------------------------------------------

const signInResponse = () =>
  new Response(toJson({ user: { id: "user-42" } }), {
    status: 200,
    headers: [
      ["content-type", "application/json"],
      ["set-cookie", "__Host-conduit_session=new-token; Path=/; HttpOnly; Secure"],
      ["set-cookie", "__Host-conduit_session_data=cache; Path=/; HttpOnly"],
    ],
  });

/** The part of a relayed sign-in body the relay test reads. */
const SignInBody = Schema.fromJsonString(Schema.Struct({ email: Schema.String }));

describe("RemoteSession relay", () => {
  it("sign-in through an app-owned front door establishes a browser session", async () => {
    const { calls, fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/session/sign-in", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example.com",
        cookie: "__Host-conduit_session=stale",
      },
      body: toJson({ email: "user@example.com", password: "hunter2hunter2" }),
    });

    const response = await Effect.runPromise(client.relay(request, "/sign-in"));

    // No app-authored header handling: the body, content-type and origin all
    // arrived, and the raw Set-Cookie came back untouched.
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/sign-in");
    expect(call.method).toBe("POST");
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers["origin"]).toBe("https://app.example.com");
    expect(Schema.decodeUnknownSync(SignInBody)(call.body).email).toBe("user@example.com");

    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toStrictEqual([
      "__Host-conduit_session=new-token; Path=/; HttpOnly; Secure",
      "__Host-conduit_session_data=cache; Path=/; HttpOnly",
    ]);
    expect(await response.json()).toStrictEqual({ user: { id: "user-42" } });
  });

  it("a key-bearing request provably receives no Set-Cookie", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/session/sign-in", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "key_live_1" },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sign-in"));
    expect(response.headers.getSetCookie()).toStrictEqual([]);
    // The rest of the response is untouched.
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ user: { id: "user-42" } });
  });

  it("the mixed cookie+key case receives no Set-Cookie either", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/session/sign-in", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "key_live_1",
        cookie: "__Host-conduit_session=raw-token",
      },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sign-in"));
    expect(response.headers.getSetCookie()).toStrictEqual([]);
  });

  it("a bearer-only native client receives no Set-Cookie", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/session/sign-in", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer tok" },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sign-in"));
    // Its credential is the token it already holds; `set-auth-token` is the
    // channel for that, not a cookie jar.
    expect(response.headers.getSetCookie()).toStrictEqual([]);
  });

  it("relayResponse applies the same rule to a hand-rolled relay", () => {
    const keyed = SessionResolution.detectCredential(
      SessionResolution.fromRequest(inbound({ "x-api-key": "k" })),
    );
    const browser = SessionResolution.detectCredential(
      SessionResolution.fromRequest(inbound(withSession)),
    );

    expect(
      RemoteSession.relayResponse(signInResponse(), keyed).headers.getSetCookie(),
    ).toStrictEqual([]);
    expect(
      RemoteSession.relayResponse(signInResponse(), browser).headers.getSetCookie(),
    ).toHaveLength(2);
  });
});

describe("RemoteSession.withSetCookie", () => {
  it("replays relayed cookies onto an outgoing response", () => {
    const response = RemoteSession.withSetCookie(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
      ["__Host-conduit_session_data=refreshed; Path=/"],
    );
    expect(response.headers.getSetCookie()).toStrictEqual([
      "__Host-conduit_session_data=refreshed; Path=/",
    ]);
    expect(response.headers.get("content-type")).toBe("application/json");
  });

  it("is a no-op when there is nothing to replay", () => {
    const original = new Response(null, { status: 204 });
    expect(RemoteSession.withSetCookie(original, [])).toBe(original);
  });
});

// ---------------------------------------------------------------------------
// The transport, for the typed client
// ---------------------------------------------------------------------------

describe("RemoteSession.layerFetcher", () => {
  it("points the typed client at an arbitrary fetch-alike", async () => {
    const { calls, fetcher } = spy(() => okSession());

    const response = await Effect.runPromise(
      Effect.gen(function* () {
        const http = yield* HttpClient.HttpClient;
        return yield* http.get("https://auth.internal/api/auth/session");
      }).pipe(Effect.provide(RemoteSession.layerFetcher(fetcher))),
    );

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(1);
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/session");
  });
});
