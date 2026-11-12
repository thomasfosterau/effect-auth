import { assert, describe, it, expect } from "vite-plus/test";
import { Effect, Exit } from "effect";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { HttpClient } from "effect/http";
import * as RemoteSession from "./RemoteSession.ts";
import * as SessionResolution from "../SessionResolution.ts";
import * as SessionContext from "../SessionContext.ts";
import { CurrentUser } from "../SessionContext.ts";
import { hashToken } from "../TokenHash.ts";
import { makeServerFixture } from "../client/testing/fixture.ts";

// ---------------------------------------------------------------------------
// A stand-in auth service
// ---------------------------------------------------------------------------

const NOW = 1_760_000_000_000;

/** What `GET /sessions/current?include=user` answers: the session, its user included. */
const sessionDocument = (expiresAt: number = NOW + 3_600_000) => ({
  data: {
    type: "sessions",
    id: "session-1",
    attributes: {
      expiresAt,
      createdAt: NOW,
      lastActivityAt: NOW,
      attributes: { ip: "203.0.113.4" },
    },
    relationships: { user: { data: { type: "users", id: "user-42" } } },
  },
  included: [
    {
      type: "users",
      id: "user-42",
      attributes: {
        // Derived on the wire, not a `Types.User` field.
        email: "user@example.com",
        emailVerified: true,
        name: "Ada",
        createdAt: NOW,
        updatedAt: NOW,
        attributes: { role: "admin" },
      },
    },
  ],
});

const JSON_API = "application/vnd.api+json";

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
      headers: R.fromEntries(request.headers.entries()),
      body: request.body === null ? "" : await request.clone().text(),
    });
    return respond(request);
  };
  return { calls, fetcher };
};

const okSession = (setCookie: ReadonlyArray<string> = []) =>
  new Response(toJson(sessionDocument()), {
    status: 200,
    headers: [
      ["content-type", JSON_API],
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
    expect(call.url).toBe("https://auth.internal/api/auth/sessions/current?include=user");
    expect(call.method).toBe("GET");
    // A JSON:API read, whatever the inbound request accepted.
    expect(call.headers["accept"]).toBe(JSON_API);
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
    const { fetcher } = spy(
      () =>
        new Response(toJson(sessionDocument(9e15)), {
          status: 200,
          headers: { "content-type": JSON_API },
        }),
    );
    const client = RemoteSession.make({ fetcher });

    const error = await Effect.runPromise(Effect.flip(client.read(inbound(withSession))));
    expect(error._tag).toBe("RemoteSessionError");
    expect(error.message).toMatch(/did not decode/);
  });

  it("a document that leaves the user out is a RemoteSessionError", async () => {
    const { data } = sessionDocument();
    const { fetcher } = spy(
      () => new Response(toJson({ data }), { status: 200, headers: { "content-type": JSON_API } }),
    );
    const client = RemoteSession.make({ fetcher });

    const error = await Effect.runPromise(Effect.flip(client.read(inbound(withSession))));
    expect(error._tag).toBe("RemoteSessionError");
    expect(error.message).toMatch(/did not include the session's user/);
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
    expect(call.url).toBe("https://auth.svc.local/auth/sessions/current?include=user");
  });
});

/** What a {@link trackedBody} whose cancel fails throws. */
class CancelFailed extends Error {}

/**
 * A body that never ends, recording whether it was cancelled; with
 * `cancelFails`, its cancel throws, so `body.cancel()` rejects.
 */
const trackedBody = (
  cancelFails: boolean,
): { readonly stream: ReadableStream<Uint8Array>; readonly cancelled: () => boolean } => {
  let cancelled = false;
  return {
    stream: new ReadableStream<Uint8Array>({
      cancel: () => {
        cancelled = true;
        if (cancelFails) throw new CancelFailed("cancel failed");
      },
    }),
    cancelled: () => cancelled,
  };
};

describe("RemoteSession cancels every response body it does not read", () => {
  const reads = [
    ["read", (client: RemoteSession.RemoteSessionClient) => client.read],
    [
      "readApiKey",
      (client: RemoteSession.RemoteSessionClient) => {
        assert(client.readApiKey !== undefined, "make builds readApiKey");
        return client.readApiKey;
      },
    ],
  ] as const;

  describe.each(reads)("%s", (_name, readOf) => {
    it.each([false, true])(
      "a 401 is anonymous, its body cancelled (the cancel fails: %s)",
      async (cancelFails) => {
        const body = trackedBody(cancelFails);
        const { fetcher } = spy(() => new Response(body.stream, { status: 401 }));
        const read = readOf(RemoteSession.make({ fetcher }));

        const result = await Effect.runPromise(
          read(inbound({ "x-api-key": "key", ...withSession })),
        );
        expect(Option.isNone(result.session)).toBe(true);
        expect(body.cancelled()).toBe(true);
      },
    );

    it.each([false, true])(
      "a non-200 is a RemoteSessionError, its body cancelled (the cancel fails: %s)",
      async (cancelFails) => {
        const body = trackedBody(cancelFails);
        const { fetcher } = spy(() => new Response(body.stream, { status: 503 }));
        const read = readOf(RemoteSession.make({ fetcher }));

        const error = await Effect.runPromise(
          Effect.flip(read(inbound({ "x-api-key": "key", ...withSession }))),
        );
        expect(error._tag).toBe("RemoteSessionError");
        expect(error.status).toBe(503);
        expect(body.cancelled()).toBe(true);
      },
    );
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
    // What `GET /api-keys/current` answers: the key, its user included (#730).
    const keyDocument = {
      data: {
        type: "api-keys",
        id: "key-1",
        attributes: {
          start: "abcdef",
          enabled: true,
          metadata: {},
          createdAt: NOW,
          updatedAt: NOW,
        },
        relationships: { user: { data: { type: "users", id: "user-42" } } },
      },
      included: sessionDocument().included,
    };
    const { calls, fetcher } = spy(
      () =>
        new Response(toJson(keyDocument), { status: 200, headers: { "content-type": JSON_API } }),
    );
    const client = RemoteSession.make({ fetcher });

    const result = await Effect.runPromise(
      RemoteSession.resolveAtEdge({ client, request: inbound({ "x-api-key": "key_live_1" }) }),
    );

    expect(result.outcome).toBe("resolved");
    expect(result.user?.id).toBe("user-42");
    expect(result.apiKey?.id).toBe("key-1");
    expect(calls).toHaveLength(1);
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/api-keys/current");
    expect(call.headers["x-api-key"]).toBe("key_live_1");
    // And it is carried as a machine credential, so the policy kernel sees the
    // same class the HTTP middleware would have provided.
    expect(result.credentialClass).toBe("machine");
  });
});

// ---------------------------------------------------------------------------
// The Set-Cookie relay
// ---------------------------------------------------------------------------

/** The `201` a `POST /sessions` answers: the new `sessions` resource. */
const signedIn = { data: { type: "sessions", id: "session-1", attributes: {} } };

const signInResponse = () =>
  new Response(toJson(signedIn), {
    status: 201,
    headers: [
      ["content-type", "application/vnd.api+json"],
      ["set-cookie", "__Host-conduit_session=new-token; Path=/; HttpOnly; Secure"],
      ["set-cookie", "__Host-conduit_session_data=cache; Path=/; HttpOnly"],
    ],
  });

/** The part of a relayed sign-in document the relay test reads. */
const SignInBody = Schema.fromJsonString(
  Schema.Struct({
    data: Schema.Struct({
      type: Schema.Literal("sessions"),
      attributes: Schema.Struct({ credential: Schema.Struct({ email: Schema.String }) }),
    }),
  }),
);

describe("RemoteSession relay", () => {
  it("sign-in through an app-owned front door establishes a browser session", async () => {
    const { calls, fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: {
        "content-type": "application/vnd.api+json",
        origin: "https://app.example.com",
        cookie: "__Host-conduit_session=stale",
      },
      body: toJson({
        data: {
          type: "sessions",
          attributes: {
            credential: {
              method: "password",
              email: "user@example.com",
              password: "hunter2hunter2",
            },
          },
        },
      }),
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));

    // No app-authored header handling: the body, content-type and origin all
    // arrived, and the raw Set-Cookie came back untouched.
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/sessions");
    expect(call.method).toBe("POST");
    expect(call.headers["content-type"]).toBe("application/vnd.api+json");
    expect(call.headers["origin"]).toBe("https://app.example.com");
    expect(Schema.decodeUnknownSync(SignInBody)(call.body).data.attributes.credential.email).toBe(
      "user@example.com",
    );

    expect(response.status).toBe(201);
    expect(response.headers.getSetCookie()).toStrictEqual([
      "__Host-conduit_session=new-token; Path=/; HttpOnly; Secure",
      "__Host-conduit_session_data=cache; Path=/; HttpOnly",
    ]);
    expect(await response.json()).toStrictEqual(signedIn);
  });

  it("a first sign-in with no inbound cookie receives its session cookie (#619)", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    // A browser that has never signed in carries no session or cache cookie:
    // the cookie it is about to receive is the one it lacks.
    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/vnd.api+json", origin: "https://app.example.com" },
      body: toJson({
        data: {
          type: "sessions",
          attributes: {
            credential: {
              method: "password",
              email: "user@example.com",
              password: "hunter2hunter2",
            },
          },
        },
      }),
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));
    expect(response.status).toBe(201);
    expect(response.headers.getSetCookie()).toStrictEqual([
      "__Host-conduit_session=new-token; Path=/; HttpOnly; Secure",
      "__Host-conduit_session_data=cache; Path=/; HttpOnly",
    ]);
  });

  it("a relayed session read with a session cookie receives its refreshed cookies", async () => {
    const refreshed = "__Host-conduit_session_data=fresh; Path=/; HttpOnly";
    const { calls, fetcher } = spy(() => okSession([refreshed]));
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions/current?include=user", {
      headers: withSession,
    });

    const response = await Effect.runPromise(
      client.relay(request, "/sessions/current?include=user"),
    );
    expect(calls[0]?.method).toBe("GET");
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toStrictEqual([refreshed]);
  });

  it("a key-bearing request provably receives no Set-Cookie", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/vnd.api+json", "x-api-key": "key_live_1" },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));
    expect(response.headers.getSetCookie()).toStrictEqual([]);
    // The rest of the response is untouched.
    expect(response.status).toBe(201);
    expect(await response.json()).toStrictEqual(signedIn);
  });

  it("the mixed cookie+key case receives no Set-Cookie either", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: {
        "content-type": "application/vnd.api+json",
        "x-api-key": "key_live_1",
        cookie: "__Host-conduit_session=raw-token",
      },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));
    expect(response.headers.getSetCookie()).toStrictEqual([]);
  });

  it("a bearer-only native client receives no Set-Cookie", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/vnd.api+json", authorization: "Bearer tok" },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));
    // Its credential is the token it already holds; `set-auth-token` is the
    // channel for that, not a cookie jar.
    expect(response.headers.getSetCookie()).toStrictEqual([]);
  });

  it("the mixed cookie+bearer case receives no Set-Cookie either", async () => {
    const { fetcher } = spy(() => signInResponse());
    const client = RemoteSession.make({ fetcher });

    const request = new Request("https://app.example.com/auth/sessions", {
      method: "POST",
      headers: {
        "content-type": "application/vnd.api+json",
        authorization: "Bearer tok",
        cookie: "__Host-conduit_session=raw-token",
      },
      body: "{}",
    });

    const response = await Effect.runPromise(client.relay(request, "/sessions"));
    expect(response.headers.getSetCookie()).toStrictEqual([]);
  });

  it("relayResponse applies the same rule to a hand-rolled relay", () => {
    const keyed = SessionResolution.detectCredential(
      SessionResolution.fromRequest(inbound({ "x-api-key": "k" })),
    );
    const browser = SessionResolution.detectCredential(
      SessionResolution.fromRequest(inbound(withSession)),
    );
    const bearer = SessionResolution.detectCredential(
      SessionResolution.fromRequest(inbound({ authorization: "Bearer tok" })),
    );
    const none = SessionResolution.detectCredential(SessionResolution.fromRequest(inbound()));

    expect(
      RemoteSession.relayResponse(signInResponse(), keyed).headers.getSetCookie(),
    ).toStrictEqual([]);
    expect(
      RemoteSession.relayResponse(signInResponse(), browser).headers.getSetCookie(),
    ).toHaveLength(2);
    expect(
      RemoteSession.relayResponse(signInResponse(), bearer).headers.getSetCookie(),
    ).toStrictEqual([]);
    expect(RemoteSession.relayResponse(signInResponse(), none).headers.getSetCookie()).toHaveLength(
      2,
    );
  });
});

/** Relay `upstream` to a caller sending `headers`. */
const relayed = (upstream: Response, headers: Record<string, string> = {}) =>
  RemoteSession.relayResponse(
    upstream,
    SessionResolution.detectCredential(SessionResolution.fromRequest(inbound(headers))),
  );

/** A sign-out answer clearing the session cookie, under `cacheControl` if given. */
const clearing = (cacheControl?: string) =>
  new Response(null, {
    status: 204,
    headers: {
      ...(cacheControl !== undefined && { "cache-control": cacheControl }),
      "set-cookie": "__Host-conduit_session=; Path=/; Max-Age=0; HttpOnly; Secure",
    },
  });

describe("a relayed response carrying Set-Cookie is no-store (#628)", () => {
  it("marks a relayed session cookie no-store, first sign-in and cookie-bearing alike", () => {
    expect(relayed(signInResponse()).headers.get("cache-control")).toBe("no-store");
    expect(relayed(signInResponse(), withSession).headers.get("cache-control")).toBe("no-store");
  });

  it("marks a relayed cookie-clearing sign-out no-store", () => {
    const response = relayed(clearing());
    expect(response.status).toBe(204);
    expect(response.headers.getSetCookie()).toHaveLength(1);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("appends no-store to an upstream Cache-Control that lacks it, keeping its directives", () => {
    expect(relayed(clearing("private, max-age=60")).headers.get("cache-control")).toBe(
      "private, max-age=60, no-store",
    );
  });

  it("keeps an upstream Cache-Control that already has no-store", () => {
    expect(relayed(clearing("private, No-Store")).headers.get("cache-control")).toBe(
      "private, No-Store",
    );
  });

  it("leaves a response without Set-Cookie as it is", () => {
    const upstream = new Response("{}", { headers: { "cache-control": "max-age=60" } });
    expect(relayed(upstream)).toBe(upstream);
  });

  it("a session read over relay carries no-store with its refreshed cookie", async () => {
    const refreshed = "__Host-conduit_session_data=fresh; Path=/; HttpOnly";
    const { fetcher } = spy(() => okSession([refreshed]));
    const client = RemoteSession.make({ fetcher });
    const request = new Request("https://app.example.com/auth/sessions/current", {
      headers: withSession,
    });
    const response = await Effect.runPromise(client.relay(request, "/sessions/current"));
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("withSetCookie marks the outgoing response no-store when it replays a cookie", () => {
    const response = RemoteSession.withSetCookie(
      new Response("{}", { headers: { "cache-control": "private" } }),
      ["__Host-conduit_session_data=; Path=/; Max-Age=0"],
    );
    expect(response.headers.get("cache-control")).toBe("private, no-store");
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
        return yield* http.get("https://auth.internal/api/auth/sessions/current");
      }).pipe(Effect.provide(RemoteSession.layerFetcher(fetcher))),
    );

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(1);
    const call = calls[0];
    assert(call !== undefined);
    expect(call.url).toBe("https://auth.internal/api/auth/sessions/current");
  });
});

// ---------------------------------------------------------------------------
// Against the real handler: the session the edge resolves carries no token
// ---------------------------------------------------------------------------

describe("RemoteSession over a real Http.make handler (#581)", () => {
  it("resolves the session under its digest; the cookie's token is in no body", async () => {
    const server = makeServerFixture();
    const signUp = await server.handler(
      new Request("http://auth.internal/users", {
        method: "POST",
        headers: { "content-type": JSON_API },
        body: toJson({
          data: {
            type: "users",
            attributes: { email: "edge@example.com", password: "pw-12345678" },
          },
        }),
      }),
    );
    expect(signUp.status).toBe(201);
    const token = /conduit_session=([^;]+)/.exec(signUp.headers.get("set-cookie") ?? "")?.[1];
    assert(token !== undefined, "sign-up set the session cookie");

    const bodies: Array<string> = [];
    const client = RemoteSession.make({
      fetcher: async (request) => {
        const response = await server.handler(request);
        bodies.push(await response.clone().text());
        return response;
      },
      baseUrl: "http://auth.internal",
      prefix: "",
    });
    const result = await Effect.runPromise(
      client.read(inbound({ cookie: `conduit_session=${token}` })),
    );

    assert(Option.isSome(result.session));
    expect(result.session.value.session.id).toBe(hashToken(token));
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).not.toContain(token);
  });
});
