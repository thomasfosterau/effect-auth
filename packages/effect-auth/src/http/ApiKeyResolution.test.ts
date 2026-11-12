/**
 * `GET /api-keys/current` and RemoteSession's API-key path (#730): a key
 * presented in an API-key header resolves to the key and its user; every key
 * that does not resolve gets one identical `401`; only a real key over its own
 * limit gets `429`; the key never reaches a log line or a body; and a key never
 * falls back to a session cookie the request also carries.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Exit, Logger, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Struct from "effect/Struct";
import { AuthError } from "../Errors.ts";
import type * as Auth from "../index.ts";
import { memoryRateLimitStore } from "../testing/MemoryStores.ts";
import { hashApiKey } from "../ApiKey.ts";
import { makeServerFixture, type ServerFixtureOptions } from "../client/testing/fixture.ts";
import * as RemoteSession from "./RemoteSession.ts";

const JSON_API = "application/vnd.api+json";
const BASE = "http://auth.internal";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

type Handler = (request: Request) => Promise<Response>;

/** A store call that fails as a down store does. */
const broken = () => Effect.fail(new AuthError({ message: "rate-limit store down" }));

/** A server with API keys mounted (unless `apiKeys: false`), its log captured as JSON lines. */
const server = (options: ServerFixtureOptions = {}) => {
  const logs: Array<string> = [];
  const collector = Logger.make((entry) => void logs.push(Logger.formatJson.log(entry)));
  const fixture = makeServerFixture({
    apiKeys: true,
    ...options,
    layer: Logger.layer([collector]),
  });
  return { handler: fixture.handler, logs, fixture };
};

/** Sign up `email`; answers the raw session token the cookie carries. */
const signUp = async (handler: Handler, email: string): Promise<string> => {
  const res = await handler(
    new Request(`${BASE}/users`, {
      method: "POST",
      headers: { "content-type": JSON_API },
      body: toJson({ data: { type: "users", attributes: { email, password: "pw-12345678" } } }),
    }),
  );
  expect(res.status).toBe(201);
  const token = /conduit_session=([^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
  assert(token !== undefined, "sign-up set the session cookie");
  return token;
};

const cookie = (token: string) => ({ cookie: `conduit_session=${token}` });

const Created = Schema.Struct({
  data: Schema.Struct({ id: Schema.String }),
  meta: Schema.Struct({ key: Schema.String }),
});

/** `POST /api-keys` as the session `token`; answers the key's id and plaintext. */
const createKey = async (
  handler: Handler,
  token: string,
  attributes: Schema.Json = {},
): Promise<{ readonly id: string; readonly key: string }> => {
  const res = await handler(
    new Request(`${BASE}/api-keys`, {
      method: "POST",
      headers: { "content-type": JSON_API, ...cookie(token) },
      body: toJson({ data: { type: "api-keys", attributes } }),
    }),
  );
  expect(res.status).toBe(201);
  const created = Schema.decodeUnknownSync(Created)(await res.json());
  return { id: created.data.id, key: created.meta.key };
};

/** `PATCH /api-keys/:id` as the session `token`. */
const updateKey = async (handler: Handler, token: string, id: string, attributes: Schema.Json) => {
  const res = await handler(
    new Request(`${BASE}/api-keys/${id}`, {
      method: "PATCH",
      headers: { "content-type": JSON_API, ...cookie(token) },
      body: toJson({ data: { type: "api-keys", id, attributes } }),
    }),
  );
  expect(res.status).toBe(200);
};

/** `GET /api-keys/current` with `headers`. */
const current = (handler: Handler, headers: Record<string, string>, query = "") =>
  handler(
    new Request(`${BASE}/api-keys/current${query}`, {
      headers: { accept: JSON_API, ...headers },
    }),
  );

/** The parts of an answer a refusal must not vary in. */
const refusalShape = async (res: Response) => ({
  status: res.status,
  contentType: res.headers.get("content-type"),
  cacheControl: res.headers.get("cache-control"),
  retryAfter: res.headers.get("retry-after"),
  setCookie: res.headers.get("set-cookie"),
  wwwAuthenticate: res.headers.get("www-authenticate"),
  body: await res.text(),
});

/** Run `requests` one after another (a key's uses are counted in order). */
const inSequence = <A, B>(items: ReadonlyArray<A>, run: (item: A) => Promise<B>) =>
  Arr.reduce(items, Promise.resolve<Array<B>>([]), async (acc, item) => [
    ...(await acc),
    await run(item),
  ]);

const CurrentKey = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("api-keys"),
    id: Schema.String,
    attributes: Schema.Struct({
      name: Schema.String,
      enabled: Schema.Boolean,
      remaining: Schema.Finite,
      lastUsedAt: Schema.Finite,
      permissions: Schema.Record(Schema.String, Schema.Array(Schema.String)),
      metadata: Schema.Record(Schema.String, Schema.Unknown),
    }),
    relationships: Schema.Struct({
      user: Schema.Struct({ data: Schema.Struct({ type: Schema.String, id: Schema.String }) }),
    }),
  }),
  included: Schema.Array(Schema.Struct({ type: Schema.String, id: Schema.String })),
});

/** The exact `401` every key that does not resolve gets. */
const REFUSED_BODY = toJson({
  errors: [
    {
      status: "401",
      code: "unauthorized",
      title: "Unauthorized",
      detail: "Invalid API key",
      meta: { message: "Invalid API key" },
    },
  ],
});

describe("GET /api-keys/current (#730)", () => {
  it("answers the key's public fields and its user, consuming one use", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const { id, key } = await createKey(handler, token, {
      name: "CI",
      remaining: 5,
      permissions: { projects: ["read"] },
      metadata: { team: "infra" },
    });

    const res = await current(handler, { "x-api-key": key });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain(JSON_API);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const text = await res.text();
    // Neither the plaintext nor its digest is anywhere in the body.
    expect(text).not.toContain(key);
    expect(text).not.toContain(hashApiKey(key));
    expect(text).not.toContain("keyHash");
    const body = Schema.decodeSync(Schema.fromJsonString(CurrentKey))(text);
    expect(body.data.id).toBe(id);
    expect(body.data.attributes).toMatchObject({
      name: "CI",
      enabled: true,
      // The resolution is a verification: it spent one of the five uses.
      remaining: 4,
      permissions: { projects: ["read"] },
      metadata: { team: "infra" },
    });
    const userId = body.data.relationships.user.data.id;
    expect(body.included).toEqual([expect.objectContaining({ type: "users", id: userId })]);

    const again = Schema.decodeUnknownSync(CurrentKey)(
      await (await current(handler, { "x-api-key": key })).json(),
    );
    expect(again.data.attributes.remaining).toBe(3);
  });

  it("answers an unknown, disabled, expired or exhausted key (or none) with one identical 401", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const disabled = await createKey(handler, token, { name: "disabled" });
    await updateKey(handler, token, disabled.id, { enabled: false });
    const expired = await createKey(handler, token, { name: "expired" });
    await updateKey(handler, token, expired.id, { expiresAt: 1 });
    const exhausted = await createKey(handler, token, { name: "exhausted", remaining: 1 });
    expect((await current(handler, { "x-api-key": exhausted.key })).status).toBe(200);

    const unknown = await refusalShape(await current(handler, { "x-api-key": "ak_not-a-key" }));
    expect(unknown).toEqual({
      status: 401,
      contentType: JSON_API,
      cacheControl: "no-store",
      retryAfter: null,
      setCookie: null,
      wwwAuthenticate: null,
      body: REFUSED_BODY,
    });
    const others = await inSequence(
      [
        { "x-api-key": disabled.key },
        { "x-api-key": expired.key },
        { "x-api-key": exhausted.key },
        {},
      ],
      async (headers) => refusalShape(await current(handler, headers)),
    );
    expect(others).toEqual([unknown, unknown, unknown, unknown]);
  });

  it("answers a disabled, expired or exhausted key over its own limit with the identical 401, not 429", async () => {
    // A revoked-but-real key must not be told apart from an unknown one by
    // its per-key bucket: every other refusal is decided before the limit.
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const rateLimit = { maxRequests: 1, windowMs: 60_000 };
    const disabled = await createKey(handler, token, { rateLimit });
    const expired = await createKey(handler, token, { rateLimit });
    const exhausted = await createKey(handler, token, { rateLimit, remaining: 1 });
    // Spend each key's one request in its window, so each bucket is full.
    const first = await inSequence(
      [disabled, expired, exhausted],
      async ({ key }) => (await current(handler, { "x-api-key": key })).status,
    );
    expect(first).toEqual([200, 200, 200]);
    await updateKey(handler, token, disabled.id, { enabled: false });
    await updateKey(handler, token, expired.id, { expiresAt: 1 });

    const unknown = await refusalShape(await current(handler, { "x-api-key": "ak_not-a-key" }));
    const overLimit = await inSequence([disabled, expired, exhausted], async ({ key }) =>
      refusalShape(await current(handler, { "x-api-key": key })),
    );
    expect(overLimit).toEqual([unknown, unknown, unknown]);
    expect(unknown.body).toBe(REFUSED_BODY);
  });

  it("never writes the key to a log line or an error body, and logs why it refused", async () => {
    const { handler, logs } = server();
    const token = await signUp(handler, "ada@example.com");
    const disabled = await createKey(handler, token);
    await updateKey(handler, token, disabled.id, { enabled: false });
    const limited = await createKey(handler, token, {
      rateLimit: { maxRequests: 1, windowMs: 60_000 },
    });
    const unknownKey = "ak_unknown-key-value-0123456789";
    const keys = [unknownKey, disabled.key, limited.key, limited.key];

    const bodies = await inSequence(keys, async (key) =>
      (await current(handler, { "x-api-key": key })).text(),
    );

    expect(logs.length).toBeGreaterThan(0);
    const leaks = Arr.flatMap(keys, (key) =>
      [...logs, ...bodies.slice(0, 2), bodies[3] ?? ""].filter((line) => line.includes(key)),
    );
    expect(leaks).toEqual([]);
    const refusals = logs.filter((line) => line.includes("API key refused"));
    expect(refusals.some((line) => line.includes("Invalid API key"))).toBe(true);
    expect(refusals.some((line) => line.includes("API key is disabled"))).toBe(true);
  });

  it("is resolved by the key, never by the cookie or bearer token beside it", async () => {
    const { handler } = server();
    const adaToken = await signUp(handler, "ada@example.com");
    const bobToken = await signUp(handler, "bob@example.com");
    const bobKey = await createKey(handler, bobToken, {
      name: "bob",
      remaining: 10,
      permissions: {},
    });

    const asBob = Schema.decodeUnknownSync(CurrentKey)(
      await (
        await current(handler, {
          "x-api-key": bobKey.key,
          ...cookie(adaToken),
          authorization: `Bearer ${adaToken}`,
        })
      ).json(),
    );
    expect(asBob.data.id).toBe(bobKey.id);
    const adaUser = await handler(
      new Request(`${BASE}/sessions/current?include=user`, {
        headers: { accept: JSON_API, ...cookie(adaToken) },
      }),
    );
    const adaId = Schema.decodeUnknownSync(
      Schema.Struct({
        data: Schema.Struct({
          relationships: Schema.Struct({
            user: Schema.Struct({ data: Schema.Struct({ id: Schema.String }) }),
          }),
        }),
      }),
    )(await adaUser.json()).data.relationships.user.data.id;
    expect(asBob.data.relationships.user.data.id).not.toBe(adaId);

    // An unknown key beside a valid cookie is refused, not answered for the cookie.
    const withCookie = await current(handler, { "x-api-key": "ak_nope", ...cookie(adaToken) });
    expect(withCookie.status).toBe(401);
    // A cookie alone is no key.
    expect((await current(handler, cookie(adaToken))).status).toBe(401);
  });

  it("never reads the key from the query string", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const { key } = await createKey(handler, token);
    const res = await current(handler, {}, `?api_key=${encodeURIComponent(key)}`);
    expect(res.status).toBe(401);
  });

  it("reads the configured API-key headers only", async () => {
    const { handler } = server({ cookie: { apiKeyHeaders: ["x-service-key"] } });
    const token = await signUp(handler, "ada@example.com");
    const { key } = await createKey(handler, token);
    expect((await current(handler, { "x-service-key": key })).status).toBe(200);
    expect((await current(handler, { "x-api-key": key })).status).toBe(401);
  });

  it("answers 429 with Retry-After only for a real key over its own limit", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const limited = await createKey(handler, token, {
      rateLimit: { maxRequests: 1, windowMs: 60_000 },
    });

    expect((await current(handler, { "x-api-key": limited.key })).status).toBe(200);
    const refused = await current(handler, { "x-api-key": limited.key });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("cache-control")).toBe("no-store");
    expect(Number(refused.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(Number(refused.headers.get("retry-after"))).toBeLessThanOrEqual(60);
    expect(await refused.text()).not.toContain(limited.key);

    // However often an unknown key is tried, it is never rate limited per key.
    const unknown = await inSequence(
      Arr.range(1, 5),
      async () => (await current(handler, { "x-api-key": "ak_unknown" })).status,
    );
    expect(unknown).toEqual(Arr.replicate(401, 5));
  });

  describe("a key whose owner is banned, SCIM-deactivated or gone (#755)", () => {
    const owners = {
      banned: (user: Auth.User): Auth.User | null => ({
        ...user,
        attributes: { ...user.attributes, banned: true },
      }),
      deactivated: (user: Auth.User): Auth.User | null => ({
        ...user,
        attributes: { ...user.attributes, scimDeactivated: true },
      }),
      gone: (): Auth.User | null => null,
    };

    it.each(Struct.keys(owners))(
      "%s: answers the unknown-key 401 under and over its limit, spending nothing",
      async (state) => {
        const { handler, fixture } = server();
        const token = await signUp(handler, "ada@example.com");
        const rateLimit = { maxRequests: 1, windowMs: 60_000 };
        const under = await createKey(handler, token, { rateLimit, remaining: 10 });
        const over = await createKey(handler, token, { rateLimit, remaining: 10 });
        // `over` spends its one request in the window; `under` keeps its token.
        expect((await current(handler, { "x-api-key": over.key })).status).toBe(200);

        const record = (id: string) =>
          Option.getOrUndefined(MutableHashMap.get(fixture.apiKeyRecords, id));
        const userId = record(under.id)?.userId ?? "";
        const owner = Option.getOrUndefined(MutableHashMap.get(fixture.usersById, userId));
        assert(owner !== undefined, "the key's owner exists before the change");
        const changed = owners[state](owner);
        if (changed === null) MutableHashMap.remove(fixture.usersById, userId);
        else MutableHashMap.set(fixture.usersById, userId, changed);
        const before = [under, over].map(({ id }) => record(id));

        const unknown = await refusalShape(await current(handler, { "x-api-key": "ak_not-a-key" }));
        const answers = await inSequence([under, over, under, over], async ({ key }) =>
          refusalShape(await current(handler, { "x-api-key": key })),
        );

        expect(answers).toEqual([unknown, unknown, unknown, unknown]);
        expect(unknown.body).toBe(REFUSED_BODY);
        // Neither key spent a use: `remaining` and `lastUsedAt` are as they were.
        expect([under, over].map(({ id }) => record(id))).toEqual(before);
      },
    );
  });

  it("answers 500 when the per-key limiter's store fails, never resolving the key", async () => {
    const failing = { on: false };
    const inner = memoryRateLimitStore();
    const rateLimitStore: typeof Auth.RateLimitStore.Service = {
      get: (key) => (failing.on ? broken() : inner.get(key)),
      set: (key, entry, ttl) => (failing.on ? broken() : inner.set(key, entry, ttl)),
      increment: (key, ttl) => (failing.on ? broken() : inner.increment(key, ttl)),
      delete: (key) => (failing.on ? broken() : inner.delete(key)),
    };
    const { handler } = server({ rateLimitStore });
    const token = await signUp(handler, "ada@example.com");
    const limited = await createKey(handler, token, {
      rateLimit: { maxRequests: 10, windowMs: 60_000 },
    });

    failing.on = true;
    const res = await current(handler, { "x-api-key": limited.key });
    expect(res.status).toBe(500);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).not.toContain(limited.key);
  });

  it("answers 404, cookie or not, when no ApiKeyService is mounted", async () => {
    const { handler } = server({ apiKeys: false });
    const token = await signUp(handler, "ada@example.com");
    const res = await current(handler, { "x-api-key": "ak_any", ...cookie(token) });
    expect(res.status).toBe(404);
    expect((await current(handler, cookie(token))).status).toBe(404);
  });
});

/** A client over `handler`, recording the requests it sends. */
const remote = (handler: Handler, options: Partial<RemoteSession.RemoteSessionOptions> = {}) => {
  const sent: Array<Request> = [];
  const client = RemoteSession.make({
    fetcher: async (request) => {
      sent.push(request.clone());
      return handler(request);
    },
    baseUrl: BASE,
    prefix: "",
    ...options,
  });
  return { client, sent };
};

/** A request arriving at the app's edge. */
const inbound = (headers: Record<string, string>) =>
  new Request("https://app.example.com/api/things", { headers });

describe("RemoteSession's API-key path (#730)", () => {
  it("resolves a key to its user, with no session, as a machine caller", async () => {
    const { handler } = server();
    const adaToken = await signUp(handler, "ada@example.com");
    const bobToken = await signUp(handler, "bob@example.com");
    const bobKey = await createKey(handler, bobToken, { name: "bot" });
    const { client, sent } = remote(handler);

    const edge = await Effect.runPromise(
      RemoteSession.resolveAtEdge({
        client,
        request: inbound({ "x-api-key": bobKey.key, ...cookie(adaToken) }),
      }),
    );

    expect(edge.outcome).toBe("resolved");
    expect(Option.isNone(edge.session)).toBe(true);
    expect(edge.credentialClass).toBe("machine");
    expect(edge.setCookie).toEqual([]);
    assert(edge.apiKey !== undefined && edge.user !== undefined);
    expect(edge.apiKey.id).toBe(bobKey.id);
    expect(edge.apiKey.name).toBe("bot");
    expect(edge.apiKey.userId).toBe(edge.user.id);
    expect(edge.user.createdAt).toBeInstanceOf(Date);
    expect(edge.apiKey).not.toHaveProperty("keyHash");
    // Only the six-character `start` of the key travels, never the key.
    expect(edge.apiKey.start).toHaveLength(6);
    expect(bobKey.key).toContain(edge.apiKey.start);

    // One call, to the key endpoint, carrying the key and not the cookie.
    expect(sent.map((request) => new URL(request.url).pathname)).toEqual(["/api-keys/current"]);
    expect(sent[0]?.headers.get("x-api-key")).toBe(bobKey.key);
    expect(sent[0]?.headers.get("cookie")).toBeNull();
  });

  it("reads a key the refusal answers as anonymous, never as the cookie's session", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const { client } = remote(handler);

    const edge = await Effect.runPromise(
      RemoteSession.resolveAtEdge({
        client,
        request: inbound({ "x-api-key": "ak_unknown", ...cookie(token) }),
      }),
    );

    expect(edge.outcome).toBe("anonymous");
    expect(Option.isNone(edge.session)).toBe(true);
    expect(edge.user).toBeUndefined();
  });

  it("forwards the configured key header", async () => {
    const { handler } = server({ cookie: { apiKeyHeaders: ["x-service-key"] } });
    const token = await signUp(handler, "ada@example.com");
    const { key } = await createKey(handler, token);
    const { client } = remote(handler, { credentials: { apiKeyHeaders: ["x-service-key"] } });

    const edge = await Effect.runPromise(
      RemoteSession.resolveAtEdge({ client, request: inbound({ "x-service-key": key }) }),
    );
    expect(edge.outcome).toBe("resolved");
  });

  it("fails closed, not over to the cookie, when the auth service mounts no ApiKeyService", async () => {
    const { handler } = server({ apiKeys: false });
    const token = await signUp(handler, "ada@example.com");
    const { client, sent } = remote(handler);
    const request = inbound({ "x-api-key": "ak_any", ...cookie(token) });

    const exit = await Effect.runPromiseExit(RemoteSession.resolveAtEdge({ client, request }));
    assert(Exit.isFailure(exit));
    const error = exit.cause.reasons[0];
    assert(error?._tag === "Fail");
    expect(error.error).toMatchObject({ _tag: "RemoteSessionError", status: 404 });

    // Failing open degrades to anonymous: the cookie's session is never read.
    const degraded = await Effect.runPromise(
      RemoteSession.resolveAtEdgeFailOpen({ client, request, onDegraded: () => Effect.void }),
    );
    expect(degraded.outcome).toBe("degraded");
    expect(Option.isNone(degraded.session)).toBe(true);
    expect(degraded.user).toBeUndefined();
    expect(sent.map((r) => new URL(r.url).pathname)).toEqual([
      "/api-keys/current",
      "/api-keys/current",
    ]);
  });

  it("fails closed with a hand-built client that has no key read", async () => {
    const { handler } = server();
    const token = await signUp(handler, "ada@example.com");
    const { client } = remote(handler);
    const handBuilt: RemoteSession.RemoteSessionClient = {
      credential: client.credential,
      read: client.read,
      relay: client.relay,
    };
    const exit = await Effect.runPromiseExit(
      RemoteSession.resolveAtEdge({
        client: handBuilt,
        request: inbound({ "x-api-key": "ak_any", ...cookie(token) }),
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });
});
