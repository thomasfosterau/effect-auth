import { describe, it, expect } from "vite-plus/test";
import { Cause, Effect, Exit, Option, Schema } from "effect";
import { HttpServerRequest } from "effect/http";
import type * as Types from "./Types.ts";
import * as SessionResolution from "./SessionResolution.ts";
import * as SessionCookies from "./SessionCookies.ts";
import { resolveCookieConfig, sessionIdFromRequest } from "./http/HttpServer.ts";

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const now = new Date();

const resolved: Types.SessionWithUser = {
  session: {
    id: "session-1",
    userId: "user-42",
    expiresAt: new Date(now.getTime() + 3600_000),
    createdAt: now,
    lastActivityAt: now,
    attributes: {},
  },
  user: { id: "user-42", createdAt: now, updatedAt: now, attributes: {} },
};

const withSessionCookie = { cookie: "__Host-conduit_session=raw-token" };

const request = (headers: Record<string, string>) =>
  SessionResolution.fromRequest(new Request("https://app.example.com/", { headers }));

// ---------------------------------------------------------------------------
// 1. Does this request carry a credential at all?
// ---------------------------------------------------------------------------

describe("SessionResolution.detectCredential", () => {
  it("a cookieless request carries nothing — the fast path is expressible", () => {
    const presence = SessionResolution.detectCredential(request({}));
    expect(presence.present).toBe(false);
    expect(presence.kinds).toStrictEqual([]);
    expect(SessionResolution.hasSessionCredential(request({}))).toBe(false);
  });

  it("finds the session cookie under its computed __Host- name", () => {
    const presence = SessionResolution.detectCredential(
      request({ cookie: "__Host-conduit_session=abc" }),
    );
    expect(presence.present).toBe(true);
    expect(presence.kinds).toStrictEqual(["session-cookie"]);
    expect(presence.hasSessionCookie).toBe(true);
    expect(presence.hasApiKey).toBe(false);
  });

  it("finds the signed cache cookie on its own", () => {
    const presence = SessionResolution.detectCredential(
      request({ cookie: "__Host-conduit_session_data=signed" }),
    );
    expect(presence.kinds).toStrictEqual(["session-cache-cookie"]);
    expect(presence.hasSessionCookie).toBe(true);
  });

  it.each([
    ["Bearer", "Bearer tok"],
    ["Token", "Token tok"],
  ])("finds an %s Authorization header", (_scheme, authorization) => {
    const presence = SessionResolution.detectCredential(request({ authorization }));
    expect(presence.hasBearer).toBe(true);
    expect(presence.present).toBe(true);
    // A bearer is not a browser cookie, so a relay must not answer it with
    // Set-Cookie either.
    expect(presence.hasSessionCookie).toBe(false);
  });

  it("ignores an Authorization scheme it does not understand", () => {
    const presence = SessionResolution.detectCredential(request({ authorization: "Basic abc" }));
    expect(presence.present).toBe(false);
  });

  it("finds a machine caller's API key, so it does not take the fast path", () => {
    const presence = SessionResolution.detectCredential(request({ "x-api-key": "key_live_1" }));
    expect(presence.present).toBe(true);
    expect(presence.hasApiKey).toBe(true);
    expect(presence.hasSessionCookie).toBe(false);
  });

  it("honours a custom API-key header list", () => {
    const config = { apiKeyHeaders: ["x-gardeneria-key"] };
    expect(
      SessionResolution.detectCredential(request({ "x-api-key": "k" }), config).hasApiKey,
    ).toBe(false);
    expect(
      SessionResolution.detectCredential(request({ "x-gardeneria-key": "k" }), config).hasApiKey,
    ).toBe(true);
  });

  it("reports the mixed cookie+key case as both", () => {
    const presence = SessionResolution.detectCredential(
      request({ cookie: "__Host-conduit_session=abc", "x-api-key": "key_live_1" }),
    );
    expect(presence.hasSessionCookie).toBe(true);
    expect(presence.hasApiKey).toBe(true);
  });
});

describe("SessionResolution.credentialClassOf", () => {
  it.each([
    ["a session cookie", withSessionCookie, "interactive"],
    ["a bearer token", { authorization: "Bearer tok" }, "machine"],
    ["an API key", { "x-api-key": "k" }, "machine"],
    ["a cookie and a key", { ...withSessionCookie, "x-api-key": "k" }, "machine"],
  ])("classifies %s as %s", (_label, headers, expected) => {
    expect(
      SessionResolution.credentialClassOf(SessionResolution.detectCredential(request(headers))),
    ).toBe(expected);
  });
});

describe("SessionResolution credential sources", () => {
  it("reads a plain header record (Node-style)", () => {
    const source = SessionResolution.fromHeaders({
      cookie: "__Host-conduit_session=abc",
    });
    expect(SessionResolution.hasSessionCredential(source)).toBe(true);
  });

  it("reads a SvelteKit-style cookie jar", () => {
    const jar = { get: (name: string) => (name === "__Host-conduit_session" ? "abc" : undefined) };
    const source = SessionResolution.fromCookies(jar);
    expect(SessionResolution.hasSessionCredential(source)).toBe(true);
  });

  it("a cookie jar plus headers sees the machine credential too", () => {
    const jar = { get: () => undefined };
    const source = SessionResolution.fromCookies(jar, { "x-api-key": "k" });
    expect(SessionResolution.detectCredential(source).hasApiKey).toBe(true);
  });

  it("extractApiKey and extractSessionToken read what the gate reads", () => {
    const source = request({ authorization: "Bearer tok", "x-api-key": "k" });
    expect(SessionResolution.extractApiKey(source)).toBe("k");
    expect(SessionResolution.extractSessionToken(source)).toBe("tok");
  });

  it("extractSessionToken falls back to the cookie, as the middleware does", () => {
    const source = request({ cookie: "__Host-conduit_session=from-cookie" });
    expect(SessionResolution.extractSessionToken(source)).toBe("from-cookie");
  });
});

// ---------------------------------------------------------------------------
// The drift test #186 asks for
// ---------------------------------------------------------------------------

describe("the edge predicate cannot desynchronise from the middleware", () => {
  const configs = [
    {},
    { name: "app_session" },
    { secure: false },
    { secure: false, name: "app_session" },
    { hostPrefix: false },
    { hostPrefix: false, name: "app_session" },
    { secure: true, hostPrefix: true, name: "app_session" },
    { path: "/api" },
    { secure: false, path: "/api", name: "app_session" },
  ] as const;

  it.each(configs.map((config) => [encodeJson(config), config] as const))(
    "%s — the name the predicate looks for is the name the middleware reads",
    (_label, config) => {
      const edgeName = SessionCookies.cookieNames(config).session;
      // `resolveCookieConfig` is what the middleware runs. If these two ever
      // disagree, a cookie-bearing request gets skipped as cookieless.
      expect(edgeName).toBe(resolveCookieConfig(config).name);
    },
  );

  it.each(configs.map((config) => [encodeJson(config), config] as const))(
    "%s — a request the middleware can read is never classified as cookieless",
    (_label, config) => {
      const name = resolveCookieConfig(config).name;
      const headers = { cookie: `${name}=raw-token` };

      const middlewareSees = sessionIdFromRequest(
        HttpServerRequest.fromWeb(new Request("https://app.example.com/", { headers })),
        resolveCookieConfig(config),
      );
      const edgeSees = SessionResolution.hasSessionCredential(request(headers), config);

      expect(middlewareSees).toBe("raw-token");
      expect(edgeSees).toBe(true);
    },
  );
});

// ---------------------------------------------------------------------------
// 2 & 3. Fault posture, and one outcome
// ---------------------------------------------------------------------------

class Unreachable {
  readonly _tag = "Unreachable";
}

describe("SessionResolution.resolve (fail closed)", () => {
  it("no credential → skipped, and the resolver never runs", async () => {
    let ran = false;
    const result = await Effect.runPromise(
      SessionResolution.resolve({
        credential: false,
        resolve: Effect.sync(() => {
          ran = true;
          return Option.some(resolved);
        }),
      }),
    );
    expect(result.outcome).toBe("skipped");
    expect(Option.isNone(result.session)).toBe(true);
    expect(ran).toBe(false);
  });

  it("ran and found a session → resolved", async () => {
    const result = await Effect.runPromise(
      SessionResolution.resolve({
        credential: true,
        resolve: Effect.succeed(Option.some(resolved)),
      }),
    );
    expect(result.outcome).toBe("resolved");
    expect(result.session).toStrictEqual(Option.some(resolved));
  });

  it("ran and found nothing → anonymous, distinct from skipped", async () => {
    const result = await Effect.runPromise(
      SessionResolution.resolve({
        credential: true,
        resolve: Effect.succeed(Option.none<Types.SessionWithUser>()),
      }),
    );
    // A stale cookie still paid the round trip. Folding this into `skipped`
    // would corrupt the duration bucket.
    expect(result.outcome).toBe("anonymous");
  });

  it("a fault stays in the error channel", async () => {
    const exit = await Effect.runPromiseExit(
      SessionResolution.resolve({
        credential: true,
        resolve: Effect.fail(new Unreachable()),
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it("accepts a CredentialPresence directly", async () => {
    const result = await Effect.runPromise(
      SessionResolution.resolve({
        credential: SessionResolution.detectCredential(request({})),
        resolve: Effect.succeed(Option.some(resolved)),
      }),
    );
    expect(result.outcome).toBe("skipped");
  });
});

describe("SessionResolution.resolveFailOpen", () => {
  it("a typed failure degrades to anonymous and calls onDegraded", async () => {
    const seen: Array<Cause.Cause<Unreachable>> = [];
    const result = await Effect.runPromise(
      SessionResolution.resolveFailOpen({
        credential: true,
        resolve: Effect.fail(new Unreachable()),
        onDegraded: (cause) => Effect.sync(() => void seen.push(cause)),
      }),
    );
    expect(result.outcome).toBe("degraded");
    expect(Option.isNone(result.session)).toBe(true);
    expect(seen).toHaveLength(1);
  });

  it("a defect degrades too — an unreachable binding throws rather than fails", async () => {
    let degraded = false;
    const result = await Effect.runPromise(
      SessionResolution.resolveFailOpen({
        credential: true,
        resolve: Effect.sync((): Option.Option<Types.SessionWithUser> => {
          throw new TypeError("Network connection lost.");
        }),
        onDegraded: () => Effect.sync(() => void (degraded = true)),
      }),
    );
    expect(result.outcome).toBe("degraded");
    expect(degraded).toBe(true);
  });

  it("a skip never calls onDegraded", async () => {
    let degraded = false;
    const result = await Effect.runPromise(
      SessionResolution.resolveFailOpen({
        credential: false,
        resolve: Effect.fail(new Unreachable()),
        onDegraded: () => Effect.sync(() => void (degraded = true)),
      }),
    );
    expect(result.outcome).toBe("skipped");
    expect(degraded).toBe(false);
  });

  it("the happy path is unchanged", async () => {
    const result = await Effect.runPromise(
      SessionResolution.resolveFailOpen({
        credential: true,
        resolve: Effect.succeed(Option.some(resolved)),
        onDegraded: () => Effect.void,
      }),
    );
    expect(result.outcome).toBe("resolved");
    expect(result.session).toStrictEqual(Option.some(resolved));
  });

  it("the four outcomes are the four states, derived in one place", async () => {
    const run = (
      credential: boolean,
      resolveEffect: Effect.Effect<Option.Option<Types.SessionWithUser>, Unreachable>,
    ) =>
      Effect.runPromise(
        SessionResolution.resolveFailOpen({
          credential,
          resolve: resolveEffect,
          onDegraded: () => Effect.void,
        }),
      ).then((r) => r.outcome);

    expect(await run(false, Effect.succeed(Option.some(resolved)))).toBe("skipped");
    expect(await run(true, Effect.succeed(Option.some(resolved)))).toBe("resolved");
    expect(await run(true, Effect.succeed(Option.none()))).toBe("anonymous");
    expect(await run(true, Effect.fail(new Unreachable()))).toBe("degraded");
  });
});
