import * as crypto from "node:crypto";
import { DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { TestClock } from "effect/testing";
import { afterEach, assert, beforeEach, describe, expect, it } from "vite-plus/test";
import { CurrentCredential, CurrentPrincipal } from "./Authorizer.ts";
import * as CloudflareAccess from "./CloudflareAccess.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { CurrentUser } from "./SessionContext.ts";
import * as SessionResolution from "./SessionResolution.ts";
import { memoryUserStore, memoryUserTable } from "./testing/MemoryStores.ts";
import type * as Types from "./Types.ts";
import { UserStore } from "./UserStore.ts";

const TEAM = "example-team.cloudflareaccess.com";
const ISSUER = `https://${TEAM}`;
const AUD = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2";
const CERTS_URL = `${ISSUER}/cdn-cgi/access/certs`;

// --- A fake Access team: RSA keys, a signer and the published key set --------

const rsaKey = (kid: string) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256" } };
};

const KEY_A = rsaKey("key-a");
const KEY_B = rsaKey("key-b");

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));
const b64 = (value: Schema.Json): string =>
  Buffer.from(encodeJson(value), "utf8").toString("base64url");

const sign = (
  payload: Types.JsonObject,
  options: { readonly key?: typeof KEY_A; readonly header?: Types.JsonObject } = {},
): string => {
  const key = options.key ?? KEY_A;
  const header = options.header ?? { alg: "RS256", kid: key.kid, typ: "JWT" };
  const input = `${b64(header)}.${b64(payload)}`;
  const signature = crypto.sign("sha256", Buffer.from(input), key.privateKey);
  return `${input}.${signature.toString("base64url")}`;
};

const nowMs = () => DateTime.toEpochMillis(DateTime.nowUnsafe());
const nowSec = () => Math.floor(nowMs() / 1000);
const nowDate = () => DateTime.toDateUtc(DateTime.nowUnsafe());

const userClaims = (overrides: Types.JsonObject = {}): Types.JsonObject => ({
  aud: [AUD],
  email: "Ada@Example.com",
  exp: nowSec() + 300,
  iat: nowSec(),
  nbf: nowSec(),
  iss: ISSUER,
  type: "app",
  identity_nonce: "nonce-1",
  sub: "7335d417-61da-459d-899c-0a01c76a2f94",
  country: "AU",
  ...overrides,
});

const serviceTokenClaims = (overrides: Types.JsonObject = {}): Types.JsonObject => ({
  aud: [AUD],
  common_name: "client-id.access",
  exp: nowSec() + 300,
  iat: nowSec(),
  iss: ISSUER,
  type: "app",
  sub: "",
  ...overrides,
});

// --- A swappable fetch that serves the key set and counts requests ----------

let publishedKeys: ReadonlyArray<object> = [KEY_A.jwk];
let fetches: Array<string> = [];
let fetchFails = false;
const originalFetch = globalThis.fetch;

beforeEach(() => {
  publishedKeys = [KEY_A.jwk];
  fetches = [];
  fetchFails = false;
  globalThis.fetch = (input) => {
    fetches.push(P.isString(input) ? input : input instanceof URL ? input.href : input.url);
    if (fetchFails) return Promise.reject(new TypeError("network down"));
    return Promise.resolve(Response.json({ keys: publishedKeys }));
  };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

const config: CloudflareAccess.CloudflareAccessConfig = { teamDomain: TEAM, audience: AUD };

const run = <A, E>(
  effect: Effect.Effect<A, E, CloudflareAccess.CloudflareAccessVerifier>,
  overrides: Partial<CloudflareAccess.CloudflareAccessConfig> = {},
) =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(CloudflareAccess.CloudflareAccessVerifier.layer({ ...config, ...overrides })),
    ),
  );

const verify = (token: string) =>
  Effect.gen(function* () {
    const access = yield* CloudflareAccess.CloudflareAccessVerifier;
    return yield* access.verify(token);
  });

const refusal = (token: string, overrides: Partial<CloudflareAccess.CloudflareAccessConfig> = {}) =>
  run(Effect.flip(verify(token)).pipe(Effect.map((error) => error.reason)), overrides);

describe("CloudflareAccessVerifier.verify", () => {
  it("accepts a user token and returns its identity", async () => {
    const identity = await run(verify(sign(userClaims())));
    expect(identity.kind).toBe("user");
    expect(identity.email).toBe("Ada@Example.com");
    expect(identity.subject).toBe("7335d417-61da-459d-899c-0a01c76a2f94");
    expect(identity.country).toBe("AU");
    expect(identity.identityNonce).toBe("nonce-1");
    expect(identity.expiresAt.getTime()).toBeGreaterThan(nowMs());
    expect(fetches).toEqual([CERTS_URL]);
  });

  it("accepts a service token as a service-token identity", async () => {
    const identity = await run(verify(sign(serviceTokenClaims())));
    expect(identity.kind).toBe("service-token");
    expect(identity.subject).toBe("client-id.access");
    expect(identity.commonName).toBe("client-id.access");
    expect(identity.email).toBeUndefined();
  });

  it("accepts the team domain with a scheme and trailing slash, and several audiences", async () => {
    const identity = await run(verify(sign(userClaims({ aud: AUD }))), {
      teamDomain: `https://${TEAM}/`,
      audience: ["another-app", AUD],
    });
    expect(identity.kind).toBe("user");
  });

  it("refuses a token signed by a key the team did not publish", async () => {
    const forged = sign(userClaims(), { key: { ...KEY_B, kid: KEY_A.kid } });
    expect(await refusal(forged)).toBe("signature");
  });

  it("refuses a payload changed after signing", async () => {
    const [header, , signature] = sign(userClaims()).split(".");
    const tampered = `${header}.${b64(userClaims({ email: "eve@example.com" }))}.${signature}`;
    expect(await refusal(tampered)).toBe("signature");
  });

  it.each([
    ["none", { alg: "none", kid: KEY_A.kid }],
    ["HS256", { alg: "HS256", kid: KEY_A.kid }],
    ["ES256", { alg: "ES256", kid: KEY_A.kid }],
  ])("refuses the %s algorithm without fetching keys", async (_name, header) => {
    expect(await refusal(sign(userClaims(), { header }))).toBe("algorithm");
    expect(fetches).toEqual([]);
  });

  it("refuses a token with no kid", async () => {
    expect(await refusal(sign(userClaims(), { header: { alg: "RS256" } }))).toBe("key");
  });

  it("refuses another team's issuer", async () => {
    expect(await refusal(sign(userClaims({ iss: "https://evil.cloudflareaccess.com" })))).toBe(
      "issuer",
    );
  });

  it("refuses another application's audience", async () => {
    expect(await refusal(sign(userClaims({ aud: ["other-app"] })))).toBe("audience");
  });

  it("refuses an expired token, past the clock tolerance", async () => {
    expect(await refusal(sign(userClaims({ exp: nowSec() - 120 })))).toBe("expired");
  });

  it("accepts a token expired within the clock tolerance", async () => {
    const identity = await run(verify(sign(userClaims({ exp: nowSec() - 10 }))));
    expect(identity.kind).toBe("user");
  });

  it("refuses a token without exp", async () => {
    const { exp: _exp, ...claims } = userClaims();
    expect(await refusal(sign(claims))).toBe("claims");
  });

  it("refuses a token that is not valid yet", async () => {
    expect(await refusal(sign(userClaims({ nbf: nowSec() + 600 })))).toBe("not-yet-valid");
  });

  it("refuses a token that names neither a user nor a service token", async () => {
    expect(await refusal(sign(userClaims({ email: "" })))).toBe("claims");
  });

  it.each(["", "abc", "a.b", "a.b.c.d", "!!!.###.$$$"])(
    "refuses the malformed token %j",
    async (token) => {
      expect(await refusal(token)).toBe("malformed");
    },
  );
});

describe("CloudflareAccessVerifier key cache", () => {
  it("fetches the key set once for many tokens", async () => {
    await run(
      Effect.forEach(Arr.range(1, 5), () => verify(sign(userClaims())), {
        concurrency: 1,
        discard: true,
      }),
    );
    expect(fetches).toHaveLength(1);
  });

  it("shares one fetch between concurrent first requests", async () => {
    await run(
      Effect.all(
        Array.from({ length: 10 }, () => verify(sign(userClaims()))),
        { concurrency: "unbounded" },
      ),
    );
    expect(fetches).toHaveLength(1);
  });

  it("refetches when a token names a rotated-in key", async () => {
    await run(
      Effect.gen(function* () {
        yield* TestClock.setTime(nowMs());
        yield* verify(sign(userClaims()));
        publishedKeys = [KEY_A.jwk, KEY_B.jwk];
        yield* TestClock.adjust("31 seconds");
        const identity = yield* verify(sign(userClaims(), { key: KEY_B }));
        expect(identity.kind).toBe("user");
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(fetches).toHaveLength(2);
  });

  it("does not refetch for unknown kids more than once per interval", async () => {
    const reasons = await run(
      Effect.gen(function* () {
        yield* TestClock.setTime(nowMs());
        yield* verify(sign(userClaims()));
        const forged = Array.from({ length: 20 }, (_, i) =>
          sign(userClaims(), { header: { alg: "RS256", kid: `forged-${i}` } }),
        );
        return yield* Effect.forEach(
          forged,
          (token) => Effect.flip(verify(token)).pipe(Effect.map((e) => e.reason)),
          { concurrency: 1 },
        );
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(reasons).toEqual(Arr.replicate("key", 20));
    // The first token's fetch; the forged kids arrive inside the interval.
    expect(fetches).toHaveLength(1);
  });

  it("refetches once the key set's TTL has passed", async () => {
    await run(
      Effect.gen(function* () {
        yield* TestClock.setTime(nowMs());
        yield* verify(sign(userClaims({ exp: nowSec() + 7200 })));
        yield* TestClock.adjust("61 minutes");
        yield* verify(sign(userClaims({ exp: nowSec() + 7200 })));
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(fetches).toHaveLength(2);
  });

  it("keeps serving a cached key when a refresh fails", async () => {
    await run(
      Effect.gen(function* () {
        yield* TestClock.setTime(nowMs());
        yield* verify(sign(userClaims({ exp: nowSec() + 7200 })));
        yield* TestClock.adjust("61 minutes");
        fetchFails = true;
        const identity = yield* verify(sign(userClaims({ exp: nowSec() + 7200 })));
        expect(identity.kind).toBe("user");
      }).pipe(Effect.provide(TestClock.layer())),
    );
    expect(fetches).toHaveLength(2);
  });

  it("fails with jwks when the first fetch fails", async () => {
    fetchFails = true;
    expect(await refusal(sign(userClaims()))).toBe("jwks");
  });

  it("fails with jwks on a key set that is not a JWKS", async () => {
    globalThis.fetch = () => Promise.resolve(Response.json({ keys: "nope" }));
    expect(await refusal(sign(userClaims()))).toBe("jwks");
  });

  it("fails with jwks on a non-2xx key set response", async () => {
    globalThis.fetch = () => Promise.resolve(new Response("down", { status: 503 }));
    expect(await refusal(sign(userClaims()))).toBe("jwks");
  });
});

const verifyRequest = (headers: Record<string, string>) =>
  Effect.gen(function* () {
    const access = yield* CloudflareAccess.CloudflareAccessVerifier;
    return yield* access.verifyRequest(SessionResolution.fromHeaders(new Headers(headers)));
  });

describe("CloudflareAccessVerifier.verifyRequest", () => {
  it("is none, without a fetch, when the request carries no token", async () => {
    const identity = await run(verifyRequest({}));
    expect(Option.isNone(identity)).toBe(true);
    expect(fetches).toEqual([]);
  });

  it("reads the Cf-Access-Jwt-Assertion header", async () => {
    const identity = await run(verifyRequest({ "Cf-Access-Jwt-Assertion": sign(userClaims()) }));
    assert(Option.isSome(identity));
    expect(identity.value.email).toBe("Ada@Example.com");
  });

  it("ignores the cookie unless the cookie source is enabled", async () => {
    const cookie = `CF_Authorization=${sign(userClaims())}`;
    expect(Option.isNone(await run(verifyRequest({ cookie })))).toBe(true);
    const identity = await run(verifyRequest({ cookie }), { sources: ["header", "cookie"] });
    expect(Option.isSome(identity)).toBe(true);
  });

  it("prefers the header and refuses an invalid one rather than fall back", async () => {
    const reason = await run(
      Effect.flip(
        verifyRequest({
          "Cf-Access-Jwt-Assertion": "garbage",
          cookie: `CF_Authorization=${sign(userClaims())}`,
        }),
      ).pipe(Effect.map((e) => e.reason)),
      { sources: ["header", "cookie"] },
    );
    expect(reason).toBe("malformed");
  });
});

describe("CloudflareAccessVerifier.layer config", () => {
  it.each([
    [{ teamDomain: "", audience: AUD }],
    [{ teamDomain: "https://team.cloudflareaccess.com/path", audience: AUD }],
    [{ teamDomain: "not a domain", audience: AUD }],
    [{ teamDomain: TEAM, audience: [] }],
    [{ teamDomain: TEAM, audience: " " }],
    [{ teamDomain: TEAM, audience: AUD, sources: [] }],
  ])("fails to build with %j", async (bad) => {
    const exit = await Effect.runPromise(
      Effect.flip(CloudflareAccess.make(bad)).pipe(Effect.map((e) => e.reason)),
    );
    expect(exit).toBe("config");
  });
});

// --- Mapping an identity to a user ------------------------------------------

const setup = (identifier: { readonly verified: boolean }, attributes: Types.JsonObject = {}) => {
  const table = memoryUserTable();
  const now = nowDate();
  const user: Types.User = { id: "u-1", createdAt: now, updatedAt: now, attributes };
  MutableHashMap.set(table.users, user.id, user);
  const records = MutableHashMap.empty<string, Identifier>();
  const record = makeIdentifier({
    userId: user.id,
    type: "email",
    value: "ada@example.com",
    verified: identifier.verified,
    now,
  });
  MutableHashMap.set(records, record.id, record);
  return Layer.mergeAll(
    Layer.succeed(UserStore)(memoryUserStore(table)),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(records)),
  );
};

const identityFor = (claims: Types.JsonObject) => run(verify(sign(claims)));

describe("findUser and userContextLayer", () => {
  it("finds the owner of a verified email, case-insensitively", async () => {
    const identity = await identityFor(userClaims());
    const user = await Effect.runPromise(
      CloudflareAccess.findUser(identity).pipe(Effect.provide(setup({ verified: true }))),
    );
    assert(Option.isSome(user));
    expect(user.value.id).toBe("u-1");
  });

  it("finds nobody for an address held unverified", async () => {
    const identity = await identityFor(userClaims());
    const user = await Effect.runPromise(
      CloudflareAccess.findUser(identity).pipe(Effect.provide(setup({ verified: false }))),
    );
    expect(Option.isNone(user)).toBe(true);
  });

  it("finds nobody for a banned user", async () => {
    const identity = await identityFor(userClaims());
    const user = await Effect.runPromise(
      CloudflareAccess.findUser(identity).pipe(
        Effect.provide(setup({ verified: true }, { banned: true })),
      ),
    );
    expect(Option.isNone(user)).toBe(true);
  });

  it("finds nobody for a service token", async () => {
    const identity = await identityFor(serviceTokenClaims());
    const user = await Effect.runPromise(
      CloudflareAccess.findUser(identity).pipe(Effect.provide(setup({ verified: true }))),
    );
    expect(Option.isNone(user)).toBe(true);
  });

  it("provides the user as an interactive principal", async () => {
    const identity = await identityFor(userClaims());
    const now = nowDate();
    const user: Types.User = { id: "u-1", createdAt: now, updatedAt: now, attributes: {} };
    const context = await Effect.runPromise(
      Effect.gen(function* () {
        return {
          user: yield* CurrentUser,
          principal: yield* CurrentPrincipal,
          credential: yield* CurrentCredential,
        };
      }).pipe(Effect.provide(CloudflareAccess.userContextLayer(identity, user))),
    );
    expect(context.user.id).toBe("u-1");
    expect(context.principal).toEqual({ type: "User", id: "u-1" });
    expect(context.credential).toBe("interactive");
  });

  it("classes a service token as a machine credential", async () => {
    const identity = await identityFor(serviceTokenClaims());
    expect(CloudflareAccess.credentialClassOf(identity)).toBe("machine");
  });
});
