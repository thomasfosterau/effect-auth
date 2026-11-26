import { assert, describe, it, expect } from "vite-plus/test";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as HashSet from "effect/HashSet";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Option from "effect/Option";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  decodeSessionCacheCookie,
  encodeSessionCacheCookie,
  resolveSessionCache,
  sessionCacheGateAttributes,
  type ResolvedSessionCache,
} from "./SessionCookieCache.ts";
import { UserService, UserServiceStore } from "./User.ts";
import { memoryUserServiceStore } from "./testing/MemoryStores.ts";
import type * as Types from "./Types.ts";

const SECRET = "a".repeat(32);
const SESSION_ID = "sess_abc123";

const cache: ResolvedSessionCache = {
  maxAge: 5 * 60 * 1000,
  secret: Redacted.make(SECRET),
  version: "",
  encrypt: false,
};

/** Run an encode or decode over the platform's WebCrypto. */
const encode = (
  ...args: Parameters<typeof encodeSessionCacheCookie>
): Promise<string | undefined> =>
  Effect.runPromise(PlatformCrypto.provide(encodeSessionCacheCookie(...args)));
const decode = (
  ...args: Parameters<typeof decodeSessionCacheCookie>
): Promise<Option.Option<Types.SessionWithUser>> =>
  Effect.runPromise(PlatformCrypto.provide(decodeSessionCacheCookie(...args)));

/** Encode, failing the test when the snapshot is refused. */
const mustEncode = async (
  ...args: Parameters<typeof encodeSessionCacheCookie>
): Promise<string> => {
  const cookie = await encode(...args);
  assert(cookie !== undefined, "encodeSessionCacheCookie refused the snapshot");
  return cookie;
};

/** Resolve, failing the test when the config leaves the cache off. */
const mustResolve = (...args: Parameters<typeof resolveSessionCache>): ResolvedSessionCache => {
  const resolved = resolveSessionCache(...args);
  assert(resolved !== undefined, "resolveSessionCache left the cache off");
  return resolved;
};

/** Decode, failing the test when the cookie is rejected. */
const mustDecode = async (
  ...args: Parameters<typeof decodeSessionCacheCookie>
): Promise<Types.SessionWithUser> => {
  const decoded = await decode(...args);
  assert(Option.isSome(decoded), "decodeSessionCacheCookie rejected the cookie");
  return decoded.value;
};

const now = DateTime.toEpochMillis(DateTime.nowUnsafe());

const makeSession = (overrides?: Partial<Types.Session>): Types.Session => ({
  id: SESSION_ID,
  userId: "user_1",
  expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now + 60 * 60 * 1000)),
  createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 60 * 1000)),
  lastActivityAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 30 * 1000)),
  attributes: {},
  ...overrides,
});

const makeUser = (overrides?: Partial<Types.User>): Types.User => ({
  id: "user_1",
  createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 7 * 24 * 60 * 60 * 1000)),
  updatedAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 60 * 1000)),
  attributes: { plan: "pro" },
  ...overrides,
});

const value: Types.SessionWithUser = { session: makeSession(), user: makeUser() };

describe("resolveSessionCache", () => {
  it("returns undefined when disabled", () => {
    expect(resolveSessionCache({ enabled: false, secret: Redacted.make(SECRET) })).toBeUndefined();
    expect(resolveSessionCache(undefined)).toBeUndefined();
  });

  it("resolves with defaults when enabled", () => {
    const result = mustResolve({ enabled: true, secret: Redacted.make(SECRET) });
    expect(result.maxAge).toBe(5 * 60 * 1000);
  });

  it("uses custom maxAge", () => {
    const result = mustResolve({
      enabled: true,
      secret: Redacted.make(SECRET),
      maxAge: 60_000,
    });
    expect(result.maxAge).toBe(60_000);
  });

  it("rejects an empty secret", () => {
    expect(() => resolveSessionCache({ enabled: true, secret: Redacted.make("") })).toThrow(
      /HMAC secret must be at least/,
    );
  });

  it("rejects a short secret (< 32 chars)", () => {
    expect(() => resolveSessionCache({ enabled: true, secret: Redacted.make("tooshort") })).toThrow(
      /HMAC secret must be at least/,
    );
  });

  it("accepts a secret of exactly 32 chars", () => {
    expect(() =>
      resolveSessionCache({ enabled: true, secret: Redacted.make("a".repeat(32)) }),
    ).not.toThrow();
  });
});

describe("encode/decode round-trip", () => {
  it("decodes a freshly encoded cookie", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    const result = await mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.session.id).toBe(SESSION_ID);
    expect(result.user.id).toBe("user_1");
    expect(result.user.attributes["plan"]).toBe("pro");
  });

  it("preserves Date fields", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    const result = await mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.session.expiresAt).toBeInstanceOf(Date);
    expect(result.session.createdAt).toBeInstanceOf(Date);
    expect(result.session.lastActivityAt).toBeInstanceOf(Date);
    expect(result.user.createdAt).toBeInstanceOf(Date);
    expect(result.user.updatedAt).toBeInstanceOf(Date);
  });

  it("preserves optional user fields", async () => {
    const withExtras: Types.SessionWithUser = {
      session: makeSession(),
      user: makeUser({ name: "Alice", image: "https://example.com/alice.png" }),
    };
    const cookie = await mustEncode(withExtras, cache, now, SESSION_ID);
    const result = await mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.user.name).toBe("Alice");
    expect(result.user.image).toBe("https://example.com/alice.png");
  });
});

describe("signature verification", () => {
  it("rejects a forged cookie (different secret)", async () => {
    const forgeryCache: ResolvedSessionCache = {
      ...cache,
      secret: Redacted.make("b".repeat(32)),
    };
    const cookie = await mustEncode(value, forgeryCache, now, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(true);
  });

  it("rejects a tampered payload", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    const dot = cookie.lastIndexOf(".");
    const encoded = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    // Flip a byte in the payload
    const raw = Buffer.from(encoded, "base64url");
    raw[10] ^= 0xff;
    const tampered = `${raw.toString("base64url")}.${sig}`;
    expect(Option.isNone(await decode(tampered, cache, now, SESSION_ID))).toBe(true);
  });

  it("rejects a cookie with a detached signature", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    const dot = cookie.lastIndexOf(".");
    const encoded = cookie.slice(0, dot);
    const wrongSig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(Option.isNone(await decode(`${encoded}.${wrongSig}`, cache, now, SESSION_ID))).toBe(
      true,
    );
  });

  it("rejects a cookie with no dot separator", async () => {
    expect(Option.isNone(await decode("nodot", cache, now, SESSION_ID))).toBe(true);
  });
});

describe("expiry", () => {
  it("rejects an expired cache entry (exp in past)", async () => {
    const cookie = await mustEncode(value, cache, now - cache.maxAge - 1, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(true);
  });

  it("rejects a cache entry whose underlying session has expired", async () => {
    const expiredSession = makeSession({
      expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 1000)),
    });
    const cookie = await mustEncode(
      { session: expiredSession, user: makeUser() },
      cache,
      now,
      SESSION_ID,
    );
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(true);
  });

  it("accepts a cache entry that is about to expire (1 ms left)", async () => {
    const cookie = await mustEncode(value, cache, now - cache.maxAge + 1, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(false);
  });
});

describe("session-binding (sid)", () => {
  it("rejects when primarySessionId does not match the encoded sid", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, "sess_other"))).toBe(true);
  });

  it("accepts when primarySessionId matches", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(false);
  });

  it("rejects after account switch (different sid in cookie vs. primary cookie)", async () => {
    const sessionA = "sess_aaa";
    const sessionB = "sess_bbb";
    // User had session A cached; primary cookie is now session B
    const cookie = await mustEncode(value, cache, now, sessionA);
    expect(Option.isNone(await decode(cookie, cache, now, sessionB))).toBe(true);
  });

  it("rejects a stale cache after logout (empty primarySessionId)", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    // An empty string will never match a real session id
    expect(Option.isNone(await decode(cookie, cache, now, ""))).toBe(true);
  });
});

const withVersion = (version: string): ResolvedSessionCache =>
  mustResolve({ enabled: true, secret: Redacted.make(SECRET), version });

describe("cache epoch", () => {
  it("rejects every cookie issued under another epoch", async () => {
    const cookie = await mustEncode(value, withVersion("2026-10"), now, SESSION_ID);
    expect(Option.isNone(await decode(cookie, withVersion("2026-10"), now, SESSION_ID))).toBe(
      false,
    );
    expect(Option.isNone(await decode(cookie, withVersion("2026-11"), now, SESSION_ID))).toBe(true);
  });

  it("rejects a cookie with no epoch once one is set, and accepts it while none is", async () => {
    const cookie = await mustEncode(value, cache, now, SESSION_ID);
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(false);
    expect(Option.isNone(await decode(cookie, withVersion("v2"), now, SESSION_ID))).toBe(true);
  });
});

describe("server-only attributes", () => {
  const admin: Types.SessionWithUser = {
    session: makeSession(),
    user: makeUser({ attributes: { plan: "pro", role: "admin" } }),
  };

  it("never snapshots a user holding a server-only attribute (default role)", async () => {
    expect(await encode(admin, cache, now, SESSION_ID)).toBeUndefined();
  });

  it("follows the configured list", async () => {
    const gate = HashSet.make("tier");
    expect(await encode(admin, cache, now, SESSION_ID, gate)).toBeDefined();
    const tiered: Types.SessionWithUser = {
      session: makeSession(),
      user: makeUser({ attributes: { tier: "gold" } }),
    };
    expect(await encode(tiered, cache, now, SESSION_ID, gate)).toBeUndefined();
  });

  it("never serves a cookie that carries one, so the request falls through to the store", async () => {
    // Issued while `role` was not server-only, then read with the default list.
    const cookie = await mustEncode(admin, cache, now, SESSION_ID, HashSet.empty());
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID, HashSet.empty()))).toBe(
      false,
    );
    expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(true);
  });
});

const holding = (attributes: Types.Attributes): Types.SessionWithUser => ({
  session: makeSession(),
  user: makeUser({ attributes }),
});

describe("standing attributes", () => {
  it.each([{ banned: true }, { banned: false }, { banExpires: 0 }, { scimDeactivated: true }])(
    "never snapshots or serves a user holding %o",
    async (attributes) => {
      expect(await encode(holding(attributes), cache, now, SESSION_ID)).toBeUndefined();
      const cookie = await mustEncode(holding(attributes), cache, now, SESSION_ID, HashSet.empty());
      expect(Option.isNone(await decode(cookie, cache, now, SESSION_ID))).toBe(true);
    },
  );

  it("gates them even when the app configures no server-only attributes", () => {
    const gate = Effect.runSync(
      sessionCacheGateAttributes.pipe(
        Effect.provide(
          UserService.layer({ serverOnlyAttributes: [] }).pipe(
            Layer.provide(Layer.succeed(UserServiceStore)(memoryUserServiceStore())),
          ),
        ),
      ),
    );
    expect(HashSet.has(gate, "banned")).toBe(true);
    expect(HashSet.has(gate, "banExpires")).toBe(true);
    expect(HashSet.has(gate, "scimDeactivated")).toBe(true);
    expect(HashSet.has(gate, "role")).toBe(false);
  });
});

describe("encryption", () => {
  const encrypted = mustResolve({
    enabled: true,
    secret: Redacted.make(SECRET),
    encrypt: true,
  });

  it("round-trips, and the browser cannot read the payload", async () => {
    const cookie = await mustEncode(value, encrypted, now, SESSION_ID);
    const payload = cookie.slice(0, cookie.lastIndexOf("."));
    expect(Buffer.from(payload.slice(1), "base64url").toString("utf8")).not.toContain("user_1");
    expect(cookie).not.toContain(Buffer.from('"plan"').toString("base64url"));
    const result = await decode(cookie, encrypted, now, SESSION_ID);
    expect(Option.getOrUndefined(result)?.user.attributes["plan"]).toBe("pro");
  });

  it("rejects a signed-only cookie when encryption is on, and an encrypted one when it is off", async () => {
    expect(
      Option.isNone(
        await decode(await mustEncode(value, cache, now, SESSION_ID), encrypted, now, SESSION_ID),
      ),
    ).toBe(true);
    expect(
      Option.isNone(
        await decode(await mustEncode(value, encrypted, now, SESSION_ID), cache, now, SESSION_ID),
      ),
    ).toBe(true);
  });
});
