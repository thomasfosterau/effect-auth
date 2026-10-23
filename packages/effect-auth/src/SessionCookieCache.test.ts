import { assert, describe, it, expect } from "vite-plus/test";
import { DateTime, Redacted } from "effect";
import {
  decodeSessionCacheCookie,
  encodeSessionCacheCookie,
  resolveSessionCache,
  type ResolvedSessionCache,
} from "./SessionCookieCache.ts";
import type * as Types from "./Types.ts";

const SECRET = "a".repeat(32);
const SESSION_ID = "sess_abc123";

const cache: ResolvedSessionCache = {
  maxAge: 5 * 60 * 1000,
  secret: Redacted.make(SECRET),
  version: "",
  encryptionKey: undefined,
};

/** Encode, failing the test when the snapshot is refused. */
const mustEncode = (...args: Parameters<typeof encodeSessionCacheCookie>): string => {
  const cookie = encodeSessionCacheCookie(...args);
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
const mustDecode = (
  ...args: Parameters<typeof decodeSessionCacheCookie>
): Types.SessionWithUser => {
  const decoded = decodeSessionCacheCookie(...args);
  assert(decoded !== null, "decodeSessionCacheCookie rejected the cookie");
  return decoded;
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
    expect(() => resolveSessionCache({ enabled: true, secret: Redacted.make("") })).toThrow();
  });

  it("rejects a short secret (< 32 chars)", () => {
    expect(() =>
      resolveSessionCache({ enabled: true, secret: Redacted.make("tooshort") }),
    ).toThrow();
  });

  it("accepts a secret of exactly 32 chars", () => {
    expect(() =>
      resolveSessionCache({ enabled: true, secret: Redacted.make("a".repeat(32)) }),
    ).not.toThrow();
  });
});

describe("encode/decode round-trip", () => {
  it("decodes a freshly encoded cookie", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    const result = mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.session.id).toBe(SESSION_ID);
    expect(result.user.id).toBe("user_1");
    expect(result.user.attributes["plan"]).toBe("pro");
  });

  it("preserves Date fields", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    const result = mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.session.expiresAt).toBeInstanceOf(Date);
    expect(result.session.createdAt).toBeInstanceOf(Date);
    expect(result.session.lastActivityAt).toBeInstanceOf(Date);
    expect(result.user.createdAt).toBeInstanceOf(Date);
    expect(result.user.updatedAt).toBeInstanceOf(Date);
  });

  it("preserves optional user fields", () => {
    const withExtras: Types.SessionWithUser = {
      session: makeSession(),
      user: makeUser({ name: "Alice", image: "https://example.com/alice.png" }),
    };
    const cookie = mustEncode(withExtras, cache, now, SESSION_ID);
    const result = mustDecode(cookie, cache, now, SESSION_ID);
    expect(result.user.name).toBe("Alice");
    expect(result.user.image).toBe("https://example.com/alice.png");
  });
});

describe("signature verification", () => {
  it("rejects a forged cookie (different secret)", () => {
    const forgeryCache: ResolvedSessionCache = {
      ...cache,
      secret: Redacted.make("b".repeat(32)),
    };
    const cookie = mustEncode(value, forgeryCache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a tampered payload", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    const dot = cookie.lastIndexOf(".");
    const encoded = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    // Flip a byte in the payload
    const raw = Buffer.from(encoded, "base64url");
    raw[10] ^= 0xff;
    const tampered = `${raw.toString("base64url")}.${sig}`;
    expect(decodeSessionCacheCookie(tampered, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a cookie with a detached signature", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    const dot = cookie.lastIndexOf(".");
    const encoded = cookie.slice(0, dot);
    const wrongSig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(decodeSessionCacheCookie(`${encoded}.${wrongSig}`, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a cookie with no dot separator", () => {
    expect(decodeSessionCacheCookie("nodot", cache, now, SESSION_ID)).toBeNull();
  });
});

describe("expiry", () => {
  it("rejects an expired cache entry (exp in past)", () => {
    const cookie = mustEncode(value, cache, now - cache.maxAge - 1, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a cache entry whose underlying session has expired", () => {
    const expiredSession = makeSession({
      expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now - 1000)),
    });
    const cookie = mustEncode(
      { session: expiredSession, user: makeUser() },
      cache,
      now,
      SESSION_ID,
    );
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("accepts a cache entry that is about to expire (1 ms left)", () => {
    const cookie = mustEncode(value, cache, now - cache.maxAge + 1, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).not.toBeNull();
  });
});

describe("session-binding (sid)", () => {
  it("rejects when primarySessionId does not match the encoded sid", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, "sess_other")).toBeNull();
  });

  it("accepts when primarySessionId matches", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).not.toBeNull();
  });

  it("rejects after account switch (different sid in cookie vs. primary cookie)", () => {
    const sessionA = "sess_aaa";
    const sessionB = "sess_bbb";
    // User had session A cached; primary cookie is now session B
    const cookie = mustEncode(value, cache, now, sessionA);
    expect(decodeSessionCacheCookie(cookie, cache, now, sessionB)).toBeNull();
  });

  it("rejects a stale cache after logout (empty primarySessionId)", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    // An empty string will never match a real session id
    expect(decodeSessionCacheCookie(cookie, cache, now, "")).toBeNull();
  });
});

describe("cache epoch (#194)", () => {
  const withVersion = (version: string): ResolvedSessionCache =>
    mustResolve({ enabled: true, secret: Redacted.make(SECRET), version });

  it("rejects every cookie issued under another epoch", () => {
    const cookie = mustEncode(value, withVersion("2026-10"), now, SESSION_ID);
    expect(
      decodeSessionCacheCookie(cookie, withVersion("2026-10"), now, SESSION_ID),
    ).not.toBeNull();
    expect(decodeSessionCacheCookie(cookie, withVersion("2026-11"), now, SESSION_ID)).toBeNull();
  });

  it("rejects a cookie with no epoch once one is set, and accepts it while none is", () => {
    const cookie = mustEncode(value, cache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).not.toBeNull();
    expect(decodeSessionCacheCookie(cookie, withVersion("v2"), now, SESSION_ID)).toBeNull();
  });
});

describe("server-only attributes (#194)", () => {
  const admin: Types.SessionWithUser = {
    session: makeSession(),
    user: makeUser({ attributes: { plan: "pro", role: "admin" } }),
  };

  it("never snapshots a user holding a server-only attribute (default role)", () => {
    expect(encodeSessionCacheCookie(admin, cache, now, SESSION_ID)).toBeUndefined();
  });

  it("follows the configured list", () => {
    const gate = new Set(["tier"]);
    expect(encodeSessionCacheCookie(admin, cache, now, SESSION_ID, gate)).toBeDefined();
    const tiered: Types.SessionWithUser = {
      session: makeSession(),
      user: makeUser({ attributes: { tier: "gold" } }),
    };
    expect(encodeSessionCacheCookie(tiered, cache, now, SESSION_ID, gate)).toBeUndefined();
  });

  it("never serves a cookie that carries one, so the request falls through to the store", () => {
    // Issued while `role` was not server-only, then read with the default list.
    const cookie = mustEncode(admin, cache, now, SESSION_ID, new Set());
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID, new Set())).not.toBeNull();
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });
});

describe("encryption (#194)", () => {
  const encrypted = mustResolve({
    enabled: true,
    secret: Redacted.make(SECRET),
    encrypt: true,
  });

  it("round-trips, and the browser cannot read the payload", () => {
    const cookie = mustEncode(value, encrypted, now, SESSION_ID);
    const payload = cookie.slice(0, cookie.lastIndexOf("."));
    expect(Buffer.from(payload.slice(1), "base64url").toString("utf8")).not.toContain("user_1");
    expect(cookie).not.toContain(Buffer.from('"plan"').toString("base64url"));
    const result = decodeSessionCacheCookie(cookie, encrypted, now, SESSION_ID);
    expect(result?.user.attributes["plan"]).toBe("pro");
  });

  it("rejects a signed-only cookie when encryption is on, and an encrypted one when it is off", () => {
    expect(
      decodeSessionCacheCookie(
        mustEncode(value, cache, now, SESSION_ID),
        encrypted,
        now,
        SESSION_ID,
      ),
    ).toBeNull();
    expect(
      decodeSessionCacheCookie(
        mustEncode(value, encrypted, now, SESSION_ID),
        cache,
        now,
        SESSION_ID,
      ),
    ).toBeNull();
  });
});
