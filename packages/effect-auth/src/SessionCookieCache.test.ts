import { describe, it, expect } from "vite-plus/test";
import { Redacted } from "effect";
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
};

const now = Date.now();

const makeSession = (overrides?: Partial<Types.Session>): Types.Session => ({
  id: SESSION_ID,
  userId: "user_1",
  expiresAt: new Date(now + 60 * 60 * 1000),
  createdAt: new Date(now - 60 * 1000),
  lastActivityAt: new Date(now - 30 * 1000),
  attributes: {},
  ...overrides,
});

const makeUser = (overrides?: Partial<Types.User>): Types.User => ({
  id: "user_1",
  email: "alice@example.com",
  emailVerified: true,
  createdAt: new Date(now - 7 * 24 * 60 * 60 * 1000),
  updatedAt: new Date(now - 60 * 1000),
  attributes: {},
  ...overrides,
});

const value: Types.SessionWithUser = { session: makeSession(), user: makeUser() };

describe("resolveSessionCache", () => {
  it("returns undefined when disabled", () => {
    expect(resolveSessionCache({ enabled: false, secret: Redacted.make(SECRET) })).toBeUndefined();
    expect(resolveSessionCache(undefined)).toBeUndefined();
  });

  it("resolves with defaults when enabled", () => {
    const result = resolveSessionCache({ enabled: true, secret: Redacted.make(SECRET) });
    expect(result).not.toBeUndefined();
    expect(result!.maxAge).toBe(5 * 60 * 1000);
  });

  it("uses custom maxAge", () => {
    const result = resolveSessionCache({
      enabled: true,
      secret: Redacted.make(SECRET),
      maxAge: 60_000,
    });
    expect(result!.maxAge).toBe(60_000);
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
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
    const result = decodeSessionCacheCookie(cookie, cache, now, SESSION_ID);
    expect(result).not.toBeNull();
    expect(result!.session.id).toBe(SESSION_ID);
    expect(result!.user.email).toBe("alice@example.com");
  });

  it("preserves Date fields", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
    const result = decodeSessionCacheCookie(cookie, cache, now, SESSION_ID);
    expect(result!.session.expiresAt).toBeInstanceOf(Date);
    expect(result!.session.createdAt).toBeInstanceOf(Date);
    expect(result!.session.lastActivityAt).toBeInstanceOf(Date);
    expect(result!.user.createdAt).toBeInstanceOf(Date);
    expect(result!.user.updatedAt).toBeInstanceOf(Date);
  });

  it("preserves optional user fields", () => {
    const withExtras: Types.SessionWithUser = {
      session: makeSession(),
      user: makeUser({ name: "Alice", image: "https://example.com/alice.png" }),
    };
    const cookie = encodeSessionCacheCookie(withExtras, cache, now, SESSION_ID);
    const result = decodeSessionCacheCookie(cookie, cache, now, SESSION_ID);
    expect(result!.user.name).toBe("Alice");
    expect(result!.user.image).toBe("https://example.com/alice.png");
  });
});

describe("signature verification", () => {
  it("rejects a forged cookie (different secret)", () => {
    const forgeryCache: ResolvedSessionCache = {
      maxAge: cache.maxAge,
      secret: Redacted.make("b".repeat(32)),
    };
    const cookie = encodeSessionCacheCookie(value, forgeryCache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a tampered payload", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
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
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
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
    const cookie = encodeSessionCacheCookie(value, cache, now - cache.maxAge - 1, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("rejects a cache entry whose underlying session has expired", () => {
    const expiredSession = makeSession({ expiresAt: new Date(now - 1000) });
    const cookie = encodeSessionCacheCookie(
      { session: expiredSession, user: makeUser() },
      cache,
      now,
      SESSION_ID,
    );
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).toBeNull();
  });

  it("accepts a cache entry that is about to expire (1 ms left)", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now - cache.maxAge + 1, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).not.toBeNull();
  });
});

describe("session-binding (sid)", () => {
  it("rejects when primarySessionId does not match the encoded sid", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, "sess_other")).toBeNull();
  });

  it("accepts when primarySessionId matches", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
    expect(decodeSessionCacheCookie(cookie, cache, now, SESSION_ID)).not.toBeNull();
  });

  it("rejects after account switch (different sid in cookie vs. primary cookie)", () => {
    const sessionA = "sess_aaa";
    const sessionB = "sess_bbb";
    // User had session A cached; primary cookie is now session B
    const cookie = encodeSessionCacheCookie(value, cache, now, sessionA);
    expect(decodeSessionCacheCookie(cookie, cache, now, sessionB)).toBeNull();
  });

  it("rejects a stale cache after logout (empty primarySessionId)", () => {
    const cookie = encodeSessionCacheCookie(value, cache, now, SESSION_ID);
    // An empty string will never match a real session id
    expect(decodeSessionCacheCookie(cookie, cache, now, "")).toBeNull();
  });
});
