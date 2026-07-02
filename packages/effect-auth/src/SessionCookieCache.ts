/**
 * Signed session-data cookie cache.
 *
 * better-auth's `session.cookieCache` stores a short-lived HMAC-signed copy of
 * the session + user in a cookie so `GET /session` (and other authenticated
 * requests) can be served without hitting the session store on every request.
 *
 * The cookie value is `base64url(payload) . base64url(HMAC-SHA256(base64url
 * payload))`, where the payload is versioned for forward compatibility and
 * carries the session, user, and a cache expiry (`now + maxAge`).
 *
 * Staleness: a session revoked on another device remains usable from a cached
 * cookie until `maxAge` elapses. Keep `maxAge` short (default 5 minutes) and
 * clear the cache cookie on sign-out / revocation (the HTTP layer does this).
 */
import { Redacted } from "effect";
import * as crypto from "node:crypto";
import type * as Types from "./Types.js";

/** Cookie-cache configuration (part of `CookieConfig`). */
export interface SessionCacheConfig {
  readonly enabled: boolean;
  /** Cache lifetime in ms. Default 5 minutes. */
  readonly maxAge?: number;
  /** HMAC secret. Use `Redacted.make(...)` / `Config.redacted`. */
  readonly secret: Redacted.Redacted<string>;
}

/** Resolved cache config used internally by the HTTP layer. */
export interface ResolvedSessionCache {
  readonly maxAge: number;
  readonly secret: string;
}

export const resolveSessionCache = (
  config: SessionCacheConfig | undefined,
): ResolvedSessionCache | undefined =>
  config?.enabled
    ? { maxAge: config.maxAge ?? 5 * 60 * 1000, secret: Redacted.value(config.secret) }
    : undefined;

const PAYLOAD_VERSION = 1;

const b64url = (data: Uint8Array): string => Buffer.from(data).toString("base64url");

const sign = (data: string, secret: string): string =>
  b64url(crypto.createHmac("sha256", secret).update(data).digest());

const timingSafeEqualStr = (a: string, b: string): boolean => {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
};

/** Serialize + sign a `SessionWithUser` into the cache cookie value. */
export const encodeSessionCacheCookie = (
  value: Types.SessionWithUser,
  cache: ResolvedSessionCache,
  now: number,
): string => {
  const s = value.session;
  const u = value.user;
  const payload = {
    v: PAYLOAD_VERSION,
    exp: now + cache.maxAge,
    session: {
      ...s,
      expiresAt: s.expiresAt.getTime(),
      createdAt: s.createdAt.getTime(),
      lastActivityAt: s.lastActivityAt.getTime(),
    },
    user: {
      ...u,
      createdAt: u.createdAt.getTime(),
      updatedAt: u.updatedAt.getTime(),
    },
  };
  const encoded = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  return `${encoded}.${sign(encoded, cache.secret)}`;
};

/**
 * Verify + parse a cache cookie. Returns `null` (falling back to store
 * validation) on a bad signature, a version/expiry mismatch, or an expired
 * underlying session.
 */
export const decodeSessionCacheCookie = (
  cookie: string,
  cache: ResolvedSessionCache,
  now: number,
): Types.SessionWithUser | null => {
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = cookie.slice(0, dot);
  const signature = cookie.slice(dot + 1);
  if (!timingSafeEqualStr(signature, sign(encoded, cache.secret))) return null;

  let payload: {
    v?: unknown;
    exp?: unknown;
    session?: Record<string, unknown>;
    user?: Record<string, unknown>;
  };
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  if (
    payload.v !== PAYLOAD_VERSION ||
    typeof payload.exp !== "number" ||
    now >= payload.exp ||
    payload.session === undefined ||
    payload.user === undefined
  ) {
    return null;
  }

  const s = payload.session;
  const u = payload.user;
  const session = {
    ...s,
    expiresAt: new Date(s["expiresAt"] as number),
    createdAt: new Date(s["createdAt"] as number),
    lastActivityAt: new Date(s["lastActivityAt"] as number),
  } as Types.Session;
  // Honour the session's own expiry even within the cache window.
  if (now > session.expiresAt.getTime()) return null;

  const user = {
    ...u,
    createdAt: new Date(u["createdAt"] as number),
    updatedAt: new Date(u["updatedAt"] as number),
  } as Types.User;

  return { session, user };
};
