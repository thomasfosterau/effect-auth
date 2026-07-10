/**
 * Signed session-data cookie cache.
 *
 * better-auth's `session.cookieCache` stores a short-lived HMAC-signed copy of
 * the session + user in a cookie so `GET /session` (and other authenticated
 * requests) can be served without hitting the session store on every request.
 *
 * The cookie value is `base64url(payload) . base64url(HMAC-SHA256(base64url
 * payload))`, where the payload is versioned for forward compatibility and
 * carries the session, user, a cache expiry (`now + maxAge`), and the primary
 * session id (`sid`) — binding the cache entry to a specific primary session
 * cookie so identity cannot bleed across account switches.
 *
 * Staleness: a session revoked on another device remains usable from a cached
 * cookie until `maxAge` elapses. Keep `maxAge` short (default 5 minutes) and
 * clear the cache cookie on sign-out / revocation (the HTTP layer does this).
 *
 * Security note: the cookie is signed but NOT encrypted — session and user
 * data (including any PII in `attributes`) is visible to the browser.
 */
import { Option, Redacted, Schema } from "effect";
import * as Cipher from "./Cipher.ts";
import { timingSafeEqualBytes } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

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
  /** Kept redacted; unwrapped only inside `sign`. */
  readonly secret: Redacted.Redacted<string>;
}

const MIN_SECRET_LENGTH = 32;

export const resolveSessionCache = (
  config: SessionCacheConfig | undefined,
): ResolvedSessionCache | undefined => {
  if (!config?.enabled) return undefined;
  if (Redacted.value(config.secret).length < MIN_SECRET_LENGTH) {
    throw new Error(
      `SessionCookieCache: HMAC secret must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  return { maxAge: config.maxAge ?? 5 * 60 * 1000, secret: config.secret };
};

const PAYLOAD_VERSION = 1;

const b64url = (data: Uint8Array): string => Buffer.from(data).toString("base64url");

const sign = (data: string, secret: Redacted.Redacted<string>): string =>
  b64url(Cipher.hmac("sha256", Redacted.value(secret), data));

const timingSafeEqualStr = (a: string, b: string): boolean =>
  timingSafeEqualBytes(Buffer.from(a), Buffer.from(b));

// Schemas for the JSON-serialized payload form (dates stored as ms timestamps).
const SerializedSession = Schema.Struct({
  id: Schema.String,
  userId: Schema.String,
  expiresAt: Schema.Number,
  createdAt: Schema.Number,
  lastActivityAt: Schema.Number,
  attributes: Schema.Record(Schema.String, Schema.Unknown),
});

const SerializedUser = Schema.Struct({
  id: Schema.String,
  email: Schema.String,
  emailVerified: Schema.Boolean,
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  attributes: Schema.Record(Schema.String, Schema.Unknown),
});

const SerializedPayload = Schema.Struct({
  v: Schema.Literal(PAYLOAD_VERSION),
  exp: Schema.Number,
  sid: Schema.String,
  session: SerializedSession,
  user: SerializedUser,
});

/** Serialize + sign a `SessionWithUser` into the cache cookie value. */
export const encodeSessionCacheCookie = (
  value: Types.SessionWithUser,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
): string => {
  const s = value.session;
  const u = value.user;
  const payload = {
    v: PAYLOAD_VERSION,
    exp: now + cache.maxAge,
    sid: primarySessionId,
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
 * validation) on a bad signature, version/expiry mismatch, an expired
 * underlying session, or a `sid` that doesn't match `primarySessionId`.
 */
export const decodeSessionCacheCookie = (
  cookie: string,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
): Types.SessionWithUser | null => {
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = cookie.slice(0, dot);
  const signature = cookie.slice(dot + 1);
  if (!timingSafeEqualStr(signature, sign(encoded, cache.secret))) return null;

  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  const parsed = Schema.decodeUnknownOption(SerializedPayload)(raw);
  if (Option.isNone(parsed)) return null;

  const payload = parsed.value;
  if (now >= payload.exp) return null;

  // Reject if the cache was issued for a different primary session.
  if (payload.sid !== primarySessionId) return null;

  const ss = payload.session;
  const session: Types.Session = {
    id: ss.id,
    userId: ss.userId,
    expiresAt: new Date(ss.expiresAt),
    createdAt: new Date(ss.createdAt),
    lastActivityAt: new Date(ss.lastActivityAt),
    attributes: ss.attributes,
  };
  // Honour the session's own expiry even within the cache window.
  if (now > session.expiresAt.getTime()) return null;

  const su = payload.user;
  const user: Types.User = {
    id: su.id,
    email: su.email,
    emailVerified: su.emailVerified,
    name: su.name,
    image: su.image,
    createdAt: new Date(su.createdAt),
    updatedAt: new Date(su.updatedAt),
    attributes: su.attributes,
  };

  return { session, user };
};
