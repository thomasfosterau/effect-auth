/**
 * Signed session-data cookie cache.
 *
 * better-auth's `session.cookieCache` stores a short-lived HMAC-signed copy of
 * the session + user in a cookie so `GET /session` (and other authenticated
 * requests) can be served without hitting the session store on every request.
 *
 * The cookie value is `base64url(payload) . base64url(HMAC-SHA256(base64url
 * payload))`, where the payload is versioned for forward compatibility and
 * carries the session, user, a cache expiry (`now + maxAge`), the app's cache
 * epoch ({@link SessionCacheConfig.version}) and the primary session id
 * (`sid`) — binding the cache entry to a specific primary session cookie so
 * identity cannot bleed across account switches. With
 * {@link SessionCacheConfig.encrypt} the payload is AES-256-GCM encrypted
 * before it is signed.
 *
 * ### An authorization bound, not a tuning knob
 *
 * A cache hit resolves the session and the user without consulting the store,
 * so for up to `maxAge` it answers with what was true when the cookie was
 * issued. Two windows follow:
 *
 * - **A revoked session keeps working.** A session signed out or revoked on
 *   another device stays usable from a cached cookie until `maxAge` elapses.
 *   (The HTTP layer clears the cache cookie on the device that signs out.)
 * - **A changed user is served stale.** Anything the snapshot carries is
 *   served as it was: a banned user's profile, an edited name.
 *
 * Authorization-bearing attributes are kept out of that window: a user who
 * holds any of `UserService`'s server-only attributes
 * (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never
 * snapshotted, and a cookie that carries one is never served, so a demoted
 * admin's `role` always comes from the store. The cache then helps only users
 * with no such attribute. Keep `maxAge` short (default 5 minutes) all the same,
 * since a revoked session's window is not narrowed by this.
 *
 * **To invalidate every outstanding cache cookie at once** (a role-ladder
 * change, a session-shape change, a suspected compromise), change
 * {@link SessionCacheConfig.version}. After a compromise, also revoke the
 * affected accounts' sessions: a still-valid session is simply re-cached under
 * the new epoch.
 *
 * Without `encrypt`, the cookie is signed but NOT encrypted: session and user
 * data (including any PII in `attributes`) is readable by the browser.
 */
import { Effect, Option, Redacted, Schema } from "effect";
import * as Cipher from "./Cipher.ts";
import { DEFAULT_SERVER_ONLY_ATTRIBUTES, UserService } from "./User.ts";
import { timingSafeEqualBytes } from "./TokenHash.ts";
import type * as Types from "./Types.ts";

/** Cookie-cache configuration (part of `CookieConfig`). */
export interface SessionCacheConfig {
  readonly enabled: boolean;
  /** Cache lifetime in ms. Default 5 minutes. */
  readonly maxAge?: number;
  /** HMAC secret. Use `Redacted.make(...)` / `Config.Redacted`. */
  readonly secret: Redacted.Redacted<string>;
  /**
   * The cache epoch. Every cookie carries it, and one issued under another
   * epoch is rejected (the request falls through to the store), so changing it
   * invalidates every outstanding cache cookie at once. Default `""`.
   *
   * It must be a static value. A function of the cached payload cannot work:
   * on a cache hit the expected value would be computed from the cached
   * payload itself, so it always agrees with itself and invalidates nothing.
   */
  readonly version?: string | undefined;
  /**
   * Encrypt the payload (AES-256-GCM, under a key derived from `secret`
   * separately from the HMAC key), so the browser cannot read the session and
   * user data. Default `false`: signed only. Turning it on or off invalidates
   * every outstanding cache cookie.
   */
  readonly encrypt?: boolean | undefined;
}

/** Resolved cache config used internally by the HTTP layer. */
export interface ResolvedSessionCache {
  readonly maxAge: number;
  /** Kept redacted; unwrapped only inside `sign`. */
  readonly secret: Redacted.Redacted<string>;
  /** {@link SessionCacheConfig.version}, `""` when unset. */
  readonly version: string;
  /** The AES-256-GCM key when {@link SessionCacheConfig.encrypt} is on. */
  readonly encryptionKey: Uint8Array | undefined;
}

const MIN_SECRET_LENGTH = 32;

/**
 * Validate a {@link SessionCacheConfig}: `undefined` when the cache is disabled, otherwise the resolved settings. Throws when the secret is shorter than 32 characters.
 */
export const resolveSessionCache = (
  config: SessionCacheConfig | undefined,
): ResolvedSessionCache | undefined => {
  if (!config?.enabled) return undefined;
  if (Redacted.value(config.secret).length < MIN_SECRET_LENGTH) {
    throw new Error(
      `SessionCookieCache: HMAC secret must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  return {
    maxAge: config.maxAge ?? 5 * 60 * 1000,
    secret: config.secret,
    version: config.version ?? "",
    // A key of its own, derived from the secret, so the HMAC key is never
    // also the encryption key.
    encryptionKey:
      config.encrypt === true
        ? Cipher.hmac("sha256", Redacted.value(config.secret), "effect-auth/session-cache/encrypt")
        : undefined,
  };
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
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  attributes: Schema.Record(Schema.String, Schema.Unknown),
});

const SerializedPayload = Schema.Struct({
  v: Schema.Literal(PAYLOAD_VERSION),
  /** The cache epoch; absent on cookies issued before it existed. */
  e: Schema.optional(Schema.String),
  exp: Schema.Number,
  sid: Schema.String,
  session: SerializedSession,
  user: SerializedUser,
});

/** Marks an encrypted payload; base64url never contains it. */
const ENCRYPTED_PREFIX = "~";

/**
 * The server-only attributes the cache keeps out of its snapshots: those of the
 * `UserService` in context, or {@link DEFAULT_SERVER_ONLY_ATTRIBUTES} without
 * one.
 */
export const sessionCacheGateAttributes: Effect.Effect<ReadonlySet<string>> = Effect.map(
  Effect.serviceOption(UserService),
  (service) =>
    new Set(
      Option.isSome(service)
        ? (service.value.serverOnlyAttributes ?? DEFAULT_SERVER_ONLY_ATTRIBUTES)
        : DEFAULT_SERVER_ONLY_ATTRIBUTES,
    ),
);

const holdsGateAttribute = (user: Types.User, gate: ReadonlySet<string>): boolean =>
  Object.keys(user.attributes).some((key) => gate.has(key));

/**
 * Serialize + sign a `SessionWithUser` into the cache cookie value. Returns
 * `undefined`, and nothing should be cached, when the user holds one of the
 * `gateAttributes` (default {@link DEFAULT_SERVER_ONLY_ATTRIBUTES}).
 */
export const encodeSessionCacheCookie = (
  value: Types.SessionWithUser,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
  gateAttributes: ReadonlySet<string> = new Set(DEFAULT_SERVER_ONLY_ATTRIBUTES),
): string | undefined => {
  const s = value.session;
  const u = value.user;
  if (holdsGateAttribute(u, gateAttributes)) return undefined;
  const payload = {
    v: PAYLOAD_VERSION,
    e: cache.version,
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
  const json = JSON.stringify(payload);
  const encoded =
    cache.encryptionKey === undefined
      ? b64url(new TextEncoder().encode(json))
      : `${ENCRYPTED_PREFIX}${Cipher.aes256GcmSeal(cache.encryptionKey, json)}`;
  return `${encoded}.${sign(encoded, cache.secret)}`;
};

/**
 * Verify + parse a cache cookie. Returns `null` (falling back to store
 * validation) on a bad signature, a version, epoch or expiry mismatch, an
 * encryption setting the cookie was not issued under, an expired underlying
 * session, a `sid` that doesn't match `primarySessionId`, or a user holding
 * one of the `gateAttributes` (default {@link DEFAULT_SERVER_ONLY_ATTRIBUTES}).
 */
export const decodeSessionCacheCookie = (
  cookie: string,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
  gateAttributes: ReadonlySet<string> = new Set(DEFAULT_SERVER_ONLY_ATTRIBUTES),
): Types.SessionWithUser | null => {
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0) return null;
  const encoded = cookie.slice(0, dot);
  const signature = cookie.slice(dot + 1);
  if (!timingSafeEqualStr(signature, sign(encoded, cache.secret))) return null;

  const encrypted = encoded.startsWith(ENCRYPTED_PREFIX);
  if (encrypted !== (cache.encryptionKey !== undefined)) return null;
  const json =
    cache.encryptionKey === undefined
      ? Buffer.from(encoded, "base64url").toString("utf8")
      : Cipher.aes256GcmOpen(cache.encryptionKey, encoded.slice(ENCRYPTED_PREFIX.length));
  if (json === null) return null;

  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }

  const parsed = Schema.decodeUnknownOption(SerializedPayload)(raw);
  if (Option.isNone(parsed)) return null;

  const payload = parsed.value;
  if (now >= payload.exp) return null;
  if ((payload.e ?? "") !== cache.version) return null;

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
    name: su.name,
    image: su.image,
    createdAt: new Date(su.createdAt),
    updatedAt: new Date(su.updatedAt),
    attributes: su.attributes,
  };
  // An authorization-bearing attribute is never served from a snapshot.
  if (holdsGateAttribute(user, gateAttributes)) return null;

  return { session, user };
};
