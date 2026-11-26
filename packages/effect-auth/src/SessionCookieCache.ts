/**
 * Signed session-data cookie cache: an optionally encrypted snapshot of the
 * session and user, bound to the session cookie. A hit skips the store for up
 * to `maxAge`, so a revoked session works until then. Users with server-only or
 * standing attributes are never cached. Change `version` to invalidate every
 * cookie.
 */
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as HashSet from "effect/HashSet";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { Base64Url } from "effect/encoding";
import type { Aead, Mac, SecureRandom } from "effect/crypto";
import * as Cipher from "./Cipher.ts";
import type { AuthError } from "./Errors.ts";
import { DEFAULT_SERVER_ONLY_ATTRIBUTES, UserService } from "./User.ts";
import { timingSafeEqualBytes } from "./TokenHash.ts";
import { STANDING_ATTRIBUTES } from "./UserStanding.ts";
import * as Types from "./Types.ts";

/** Cookie-cache configuration (part of `CookieConfig`). */
export interface SessionCacheConfig {
  readonly enabled: boolean;
  /** Cache lifetime in ms. Default 5 minutes. */
  readonly maxAge?: number;
  /** HMAC secret. Use `Redacted.make(...)` / `Config.Redacted`. */
  readonly secret: Redacted.Redacted;
  /**
   * The cache epoch. Every cookie carries it, and one issued under another
   * epoch is rejected (the request falls through to the store), so changing it
   * invalidates every outstanding cache cookie at once. Default `""`.
   *
   * It must be a static value. A function of the cached payload cannot work:
   * on a cache hit the expected value would be computed from the cached
   * payload itself, so it always agrees with itself and invalidates nothing.
   */
  readonly version?: string;
  /**
   * Encrypt the payload (AES-256-GCM, under a key derived from `secret`
   * separately from the HMAC key), so the browser cannot read the session and
   * user data. Default `false`: signed only. Turning it on or off invalidates
   * every outstanding cache cookie.
   */
  readonly encrypt?: boolean;
}

/** Resolved cache config used internally by the HTTP layer. */
export interface ResolvedSessionCache {
  readonly maxAge: number;
  /** Kept redacted; unwrapped only inside `sign`. */
  readonly secret: Redacted.Redacted;
  /** {@link SessionCacheConfig.version}, `""` when unset. */
  readonly version: string;
  /** {@link SessionCacheConfig.encrypt}: the payload is sealed under a key derived from `secret`. */
  readonly encrypt: boolean;
}

const MIN_SECRET_LENGTH = 32;

/** The session cache is enabled with an HMAC secret that is too short. */
class SessionCacheConfigError extends Schema.TaggedError<
  SessionCacheConfigError,
  { readonly brand: unique symbol }
>()("SessionCacheConfigError", {
  message: Schema.String,
}) {}

/**
 * Validate a {@link SessionCacheConfig}: `undefined` when the cache is disabled, otherwise the resolved settings. Throws when the secret is shorter than 32 characters.
 */
export const resolveSessionCache = (
  config: SessionCacheConfig | undefined,
): ResolvedSessionCache | undefined => {
  if (!config?.enabled) return undefined;
  if (Redacted.value(config.secret).length < MIN_SECRET_LENGTH) {
    throw new SessionCacheConfigError({
      message: `SessionCookieCache: HMAC secret must be at least ${MIN_SECRET_LENGTH} characters`,
    });
  }
  return {
    maxAge: config.maxAge ?? 5 * 60 * 1000,
    secret: config.secret,
    version: config.version ?? "",
    encrypt: config.encrypt === true,
  };
};

const PAYLOAD_VERSION = 1;

const b64url = (data: Uint8Array): string => Base64Url.encode(data);

const sign = (data: string, secret: Redacted.Redacted): Effect.Effect<string, AuthError, Mac.Mac> =>
  Effect.map(Cipher.hmac("sha256", Redacted.value(secret), data), b64url);

// A key of its own, derived from the secret, so the HMAC key is never also the
// encryption key.
const encryptionKey = (secret: Redacted.Redacted): Effect.Effect<Uint8Array, AuthError, Mac.Mac> =>
  Cipher.hmac("sha256", Redacted.value(secret), "effect-auth/session-cache/encrypt");

const timingSafeEqualStr = (a: string, b: string): boolean =>
  timingSafeEqualBytes(new TextEncoder().encode(a), new TextEncoder().encode(b));

// Schemas for the JSON-serialized payload form (dates stored as ms timestamps).
const SerializedSession = Schema.Struct({
  id: Schema.String,
  userId: Schema.String,
  expiresAt: Schema.Finite,
  createdAt: Schema.Finite,
  lastActivityAt: Schema.Finite,
  attributes: Types.Attributes,
});

const SerializedUser = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Finite,
  updatedAt: Schema.Finite,
  attributes: Types.Attributes,
});

const SerializedPayload = Schema.Struct({
  v: Schema.Literal(PAYLOAD_VERSION),
  /** The cache epoch; absent on cookies issued before it existed. */
  e: Schema.optional(Schema.String),
  exp: Schema.Finite,
  sid: Schema.String,
  session: SerializedSession,
  user: SerializedUser,
});

/** Marks an encrypted payload; base64url never contains it. */
const ENCRYPTED_PREFIX = "~";

const gateOf = (serverOnly: ReadonlyArray<string>): HashSet.HashSet<string> =>
  HashSet.fromIterable([...serverOnly, ...STANDING_ATTRIBUTES]);

const defaultGate = gateOf(DEFAULT_SERVER_ONLY_ATTRIBUTES);

/**
 * The attributes the cache keeps out of its snapshots: the server-only
 * attributes of the `UserService` in context (or
 * {@link DEFAULT_SERVER_ONLY_ATTRIBUTES} without one), plus the ban and SCIM
 * standing keys, whatever the config.
 */
export const sessionCacheGateAttributes: Effect.Effect<HashSet.HashSet<string>> = Effect.map(
  Effect.serviceOption(UserService),
  (service) =>
    Option.isSome(service) && service.value.serverOnlyAttributes !== undefined
      ? gateOf(service.value.serverOnlyAttributes)
      : defaultGate,
);

const holdsGateAttribute = (user: Types.User, gate: HashSet.HashSet<string>): boolean =>
  Arr.some(R.keys<string, Types.Json>(user.attributes), (key) => HashSet.has(gate, key));

// `Schema.Unknown` passes the payload through untouched, so encoding is exactly
// `JSON.stringify`; decoding parses and validates in one step.
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));
const decodePayloadJson = Schema.decodeUnknownOption(Schema.fromJsonString(SerializedPayload));

/**
 * Serialize + sign a `SessionWithUser` into the cache cookie value. Returns
 * `undefined`, and nothing should be cached, when the user holds one of the
 * `gateAttributes` (default {@link DEFAULT_SERVER_ONLY_ATTRIBUTES} and the
 * standing keys).
 * `primarySessionId` is the primary session's stored id (the digest of its
 * token), as {@link decodeSessionCacheCookie} is given it.
 */
export const encodeSessionCacheCookie = (
  value: Types.SessionWithUser,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
  gateAttributes: HashSet.HashSet<string> = defaultGate,
): Effect.Effect<string | undefined, AuthError, Mac.Mac | Aead.Aead | SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
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
    const json = encodeJson(payload);
    const encoded = cache.encrypt
      ? `${ENCRYPTED_PREFIX}${yield* Cipher.aes256GcmSeal(yield* encryptionKey(cache.secret), json)}`
      : b64url(new TextEncoder().encode(json));
    return `${encoded}.${yield* sign(encoded, cache.secret)}`;
  });

/**
 * Verify + parse a cache cookie. Answers `None` (falling back to store
 * validation) on a bad signature, a version, epoch or expiry mismatch, an
 * encryption setting the cookie was not issued under, an expired underlying
 * session, a `sid` that doesn't match `primarySessionId`, or a user holding
 * one of the `gateAttributes` (default {@link DEFAULT_SERVER_ONLY_ATTRIBUTES} and the
 * standing keys).
 */
export const decodeSessionCacheCookie = (
  cookie: string,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
  gateAttributes: HashSet.HashSet<string> = defaultGate,
): Effect.Effect<Option.Option<Types.SessionWithUser>, never, Mac.Mac | Aead.Aead> =>
  Effect.gen(function* () {
    const dot = cookie.lastIndexOf(".");
    if (dot <= 0) return Option.none();
    const encoded = cookie.slice(0, dot);
    const signature = cookie.slice(dot + 1);
    const expected = yield* Effect.option(sign(encoded, cache.secret));
    if (Option.isNone(expected) || !timingSafeEqualStr(signature, expected.value))
      return Option.none();

    const json = yield* payloadJson(encoded, cache);
    return Option.flatMap(Option.flatMap(json, decodePayloadJson), (payload) =>
      restoreSnapshot(payload, cache, now, primarySessionId, gateAttributes),
    );
  });

/** The signed body's JSON: decrypted under `cache.encrypt`, else base64url-decoded. */
const payloadJson = (
  encoded: string,
  cache: ResolvedSessionCache,
): Effect.Effect<Option.Option<string>, never, Aead.Aead | Mac.Mac> =>
  Effect.gen(function* () {
    if (encoded.startsWith(ENCRYPTED_PREFIX) !== cache.encrypt) return Option.none();
    if (!cache.encrypt) return Result.getSuccess(Base64Url.decodeString(encoded));
    const key = yield* Effect.option(encryptionKey(cache.secret));
    if (Option.isNone(key)) return Option.none();
    return yield* Cipher.aes256GcmOpen(key.value, encoded.slice(ENCRYPTED_PREFIX.length));
  });

/** The snapshot a verified payload carries, or `None` when it may not be served. */
const restoreSnapshot = (
  payload: typeof SerializedPayload.Type,
  cache: ResolvedSessionCache,
  now: number,
  primarySessionId: string,
  gateAttributes: HashSet.HashSet<string>,
): Option.Option<Types.SessionWithUser> => {
  if (now >= payload.exp) return Option.none();
  if ((payload.e ?? "") !== cache.version) return Option.none();

  // Reject if the cache was issued for a different primary session.
  if (payload.sid !== primarySessionId) return Option.none();

  const ss = payload.session;
  const session: Types.Session = {
    id: ss.id,
    userId: ss.userId,
    expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(ss.expiresAt)),
    createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(ss.createdAt)),
    lastActivityAt: DateTime.toDateUtc(DateTime.makeUnsafe(ss.lastActivityAt)),
    attributes: ss.attributes,
  };
  // Honour the session's own expiry even within the cache window.
  if (now > session.expiresAt.getTime()) return Option.none();

  const su = payload.user;
  const user: Types.User = {
    id: su.id,
    name: su.name,
    image: su.image,
    createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(su.createdAt)),
    updatedAt: DateTime.toDateUtc(DateTime.makeUnsafe(su.updatedAt)),
    attributes: su.attributes,
  };
  // An authorization-bearing attribute is never served from a snapshot.
  if (holdsGateAttribute(user, gateAttributes)) return Option.none();

  return Option.some({ session, user });
};
