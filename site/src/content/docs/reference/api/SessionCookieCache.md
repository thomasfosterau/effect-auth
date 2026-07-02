---
title: "SessionCookieCache"
description: "API reference for the SessionCookieCache module."
---

## SessionCookieCache overview

Signed session-data cookie cache.

better-auth's `session.cookieCache` stores a short-lived HMAC-signed copy of
the session + user in a cookie so `GET /session` (and other authenticated
requests) can be served without hitting the session store on every request.

The cookie value is `base64url(payload) . base64url(HMAC-SHA256(base64url
payload))`, where the payload is versioned for forward compatibility and
carries the session, user, and a cache expiry (`now + maxAge`).

Staleness: a session revoked on another device remains usable from a cached
cookie until `maxAge` elapses. Keep `maxAge` short (default 5 minutes) and
clear the cache cookie on sign-out / revocation (the HTTP layer does this).

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [ResolvedSessionCache (interface)](#resolvedsessioncache-interface)
  - [SessionCacheConfig (interface)](#sessioncacheconfig-interface)
  - [decodeSessionCacheCookie](#decodesessioncachecookie)
  - [encodeSessionCacheCookie](#encodesessioncachecookie)
  - [resolveSessionCache](#resolvesessioncache)

---

# utils

## ResolvedSessionCache (interface)

Resolved cache config used internally by the HTTP layer.

**Signature**

```ts
export interface ResolvedSessionCache {
  readonly maxAge: number;
  readonly secret: string;
}
```

## SessionCacheConfig (interface)

Cookie-cache configuration (part of `CookieConfig`).

**Signature**

```ts
export interface SessionCacheConfig {
  readonly enabled: boolean;
  /** Cache lifetime in ms. Default 5 minutes. */
  readonly maxAge?: number;
  /** HMAC secret. Use `Redacted.make(...)` / `Config.redacted`. */
  readonly secret: Redacted.Redacted<string>;
}
```

## decodeSessionCacheCookie

Verify + parse a cache cookie. Returns `null` (falling back to store
validation) on a bad signature, a version/expiry mismatch, or an expired
underlying session.

**Signature**

```ts
export declare const decodeSessionCacheCookie: (
  cookie: string,
  cache: ResolvedSessionCache,
  now: number,
) => Types.SessionWithUser | null;
```

## encodeSessionCacheCookie

Serialize + sign a `SessionWithUser` into the cache cookie value.

**Signature**

```ts
export declare const encodeSessionCacheCookie: (
  value: Types.SessionWithUser,
  cache: ResolvedSessionCache,
  now: number,
) => string;
```

## resolveSessionCache

**Signature**

```ts
export declare const resolveSessionCache: (
  config: SessionCacheConfig | undefined,
) => ResolvedSessionCache | undefined;
```
