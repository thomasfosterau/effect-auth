---
"@thomasfosterau/effect-auth": minor
---

The session cookie cache (`cookie.cache`) is treated as the authorization bound it is (#194).

- **`cookie.cache.version`**: a static cache epoch carried in every cookie. A cookie issued under another epoch is rejected and the request falls through to the store, so changing it invalidates every outstanding cache cookie at once. A function of the cached payload can't do this (it would always agree with itself), so it is a string.
- **Server-only attributes never come from the cookie.** A user holding any of `UserService`'s server-only attributes (`UserServiceConfig.serverOnlyAttributes`, default `["role"]`) is never snapshotted, and a cookie carrying one (for example one issued before this release) is never served. Their requests read the store, so `role` is always current. `UserService` exposes the list as an optional `serverOnlyAttributes` (`DEFAULT_SERVER_ONLY_ATTRIBUTES` when an implementation leaves it unset); `encodeSessionCacheCookie` and `decodeSessionCacheCookie` take it as an optional argument, and `encodeSessionCacheCookie` returns `undefined` for such a user. With the default list, the cache now helps only users who hold no `role`.
- **`cookie.cache.encrypt: true`** encrypts the payload with AES-256-GCM under a key derived from the cache secret, separate from the HMAC key, so the browser can't read it. The default stays signed-only.
- The `SessionCookieCache` module docs and `SECURITY.md` spell out the revoked-session and stale-user windows and the "change the version and revoke the sessions" procedure.
