---
"@thomasfosterau/effect-auth": minor
---

Replace type assertions with checks:

- The `KeyValueStore` stores decode every record they read with a schema, and `./sql` decodes the stored identifier type and email OTP purpose, so a value that is not the record its key or column names fails with `AuthError` instead of reaching a service.
- `AuthorizationMiddlewareInstance` and `AuthorizationMiddlewareClass` now carry the guard's runtime key type, the new `AuthorizationMiddlewareKey<Id>` (`@effect-auth/AuthorizationMiddleware/<name>#<n>`), instead of the bare name. Each name is still its own type.
- `RemoteJwks.KeySets.forUrl` shares a URL's keys between callers but refetches through each caller's own `fetch`, so a failure keeps that caller's error type; it no longer returns the same `KeySet` object for a URL.
- The Twitter, Notion, TikTok and Kick providers fall back to the whole answer when the nested user is not an object, rather than reading it as one.
