---
"@thomasfosterau/effect-auth": minor
---

`SessionCookieCache`'s gate attributes are now an Effect `HashSet<string>` instead of a native `ReadonlySet<string>`, matching `UserService`'s `serverOnlyAttributes`: `sessionCacheGateAttributes` yields one, and `encodeSessionCacheCookie` / `decodeSessionCacheCookie` take one as their `gateAttributes` argument (#443).

**Breaking:** a caller that passes a native `Set` as `gateAttributes` must pass a `HashSet` instead. Migration: `HashSet.fromIterable(set)`.
