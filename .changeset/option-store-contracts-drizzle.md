---
"@thomasfosterau/effect-auth-drizzle": minor
---

**Breaking:** the Drizzle stores follow the core's new store contracts and answer a miss with `Option.none()` instead of `null`. The batched `Requests.getSession`, `Requests.getUser` and `Requests.getIdentifierByValue` (and their `GetSession`, `GetUser` and `GetIdentifierByValue` request classes) now resolve to an `Option`, and so does `TokenStore`'s `get`, `consume` and `getLatestByUserId`.
