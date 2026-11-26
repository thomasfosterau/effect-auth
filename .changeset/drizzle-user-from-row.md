---
"@thomasfosterau/effect-auth-drizzle": minor
---

`UserStore.makeToUser` is renamed `UserStore.userFromRow`. It builds a row decoder, not a service, and a `make*` name reads as a service constructor.
