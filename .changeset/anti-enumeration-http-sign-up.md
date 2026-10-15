---
"@thomasfosterau/effect-auth": patch
---

With `antiEnumeration: true`, an email and password sign-up for an address another user holds answers over HTTP exactly as a fresh sign-up does (#414): a `200` with the same headers and no `Set-Cookie`, and a `user` with the same fields, whose `email` is the submitted address with `emailVerified: false`. The sign-up response takes `email` from the address the sign-up was made with, which `AuthLifecycleResult` carries as `identifier`.

The stand-in user in that answer has one timestamp for both `createdAt` and `updatedAt`. Its id is a random UUID, or comes from the optional `EmailPasswordStore.newUserId` seam, so a store whose ids have another shape can give the stand-in an id of that shape.

`UsernameService.signUp` claims no username for the stand-in, so a sign-up with a held address cannot squat a username, and it fails with `UsernameError` when someone holds the username by then, as the claim does. The `EmailPasswordConfig.antiEnumeration` docs list what the two answers share and what still tells them apart.
