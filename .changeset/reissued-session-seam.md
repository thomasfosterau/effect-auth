---
"@thomasfosterau/effect-auth": minor
---

`SessionService.validateSession` may now answer `reissued` beside the session (`Types.ValidatedSession`), for a backend whose credential changes as it validates (a sealed cookie whose access token it refreshed). The HTTP tier's session resolution, both middlewares and the device-session handlers write a reissued credential only to the response headers (the session cookie, the multi-session list, or `set-auth-token` for a bearer caller), mark the response `no-store`, and hand on only `{ session, user }`. The core's own `SessionService` never reissues, so nothing changes for it.

`remoteJwksVerifier` takes `tokenType: null` to skip the `typ` check for an issuer that sets none; the issuer, signature and `exp` are still checked.
