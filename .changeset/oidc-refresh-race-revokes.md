---
"@thomasfosterau/effect-auth": minor
---

The OIDC provider's `refresh_token` grant now treats concurrent presentations of one refresh token as reuse: every one is refused with `invalid_grant` and the token family is revoked, including the tokens the first request was issued, as a later replay already was. A client that double-submits a refresh is signed out. The rotation record is now written before the token is spent, so a presentation that finds the token gone always finds it.
