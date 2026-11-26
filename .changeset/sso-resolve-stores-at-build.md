---
"@thomasfosterau/effect-auth": minor
---

`SsoService` resolves its stores when its layer is built, as the other services do: `SsoService.layer` and `Sso.make` now require `OAuthStateStore`, `OAuthUserStore`, `IdentifierStore`, `UserStore`, `SessionService` and `EmailPasswordStore`, and `signIn`, `handleCallback` and `handleSamlCallback` require nothing per call. Provide those services to the layer rather than around each call.
