---
"@thomasfosterau/effect-auth-sql": patch
---

Correct the `layer` doc comment: core's `KeyValueStore`-backed layers do not cover the stores this package lacks (one-time token, trusted device, phone OTP, organization, OIDC, SSO, device authorization), so implement those yourself until they land here.
