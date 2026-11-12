---
"@thomasfosterau/effect-auth": patch
---

More answers are `Cache-Control: no-store` (#628 follow-ups): `POST /device/code` (the device code), the second-factor challenge a `POST /sessions` answers, `POST /oauth2/consent` (the redirect carries the authorization code), and the per-caller single-use `POST /sso-authorizations` state and `POST /google-one-tap-nonces` nonce. Under `Http.make`, every answer of `POST /oauth2/token` and `POST /device/token` is `no-store`, including the `400` for a payload that does not decode (RFC 6749 §5.2). `Http.RemoteSession.relayResponse` marks a response `no-store` when it strips its `Set-Cookie` for an API-key or bearer caller.
