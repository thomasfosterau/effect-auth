---
"@thomasfosterau/effect-auth": patch
---

Every response carrying `Set-Cookie` is now sent with `Cache-Control: no-store` (#628), whether `Http.make` serves it or `Http.RemoteSession.relayResponse` / `withSetCookie` relays it: sign-in, sign-up, sign-out and the other cookie-clearing answers, and the `GET /sessions/current` that refreshes the session-data cache cookie. An existing `Cache-Control` with `no-store` is kept; one without it keeps its directives and gets `no-store` appended. The responses that hand a credential over without a cookie are `no-store` too: `GET /sessions/:id`, `POST /tokens`, `POST /api-keys`, `POST /oauth-clients`, `POST /multi-factor-enrollments`, `POST /backup-code-sets`, `POST /device/token`, `POST /oauth2/token`, `GET /oauth2/userinfo` and `POST /register`.
