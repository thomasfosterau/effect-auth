---
"@thomasfosterau/effect-auth": minor
---

Outbound requests now go through `effect/http`'s `HttpClient` instead of the global `fetch`: the OAuth and OIDC provider endpoints (token, userinfo, JWKS), `discoverOAuthEndpoints`, `verifyIdToken`, `RemoteJwksVerifier`, Cloudflare Access's key set and Google One Tap's JWKS.

**Breaking:** `OAuthService.layer`, `SsoService.layer`, `GoogleOneTapService.layer`, `RemoteJwksVerifier.layer` / `remoteJwksVerifier`, `CloudflareAccessVerifier.layer` / `make`, and the `OAuthProvider` methods, `verifyIdToken` and `discoverOAuthEndpoints` now require `HttpClient.HttpClient`. Provide `FetchHttpClient.layer` (Workers, Node and browsers) or a stub in tests.
