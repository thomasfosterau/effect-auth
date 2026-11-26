---
"@thomasfosterau/effect-auth": minor
---

Breaking: an OIDC `id_token` is no longer accepted as a first-party bearer JWT. `JwtService.sign` now issues access JWTs with the header `typ: "at+jwt"` (RFC 9068, exported as `ACCESS_TOKEN_TYPE`), and `JwtService.verify` and `RemoteJwksVerifier` refuse any token without that type (`application/at+jwt` is accepted too). The OIDC provider signs `id_token`s through the new `JwtService.signIdToken(claims)`, which keeps `typ: "JWT"` and writes only the OIDC claims plus `iat` and `exp`: `definePayload` claims and the configured `audience` no longer reach an `id_token`. Keys and the JWKS endpoint are unchanged. A JWT issued before the upgrade carries `typ: "JWT"` and is refused, so its holder mints a new one (`POST /tokens`); by default it would have expired within 15 minutes anyway. A custom `JwtService` implementation needs a `signIdToken`.
