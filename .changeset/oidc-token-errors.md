---
"@thomasfosterau/effect-auth": minor
---

Breaking: `POST /oauth2/token` refusals are RFC 6749 §5.2 error responses. The body is `{ error, error_description? }` instead of `{ message }`, so generic OAuth clients can read them. `invalid_client` answers `401` with `WWW-Authenticate: Basic realm="oauth"`, every other refusal `400`, and every answer stays `Cache-Control: no-store`. A request the endpoint cannot decode (a missing `grant_type`, a non-string member) answers `400` `invalid_request` in the same shape. A consumer that read `message` reads `error`.
