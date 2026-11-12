---
"@thomasfosterau/effect-auth": minor
---

The optional peer `@thomasfosterau/effect-jsonapi` moves to `^0.22.0` (was `^0.21.0`), so an application on effect-jsonapi 0.22 no longer gets a peer mismatch (#723). It is still needed only by `./http` (and `./client/testing` through it); `./http` now requires 0.22, so an application on 0.21 upgrades effect-jsonapi with this release. effect-jsonapi 0.22 itself requires `effect ^4.1.0`, the floor effect-auth already declares.

What a consumer of the HTTP API sees:

- A `400` the JSON:API tier answers for a request it could not decode (a malformed query or body, answered by effect-jsonapi's `SchemaErrors` middleware) no longer repeats its `detail` in `meta`: the error object is `{ status: "400", code: "bad_request", title: "Bad Request", detail: "Request query failed validation" }`, without `meta: { detail: … }`. Read `errors[].detail`, which was already there.
- Every other effect-auth error body is unchanged: the JSON:API errors keep `detail` and `meta: { message, code? }`, and the `406` / `415` content-negotiation errors keep the codes `not_acceptable` / `unsupported_media_type` they already carried.
