---
"@thomasfosterau/effect-auth": minor
---

Resolve an API key over the HTTP tier and across a service binding (#730).

- `GET /api-keys/current` (JSON:API, mounted with the `api-keys` group, `404` without an `ApiKeyService`) reads the key from an API-key header, never the URL: `cookie.apiKeyHeaders` on `Http.make`, default `x-api-key`. It verifies it with `ApiKeyService.verifyWithRateLimit` and no required permissions, and answers the `api-keys` resource (never its hash or plaintext) with its `user` in `included` and `Cache-Control: no-store`. The key wins over any cookie or bearer token on the request. An unknown, disabled, expired or exhausted key gets one identical `401`, and the reason is logged server-side only. Only a real key over its own `rateLimit` gets `429` with `Retry-After`. The endpoint is in `defaultEndpointRules` (300 requests a minute per address, then a 5 minute block).
- **Each resolution consumes one use of the key**: `remaining` decrements and `lastUsedAt` moves. A non-consuming check is #645.
- `RemoteSession.resolveAtEdge` and `resolveAtEdgeFailOpen` resolve a request carrying an API key through that endpoint, to `{ session: None, user, apiKey, credentialClass: "machine" }`. This is new `RemoteSessionResult.user` / `apiKey` fields, a `RemoteApiKey` type, `RemoteSessionClient.readApiKey` and `fromApiKeyDocument`. The cookie is not forwarded on that call. A key-bearing request that used to resolve through a cookie or bearer token beside the key now resolves the key; an auth service without an `ApiKeyService` answers `404`, which fails closed (or degrades to anonymous), never falling back to the cookie.
- `ApiKeyVerifyResult` gains `reason` (`ApiKeyRefusal`) and, for `rate-limited`, `retryAfter`. `ApiKeyService.verifyWithRateLimit` now carries `R = never`, as every service method does (it never read `RateLimitStore` from its context).
- `SessionResolution.ResolveWithOptions` gains an optional `resolved` predicate for a payload that names a caller without a session.
- `./client/testing`'s `makeServerFixture` gains `apiKeys`, `layer` and `cookie` options.
