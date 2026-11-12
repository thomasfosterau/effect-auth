---
"@thomasfosterau/effect-auth": minor
---

Resolve an API key over the HTTP tier and across a service binding (#730).

- **New endpoint, `GET /api-keys/current`.** It is JSON:API and mounted with the `api-keys` group; without an `ApiKeyService` it answers `404`.
  - It reads the key from an API-key header, never from the URL: `cookie.apiKeyHeaders` on `Http.make`, default `x-api-key`.
  - It verifies the key with `ApiKeyService.verifyWithRateLimit` and no required permissions.
  - It answers the `api-keys` resource, never its hash or plaintext, with its `user` in `included` and `Cache-Control: no-store`.
  - The key wins over any cookie or bearer token on the request.
  - An unknown, disabled, expired or exhausted key gets one identical `401`, and the reason is logged server-side only.
  - Only a real key over its own `rateLimit` gets `429` with `Retry-After`.
- **Each resolution consumes one use of the key**: `remaining` decrements and `lastUsedAt` moves. A non-consuming check is #645.
- **New default rate-limit rule.** `defaultEndpointRules` gains one for the endpoint: 300 requests a minute per client address, then a 5-minute block.
  - It counts every request before the key is read, refused and resolved ones alike.
  - A request it refuses spends no use of the key.
  - Override it with a rule ahead of `...defaultEndpointRules`; the first match wins.
- **Behaviour change in `RemoteSession`.** `resolveAtEdge` and `resolveAtEdgeFailOpen` now resolve a request that carries an API key through `GET /api-keys/current`, to `{ session: None, user, apiKey, credentialClass: "machine" }`.
  - The cookie is not forwarded on that call.
  - A request carrying a key **and** a session cookie or bearer token used to resolve through the cookie or token. It now resolves the key.
  - If the auth service has no `ApiKeyService`, that call answers `404`. `resolveAtEdge` then fails closed with a `RemoteSessionError` (`status: 404`), and `resolveAtEdgeFailOpen` degrades to anonymous. Neither falls back to the cookie.
  - New API: `RemoteSessionResult.user` / `apiKey`, a `RemoteApiKey` type, `RemoteSessionClient.readApiKey` and `fromApiKeyDocument`.
- **Fix in `ApiKeyService.verifyWithRateLimit`.** It now runs the enabled, expiry, remaining-uses and permission checks before it consumes the key's per-key rate-limit token.
  - A disabled, expired, exhausted or under-permitted key is refused with that reason even when it is over its limit. It used to be refused as `Rate limit exceeded`, which told a revoked-but-real key apart from an unknown one.
  - A refused attempt no longer spends a token from the key's bucket.
- **Type narrowing in `ApiKeyService.verifyWithRateLimit`.** It now declares `R = never` instead of `RateLimitStore`, as every service method does; it never read the store from its context.
  - Callers keep compiling.
  - It breaks only a hand-written `ApiKeyService` implementation whose `verifyWithRateLimit` requires `RateLimitStore`.
- **Smaller additions:**
  - `ApiKeyVerifyResult` gains `reason` (`ApiKeyRefusal`) and, for `rate-limited`, `retryAfter`.
  - `SessionResolution.ResolveWithOptions` gains an optional `resolved` predicate.
  - `./client/testing`'s `makeServerFixture` gains `apiKeys`, `layer` and `cookie` options.
