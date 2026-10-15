---
"@thomasfosterau/effect-auth": minor
---

Rate limits keyed by client address need an address source. A Web `Request` carries no socket address, so `Http.make` with `ipRateLimit` requires `trustedProxy` (for example `ClientIP.cloudflare`), and throws `ClientAddressConfigError` at build without one. An app that sets `trustedProxy` also gets `429` on rate-limited endpoints when a request's trusted header is missing or unusable and so has no socket address, such as service-binding or health-check traffic, when a `RateLimiter` is in `services`. The new `allowMissingClientIp: true` option accepts that address-less requests to rate-limited endpoints are refused with `429`, when a `RateLimiter` is in `services`. Such a request is never let through unlimited and never counted under a bucket shared with other callers. This includes the dynamic client registration limit on `POST /register`, which refuses it too, when a `RateLimiter` is in `services` (#358).
