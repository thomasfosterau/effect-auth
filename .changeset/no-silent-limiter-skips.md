---
"@thomasfosterau/effect-auth": minor
---

A rate limit that cannot run refuses the request or stops the app from starting; it never skips silently (#389).

- **Missing `RateLimiter`.** `Http.make` throws `RateLimiterConfigError` (exported from the package root) when a limit is configured and no `RateLimiter` is in `services`. The limits are `ipRateLimit`, the dynamic client registration limit and the device user-code limit on approve/deny. `make` builds `services` once, synchronously where it can, and the handler reuses that build. When `services` does asynchronous work while building, `make` cannot see the result before it returns: the handler's build fails with the same error instead, and every request rejects with it.
- **Device user-code limit.** It counts as configured whenever a `DeviceAuthorizationService` is in `services`. `DeviceAuthorizationConfig.allowMissingRateLimiter: true` is the explicit opt-out: approve and deny then run without the limit when no `RateLimiter` is present.
- **`IPRateLimitPlugin` needs an address source.** `Http.make` throws `ClientAddressConfigError` when the `Hooks` in `services` include `IPRateLimitPlugin` and neither `trustedProxy` nor `allowMissingClientIp: true` is set, because a Web `Request` has no socket address.
- **Requests that cannot be limited are refused.** `IPRateLimitPlugin` fails a hook with `RateLimitError` (`429` over HTTP) when the request has no client address, including when no `ClientIP` service is in scope, as for a hook run outside an HTTP request. The group layers composed by hand outside `Http.make` (`authGroupLayer`) answer `429` when a configured limit has no `RateLimiter` in scope, or when the registration limit has no client address. Such a request is never let through unlimited and never counted under a bucket shared with other callers.
