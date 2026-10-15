---
"@thomasfosterau/effect-auth": minor
---

IP-keyed limits no longer skip silently. Two cases that used to do nothing now refuse or fail (#389).

- **Address-less hooks.** `IPRateLimitPlugin` refuses a request whose `ClientIP` carries no address with a `RateLimitError`, which the HTTP layer answers with `429`. It used to return unlimited, so the sign-in, sign-up and password-reset limits did not run for those requests. With the `ClientIP` service absent (no request in scope, for example a direct call outside HTTP), the plugin is still a no-op.
- **No `RateLimiter`.** `Http.make`'s layer build fails with `RateLimiterConfigError` (new export) when `ipRateLimit`, the dynamic client registration limit or the device user-code limit is configured and no `RateLimiter` is in `services`. The check reads `services`, so it runs when the layer is built, not synchronously in `make`. The failure is logged at startup, and every request to the handler then rejects with it. Before, these limits were silent no-ops.
