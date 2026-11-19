---
"@thomasfosterau/effect-auth": minor
---

Store faults now fail closed in the HTTP tier (#612). This changes what an app sees during a store outage.

- **A session-store or user-store fault is a logged `500`, never a `401`.** Only a session that is absent, expired, banned or whose user no longer exists (or one a hook denies) is `401`. Before, any fault answered `401 Invalid or expired session` with nothing logged, which the browser client read as a sign-out. This covers `Http.make`'s handlers (`GET /sessions/current` and every authenticated route, the device-session list and switch, `GET /oauth2/authorize`) and `AuthMiddleware` in an app's own `HttpApi`, which now declares `InternalError` beside `UnauthorizedError`.
- **`OptionalAuthMiddleware` fails on a fault instead of serving the caller as anonymous.** An absent or refused session is still anonymous. To degrade a fault to anonymous, pass `onDegraded` as `Http.optionalLayer(config, { onDegraded })`'s new second argument; it receives the fault's `Cause`, as `SessionResolution.resolveFailOpen`'s callback does. The middleware now declares `InternalError`.
- **The per-endpoint IP limit refuses a request when its `RateLimitStore` errors**, with a logged `500`, where it used to serve the request unlimited and silently. `ipRateLimit: { onStoreError: "fail-open" }` restores the old behaviour, with a logged warning per request, like `AccountLockoutPlugin`'s option of the same name.
- **`SessionService` logs a failed session refresh write or expired-session delete** as a warning instead of ignoring it.
- **`SessionService.layer` / `make` dies with the new `SessionConfigError`** when `sessionExpiresIn.activePeriod` or `idlePeriod` is not a finite, positive number, or `updateAge` is not a finite number of 0 or more. A `NaN` period (from an unset `Number(env)`, for example) used to issue sessions that never expired.
