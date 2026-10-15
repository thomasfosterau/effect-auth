---
"@thomasfosterau/effect-auth": minor
---

`Http.makeAsync` is the asynchronous counterpart of `Http.make`, for `services` that build asynchronously: a database connection or other `Effect.promise` step, merged layers that yield, or finalizers that do asynchronous work. It takes the same options, waits for the `services` build however it is composed, and resolves to the same `{ handler, dispose }`. The handler serves that one build, and `dispose` releases it. The promise rejects with the errors `make` throws, so the app fails to start: `ClientAddressConfigError`, `RateLimiterConfigError`, or any failure of the `services` build (its error, or for a defect the defect itself). It releases what the build acquired and waits for every finalizer, asynchronous ones included, then rejects; a finalizer that fails is logged as an error. `Http.AuthWebHandler` names the `{ handler, dispose }` pair that both constructors return (#400).
