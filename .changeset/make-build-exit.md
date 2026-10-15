---
"@thomasfosterau/effect-auth": patch
---

`Http.make` runs the `services` build until it finishes, and no further. A fiber the build forks and does not await (a background job, a refresh loop, a busy worker) keeps running under the default scheduler after `make` returns, and `make` does not wait for it. One forked into the layer's scope (`Effect.forkScoped`) stops on `dispose`. Any failure of a synchronous `services` build makes `make` throw, so the app fails to start: the failure's error, or for a defect the defect itself, as `Effect.runSync` throws. An example is the OIDC layer's `ClientAddressConfigError` for dynamic registration with no address source. `make` releases what the build acquired, then throws. A `services` build that does asynchronous work finishes after `make` returns, so its failure fails the handler's build instead, and every request rejects with it (#402).
