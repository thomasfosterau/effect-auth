---
"@thomasfosterau/effect-auth": patch
---

`Http.make` and `Http.makeAsync` take a `services` layer that can fail, as they already handled at runtime: a failed build makes `make` throw, or `makeAsync` reject, with its failure.
