---
"@thomasfosterau/effect-auth-client": patch
---

The `./testing` in-memory server's feature set (`features: true`) now includes an in-memory `RateLimiter`. The core's device-flow limit fails the handler build without one (#389), so the fixture supplies one. No API change.
