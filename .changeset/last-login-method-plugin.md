---
"@thomasfosterau/effect-auth": minor
---

The last-login-method plugin's constructor is now `LastLoginMethodPlugin`, matching its siblings (`AuditPlugin`, `RateLimitPlugin`, …), instead of a bare `make` (#284). Through the barrel it surfaced as `Auth.Plugins.make` (and `make` from `@thomasfosterau/effect-auth/plugins`), which read as a constructor for the whole plugins cluster. Like the other plugins that take no config, `LastLoginMethodPlugin` is the layer itself rather than a function: replace `Plugins.make()` with `Plugins.LastLoginMethodPlugin`. It still requires `SessionService` and isolates its taps.
