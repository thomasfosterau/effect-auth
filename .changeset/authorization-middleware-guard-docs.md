---
"@thomasfosterau/effect-auth": patch
---

TSDoc for `makeAuthorizationMiddleware` gives the runtime key of a guard: `@effect-auth/AuthorizationMiddleware/<name>#<n>`, where `<n>` counts factory calls. The type-level key is the bare name, so the two differ.
