---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-saml": patch
---

Services, stores and the HTTP handlers read the current time from Effect's `Clock` (`Clock.currentTimeMillis`, `DateTime.now`, `DateTime.nowAsDate`) instead of `Date.now()` / `new Date()` (#443). Under the default clock nothing changes; under `TestClock` (or any custom `Clock` layer) token, OTP, session, invitation, rate-limit and JWT expiry, `createdAt` / `updatedAt` / `verifiedAt` stamps, the SAML subject-confirmation window and the in-memory stores in `@thomasfosterau/effect-auth/testing` all follow that clock. `generateTotp` reads the time when its effect runs, not when it is built.
