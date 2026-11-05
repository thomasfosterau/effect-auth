---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-vue": patch
---

Type-only tidying from the lint paydown (#503); no runtime change. Optional parameters no longer repeat `| undefined` (which an optional parameter already admits): `EmailVerificationService.createVerification` / `resendVerification`'s `options`, `Testing.sessionFor`'s `overrides`, and effect-auth-vue's `useAuthClient(override?)`. Callers are unaffected.
