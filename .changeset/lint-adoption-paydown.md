---
"@thomasfosterau/effect-auth": patch
---

Type-only tidying from the lint paydown (#503); no runtime change. Optional parameters no longer repeat `| undefined` (which an optional parameter already admits): `EmailVerificationService.createVerification` / `resendVerification`'s `options` and `Testing.sessionFor`'s `overrides`. Callers are unaffected.
