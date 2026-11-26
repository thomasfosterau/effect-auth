---
"@thomasfosterau/effect-auth": minor
---

`Http.make` and `Http.makeAsync` now log a warning when `signUpAttributes` names a key of `SIGN_UP_PROTECTED_ATTRIBUTES` (such as `banned` or `scimExternalId`), which a sign-up never stores, so naming it did nothing silently. With `strict: true` they refuse to start with the new `SignUpAttributesConfigError` instead. `strict` now also applies to `makeAsync` for this check.
