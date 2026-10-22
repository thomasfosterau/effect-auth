---
"@thomasfosterau/effect-auth": minor
---

`@thomasfosterau/effect-auth/testing` adds guard-negative helpers: `expectGuarded` asserts in one call that an operation refuses an anonymous viewer and a viewer one rung too low (`Unauthorized` / `Forbidden` for a write, the app's not-found for a read), admits its minimum rung, and admits the owner. `expectRefusesAnonymous`, `expectRefusesBelow` and `expectAllowsOwner` check one case each. A failure is a `GuardExpectationError` listing every mismatched case.
