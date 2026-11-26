---
"@thomasfosterau/effect-auth-svelte": minor
---

`SignInForm` and `EmailOtpForm` no longer call `onSuccess` when the server answers with a second-factor challenge (`202`), so `onSuccess={() => goto("/app")}` never navigates without a session. The challenge goes to the new `onSecondFactor` prop; the `SecondFactorChallenge` type is exported.
