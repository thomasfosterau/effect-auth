---
"@thomasfosterau/effect-auth-sveltekit": patch
---

`handle`, `HandleOptions` and `FailurePolicy` carry the lookup's error type, so `onDegraded` receives a `Cause` of that error rather than of `unknown`. Both type parameters default to `unknown`, so existing annotations still compile.
