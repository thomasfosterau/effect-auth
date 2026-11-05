---
"@thomasfosterau/effect-auth-sveltekit": minor
---

`credentialAction` no longer redirects on a `202 Accepted`, which the auth handler answers when it issued no session: a second factor is pending, the address must be verified first, or a sign-up ran under `antiEnumeration` (#497). It returns a `CredentialPending` (`{ kind: "pending", secondFactor, needsEmailVerification, fields }`) as the action's data, carrying the challenge's `token` and `expiresAt` when a second factor is pending, so the form can show its code step or a check-your-inbox step. A `202` whose body is not the handler's pending document reports as `unavailable`. Any other 2xx still relays `Set-Cookie` and redirects. The action's return type is now `Promise<Failure | CredentialPending<Fields>>`.
