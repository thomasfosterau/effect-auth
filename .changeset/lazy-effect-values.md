---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** zero-argument members and exports that only returned an Effect or a Layer are now that Effect or Layer. Drop the call:

- Store members: `AnonymousUserStore.createAnonymousUser`, `JwtKeyStore.getActive` and `list`, `OidcClientStore.list`, `PolicyStore.listPolicies` and `listTemplates`, `SsoProviderStore.list`. A custom store implements them as Effects, for example `list: Effect.sync(() => [...rows])`.
- Service members: `GoogleOneTapService.createNonce`, `JwtService.getJwks`, `OidcProviderService.listClients`.
- Exports: `RateLimit.make`, `OAuth.generateState`, `generatePKCE` and `generateNonce`, `Observability.recordSessionCreated`, `recordSessionInvalidated` and `recordMultiFactorChallenge`, and, from `./http`, `otpChallengesGroupLayer`, `passwordResetsGroupLayer`, `googleOneTapNoncesGroupLayer` and `scimGroupLayer`.
