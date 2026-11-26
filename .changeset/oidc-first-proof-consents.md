---
"@thomasfosterau/effect-auth": patch
---

The first proof of an email address now deletes the consents the account's earlier holder gave OIDC clients (`OidcConsentStore.deleteByUserId`), beside its OIDC tokens, so a client asks the prover for consent again instead of inheriting it. `FirstProofCredentials` gains `oidcConsents`, which `firstProofServices` resolves from the context when an `OidcConsentStore` is there.
