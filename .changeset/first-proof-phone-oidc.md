---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#704):** the first proof of an email address now also removes the phone numbers and OIDC-provider tokens the account's earlier, unproven holder could still use. Before, someone who signed up with an address they did not own kept two ways back in after its real holder proved it: a phone number they had added, which signs in with a phone one-time code, and the access and refresh tokens the core's OIDC provider had issued them (a refresh token mints new access tokens).

`proveAddress` now deletes the account's unverified phone identifiers (through `IdentifierStore.listByUser` and `delete`) and, when the layer's context provides an `OidcTokenStore`, every access and refresh token issued to the user, before its sessions are revoked as before. A phone number the account already verified stays: its holder proved it. JWTs already issued (`Jwt`) cannot be revoked and expire on their own. An address that is already verified keeps everything, as before.

`OidcTokenStore` gains a required `deleteByUserId(userId)`, which deletes every token issued to the user for every client; a custom `OidcTokenStore` must implement it. `Testing.memoryOidcTokenStore` implements it.
