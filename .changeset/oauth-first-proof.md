---
"@thomasfosterau/effect-auth": minor
---

**Security — OAuth sign-in proves an unverified address on the provider's verification, as Google One Tap and SSO do (#671).** One policy now holds for every IdP-backed sign-in: the first-proof rule (#440). When a first `OAuthService.signInWithCallback` sign-in's provider-verified email matches an existing user whose email identifier is still unverified, the provider's verification is the address's first proof. The flow runs `proveAddress`: it clears the account's password, revokes all of its sessions and marks the address verified, and only then links the provider identity and mints the signed-in user's session. A squatter who signed up with someone else's address and a password keeps nothing, and the address's real holder gets in without proving the address another way first.

A verified local address still links only under the #588 rules: the provider reports `email_verified: true`, and `autoLinkByVerifiedEmail` (default `true`) or a `trustedProviders` entry applies. Without auto-linking for the provider the match fails with `EmailInUseError` and changes nothing, whether the local address is verified or not. An unverified provider email never links and never takes over an address.

**Breaking:**

- `signInWithCallback` no longer refuses a provider-verified match on an unverified local address with `EmailInUseError` (the #588 behaviour); it takes the address over, clearing the earlier sign-up's password and sessions.
- `OAuthService.layer` and `OAuth.make` now require `EmailPasswordStore` (for `clearPasswordHash`). `Testing.memoryStores`, `@thomasfosterau/effect-auth/sql`'s `layer` and the other storage adapters provide it; an application that composes its stores by hand adds one.

ADR-0007's amendment gains a #671 note.
