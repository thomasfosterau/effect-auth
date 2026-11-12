---
"@thomasfosterau/effect-auth": minor
---

**Security — OAuth sign-in no longer auto-links to an account whose email is unverified (#588).** `OAuthService.signInWithCallback` linked a new provider identity to the user holding its email whenever the provider reported the email verified, without checking whether the local address was verified. A squatter who signed up with someone else's address and a password (email verification is off by default) got the victim's provider account linked to theirs on the victim's first OAuth sign-in, with the squatter's password and sessions still valid. With `trustedProviders`, the link happened even when the provider reported `email_verified: false`.

Now a first OAuth sign-in whose email matches an existing user is linked only when the provider reports `email_verified: true`, the local email identifier is verified, and auto-linking applies to the provider. `autoLinkByVerifiedEmail` still defaults to `true`. Every other match fails with `EmailInUseError` (a conflict) and changes nothing: no account is linked, no session is minted and the existing account keeps its password and sessions.

**Breaking:**

- `trustedProviders` no longer waives the provider's `email_verified` claim. It now means "auto-link this provider even with `autoLinkByVerifiedEmail: false`", under the same verified-match rule.
- `signInWithCallback` refuses a claimed email with `EmailInUseError` (its error channel gains it) instead of `AuthError`, including when the user store reports the address taken while the user is being created. Code that caught the `AuthError` for this case catches `EmailInUseError`.
- The real holder of an address someone signed up with unverified cannot use OAuth sign-in until that account is removed or the address is proven another way: the verification link, a magic link or an email OTP, which clear the earlier sign-up's password and sessions.

ADR-0007 is amended to describe this behaviour.
