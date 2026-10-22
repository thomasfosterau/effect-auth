---
"@thomasfosterau/effect-auth": minor
---

**Security — magic link, email OTP, Google One Tap and SSO no longer hand the prover an account whose password someone else chose (#440, following #425).** Each of these flows promotes an email address held unverified to verified when the caller proves it (the link, the code, or the IdP's verified email claim), then signs the caller in. That address's account was created by a sign-up that proved nothing about it, so a squatter who signed up with someone else's address and a password they know kept that password, and their sessions, once the real holder signed in this way. Now, as `AuthLifecycleService.verifyEmail` does since #425, the first proof of an address clears the account's password and revokes all of its sessions before marking the address verified. Signing in to an account whose address is already verified changes nothing.

**Breaking — `EmailPasswordStore` is now required** by `MagicLinkService`, `EmailOtpService` and `GoogleOneTapService` (at layer construction) and by `SsoService`'s callback methods (in their context), to clear the password. An app that runs one of these flows must provide an `EmailPasswordStore`: effect-auth-sql's `makeEmailPasswordStore`, or the app's own, with the `clearPasswordHash` that #425 added.
