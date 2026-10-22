---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-client": patch
---

**Security — verifying an address no longer hands the verifier an account whose password someone else chose (#425).** The first time `AuthLifecycleService.verifyEmail` verifies an address (`POST /email-verification/verify`), it clears the account's password and revokes all of its sessions before marking the address verified. Until then no one had proven they own the address, so an attacker could sign up with a victim's address and a password they know, and the victim's later verification (from the attacker's sign-up email, a re-send, or the victim's own recovered sign-up) left the attacker able to sign in. The verifier now sets a password afterwards, with `EmailPasswordService.setPassword` from the session the verification issues (with `autoSignInAfterVerification`, the default) or through a password reset. Verifying an address already verified changes neither.

This applies to every first verification, the account's real owner included: after verifying, a user who signed up with a password has none until they set one, and any session they held before verifying is signed out.

**Breaking — `EmailPasswordStore` gains a required `clearPasswordHash(userId)`**, which removes the user's password so `getPasswordHash` returns `null` (a no-op when there is none). `EmailPasswordService` gains `clearPassword(userId)` over it. effect-auth-sql's `EmailPasswordStore` implements it (`password_hash = NULL`); the effect-auth-client `./testing` server implements it in memory.

**The recovered sign-up acts on the address the `beforeSignUp` hooks returned (#426).** With `antiEnumeration` off, a sign-up for an address held unverified looks the holder up by the address `EmailPasswordService.signUp` found taken, not the raw submitted one, and answers with that address as its `identifier`. `EmailInUseError` carries that address as an optional `email` (never sent over HTTP); `AccountManagementService`'s change-email sets it too.
