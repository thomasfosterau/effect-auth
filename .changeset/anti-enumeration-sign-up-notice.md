---
"@thomasfosterau/effect-auth": patch
---

With `EmailPasswordConfig.antiEnumeration` and email verification on, `AuthLifecycleService.signUp` stores a verification record, runs the `beforeCreateVerification` and `afterCreateVerification` hooks and sends a verification link only for a fresh sign-up (#422). A sign-up for an address another user holds is answered by a stand-in user that no row backs, so it gets none of these: the address's holder is never sent a link that can't verify.

The optional `AuthLifecycleConfig.sendExistingAccountNotice` sends that holder a notice that someone tried to sign up with the address, so each of the two answers makes one send. `emailCallbacks(...).sendExistingAccountNotice` derives it from an `EmailSender`, under the `"existing-account"` delivery purpose, off the response path like the other derived callbacks. A failed notice fails the sign-up with the same `EmailVerificationError` a failed verification send does. Without the option, such a sign-up sends nothing.
