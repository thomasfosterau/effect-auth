---
"@thomasfosterau/effect-auth": minor
---

Security fix (#591): WebAuthn challenges are bound to their ceremony, user verification is enforced, and registration stores the attested credential.

- **Ceremony binding.** `WebAuthnChallenge` gains a required `ceremony: "registration" | "authentication"` (`Auth.MultiFactor.WebAuthnCeremony`, with `isWebAuthnCeremony`). `verifyRegistration` refuses an authentication challenge and `verifyAuthentication` a registration one, so a user-bound login challenge can no longer be answered with an attestation that registers an attacker's key on the victim's account. A stored challenge with no known ceremony reads as `null`, so challenges in flight at upgrade must be reissued.
- **`verifyRegistration(userId, challenge, response)`** now takes the signed-in user's id first (from the session, never the request) and refuses a challenge issued to anyone else; the credential is filed under that id.
- **User verification.** `userVerification: "required"` is enforced in both ceremonies: a response without the UV flag is refused. `RegistrationResult` and `AuthenticationResult` report `userVerified`, `backupEligible` and `backupState` (`AuthenticatorFlags`); `RegistrationResult.verified` is replaced by `userVerified`. A backup state on a credential that is not backup eligible is refused.
- **Registration storage.** The stored credential id is the one inside the attestation, which must equal `response.credentialId`, and an id already registered (to any user) is refused rather than overwritten.
- **Smaller checks.** A `clientDataJSON` with `crossOrigin: true` is refused, an ES256 key must be on P-256, and a malformed public key fails with `WebAuthnVerificationError` instead of a defect.
- **Stores.** `ChallengeStoreKV` persists the ceremony. `./sql` keeps it in a new table, `auth_webauthn_challenge_ceremonies` (run `migrate`; D1 and Alchemy Postgres deployments pick it up through `AuthSchema`), and `ChallengeStore.delete` now runs in a transaction. `./testing` adds `challengeStoreConformance`.

Migration: pass the session's user id as the first argument of `verifyRegistration`; read `userVerified` instead of `verified`; a custom `ChallengeStore` must store and return `ceremony` (check it with `Testing.challengeStoreConformance`).
