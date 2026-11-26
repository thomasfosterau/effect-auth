---
"@thomasfosterau/effect-auth": minor
---

WebAuthn credentials keep their backup flags and AAGUID. `WebAuthnCredential` gains `backupEligible`, `backupState` and `aaguid` (a lowercase hyphenated UUID), set at registration. `verifyAuthentication` refuses an assertion whose backup eligibility differs from the stored one (WebAuthn Level 3 §6.1.3) and records the backup state on each sign-in; a credential stored before the flags were has them recorded by its next sign-in.

Breaking for a `CredentialStore` you implement: it must persist the three fields, which `Testing.credentialStoreConformance` now checks. `./sql` keeps them in a new table, `auth_webauthn_credential_flags`, which `migrate` creates, so D1 and Alchemy Postgres deployments get it the same way.
