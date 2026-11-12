---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

Deleting a user now deletes everything the account holds (#601). `AccountManagementService.confirmAccountDeletion`, `AdminService.removeUser` and `AnonymousService.linkAccount` run one purge: every user-keyed credential and token store present where the service's layer is built deletes that user's rows (OAuth links and their provider tokens, passkeys, API keys, the TOTP enrolment and backup codes, trusted devices, OIDC-provider tokens and consents, pending password resets, email verifications and account-management tokens), then the sessions are revoked, then the identifiers are deleted (`removeUser` used to leave them, so the address stayed claimed), and the user row goes last, so a failure leaves the user rather than rows naming a missing one. No foreign keys are added; wrap the call in your stores' transaction (`sql.withTransaction` on `./sql`) to make it atomic. `ApiKeyService.verify` and `verifyWithRateLimit` now answer `Invalid API key` for a key whose owner no longer exists.

Breaking for bring-your-own stores and for layer wiring:

- `ApiKeyStore`, `OAuthAccountStore`, `MultiFactor.CredentialStore` and `OidcConsentStore` gain a required `deleteByUserId(userId)`, which deletes that user's rows only (a no-op for a user with none). `MultiFactorStore.delete(userId)` is its per-user delete, unchanged.
- `ApiKeyService` requires `UserStore`. `Testing.apiKeyServiceLayer` takes `users` (seed the owners of the keys a test verifies) and provides `UserStore`.
- `UserService.deleteUser` still deletes the user row only, and is documented as not an account deletion.
- `./sql`: `UserServiceStore.delete` also deletes the user's `auth_user_roles` rows, in one transaction; the API key, OAuth account and passkey stores implement `deleteByUserId`.
- `./testing`: `memoryStores` also provides `UserServiceStore`, `CredentialStore` and `AccountManagementStore` (`memoryUserServiceStore`, `memoryCredentialStore`, `memoryAccountManagementStore`), and new conformance suites check every per-user delete: `oauthAccountStoreConformance`, `credentialStoreConformance`, `multiFactorStoreConformance`, `trustedDeviceStoreConformance`, `oidcTokenStoreConformance`, `oidcConsentStoreConformance`, `emailVerificationStoreConformance`, `passwordResetStoreConformance`, `accountManagementStoreConformance`, and a case in `apiKeyStoreConformance`.

`@thomasfosterau/effect-auth-drizzle`: `ApiKeyStore` implements `deleteByUserId` (one `DELETE`), as the core contract now requires.
