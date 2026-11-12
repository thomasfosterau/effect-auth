---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#694):** the first proof of an email address now removes every credential the account held, not only its password and sessions. Before, someone who signed up with an address they did not own and then linked an OAuth provider that reports emails unverified, registered a passkey, minted an API key or enrolled a second factor kept that access after the address's real holder proved it.

When a flow promotes an unverified email identifier to verified on a proof (the verification link, a magic link, an email OTP, an invitation token, or a provider-verified email through OAuth, Google One Tap or SSO), the account's linked OAuth accounts (`OAuthAccountStore`), passkeys (`CredentialStore`), API keys (`ApiKeyStore`), multi-factor enrolment (`MultiFactorStore`: the TOTP secret and backup codes) and trusted devices (`TrustedDeviceStore`) are deleted before its sessions are revoked. Each store is optional: a store the layer's context does not provide is skipped. The holder enrols their own credentials afterwards. In the OAuth sign-in, the provider link being made is created after the sweep and survives it. An address that is already verified keeps everything, as before.

`AuthLifecycleService.verifyEmail` now goes through the same first-proof path as the other flows. `OAuthAccount` and `OAuthAccountStore` moved to their own module; `@thomasfosterau/effect-auth/oauth` and the root `Auth.OAuth` namespace export them as before.
