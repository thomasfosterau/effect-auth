---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#684):** every unauthenticated send is capped per recipient, so clients spread across many addresses can no longer flood one email address or phone number with codes and links (email bombing, SMS toll fraud).

- **The cap.** `EmailOtpService.send`, `PhoneOtpService.send`, `MagicLinkService.send`, `PasswordResetService.requestPasswordReset` and `EmailVerificationService.resendVerification` allow at most 5 sends per recipient and purpose an hour by default. A new `recipientSendLimit` option on each service's config (`RecipientSendLimit`: `{ max, windowMs }`) changes it, and `false` turns it off. A send past it fails with `RateLimitError` (`429` over HTTP, `retryAfter` set to what is left of the window). The cap comes on top of the `resendCooldown`s and the OTP failure backoff, and counts only the sends they let through. `PhoneOtpService`'s `phone-verification` sends count too.
- **No enumeration.** The cap counts a request whether or not the address has an account, so an unknown address is refused exactly as a known one. `POST /email-verifications` and the `AuthLifecycleService` sign-in and duplicate sign-up resends answer a capped resend as they answer any other, as they do inside the cooldown.
- **Storage.** The counts go through the existing `RateLimitStore`, under `recipient-send:<purpose>:<digest>` keys, where the digest is `hashToken` of the normalized address: no raw address is stored. The five services therefore now require a `RateLimitStore` in their layer's context. `layerKV`, `./sql`'s `layer` and `Testing.memoryStores` already provide one; a hand-built composition adds one (`RateLimitStoreKV` over a `KeyValueStore`, for example). `Testing.memoryRateLimitStore` is a map-backed one for tests.
