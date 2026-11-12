---
"@thomasfosterau/effect-auth": minor
---

**Security (#698), released together with #678's captcha on sends:** passkeys are exempt from `AccountLockoutPlugin`'s account lock, as the one-time codes and magic links are. A WebAuthn assertion is a signature nobody can guess, and a credential id is not secret, so counting passkey attempts let anyone who holds one lock the account. Passkey verification still counts against `IPRateLimitPlugin` and `RateLimitPlugin`. `PhoneOtpService.verifyPhoneNumber` now fires `beforeAuthenticate` (method `phone-otp`, keyed on the signed-in user) before the code is checked.
