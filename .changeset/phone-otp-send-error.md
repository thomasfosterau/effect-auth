---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** `PhoneOtpConfig.sendOtp` now fails with `AuthError | PhoneOtpError`, not `unknown`. `smsCallbacks(...).sendPhoneOtp` already does. A custom sender that fails with another error maps it first, for example with `Effect.mapError((cause) => new PhoneOtpError({ message: "SMS send failed", cause }))`.
