---
"@thomasfosterau/effect-auth": patch
---

Email OTP and phone OTP verification answer an address with and without an account alike where `send` hides which addresses have one: sign-in with `disableSignUp`, and email OTP `forget-password` (#417).

- In those configurations, every code that fails verification answers `Invalid or expired OTP`, whether the code is wrong, has expired or has reached `maxAttempts`, so `/sign-in/email-otp` and `/sign-in/phone-otp` return the same 400 body for every address. The reason is recorded on the `signIn` / `check` span as `auth.otp.failure`. Everywhere else, an expired code answers `OTP has expired` and the attempt limit answers `Too many attempts`.
- In the same configurations, and in magic-link sign-in with `disableSignUp`, `send` stores an undelivered marker record for an address with no account whether or not `resendCooldown` is set, so a known and an unknown address get the same store work. An OTP marker expires and counts attempts exactly as a code's record does, and no code redeems it.
