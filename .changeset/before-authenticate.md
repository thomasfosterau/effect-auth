---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#592):** username, email OTP, phone OTP, magic-link and second-factor sign-ins now run the lockout, captcha and rate-limit plugins, and account lockout clears only when a session is issued. Before, only email-and-password sign-in fired `beforeSignIn`, the hook those plugins guarded, so `UsernameService.signIn` (and `POST /sessions` with `method: "username"`) could guess a password with no lockout, per-account limit, per-IP limit or captcha; and a correct password that earned only a second-factor challenge reset the lockout counter, so an attacker holding the password could guess TOTP codes without ever being locked out.

A new hook point, `beforeAuthenticate`, runs in every credential-verifying flow (email and password, username, email OTP, phone OTP, magic link, and the TOTP, backup-code and OTP second factors), after the handle is resolved to a user and before the credential is checked or a code, link or challenge is spent. Its input is `AuthenticateAttempt`: `{ method, identifier: { type, value }, userId?, captchaToken? }`. `authenticationSubject(attempt)` gives the per-account key: `user:<id>` for a resolved handle, else `<type>:<value>`. `beforeSignIn` stays, for rewriting an email-and-password sign-in's input.

**Breaking:**

- `AccountLockoutPlugin`, `CaptchaPlugin`, `RateLimitPlugin` and `IPRateLimitPlugin` hook `beforeAuthenticate` instead of `beforeSignIn`. A test or a custom flow that drove them through `hooks.beforeSignIn` must call `hooks.beforeAuthenticate`.
- `AccountLockoutPlugin` keys its counters on the account (`lockout:user:<id>`, or `lockout:<type>:<value>` for a handle no account holds) instead of the email (`lockout:<email>`), so counts stored under the old keys are ignored and lapse. It clears them in `afterCreateSession` (any session issued for the user) instead of `afterSignIn`, and no longer on a sign-in that returned only a second-factor challenge. A lock now refuses every method of the account, a magic link and a one-time code included. A new per-user second-factor count (`lockout:second-factor:user:<id>`, `maxSecondFactorAttempts`, default 5) runs across challenges and refuses second-factor redemption with `AccountLockedError` while locked.
- `RateLimitPlugin` keys its bucket on `signin:<subject>` instead of `signin:<email>`, and draws second-factor redemptions from `second-factor:<subject>` under `RateLimitPresets.totpVerification`.
- `IPRateLimitPlugin`'s `signin` bucket now counts every first-factor method, and second-factor redemptions draw on a new `second-factor` bucket (`secondFactor` option, default `RateLimitPresets.totpVerification`). Without a client address, these flows are refused with `RateLimitError` too.
- `CaptchaPlugin`'s `"signIn"` endpoint also guards username sign-in, which now needs a token: `UsernameSignInInput.captchaToken`, the `captchaToken` attribute on the `username` sign-in credential and `UsernameSignInPayload`, and `captchaToken` on the client's `signInUsername`.
- `EmailOtpService`, `PhoneOtpService`, `MagicLinkService`, `MultiFactorService` and `OtpSecondFactorService` now require `Hooks` when their layers are built.
- The `Hooks` service has a new member, `beforeAuthenticate`: a hand-written `typeof Hooks.Service` implementation must add it.
