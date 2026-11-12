---
"@thomasfosterau/effect-auth": minor
---

**Security fix (#678):** an account lock no longer blocks magic-link and one-time-code recovery, the captcha now guards the code and link sends, unknown challenges and tokens count against the per-IP limit, passkey sign-in and `EmailOtpService.check` run the `beforeAuthenticate` gate, and an admin impersonation no longer clears the target's lockout.

- **Lock scope.** `AccountLockoutPlugin` exempts the possession proofs (email OTP, phone OTP, magic link; `isPossessionMethod`) from its account lock: it neither refuses them nor counts them. Before, anyone who knew a handle could lock its owner out of passwordless recovery for `lockoutDurationMs`. Their guesses stay bounded by the per-code `maxAttempts`, the per-address failure backoff (#590), 256-bit magic-link tokens and the rate limits. A session one of them issues clears the lock, as any session the user earns does.
- **Captcha on sends.** A new hook point, `beforeSendCode` (`SendCodeAttempt`: `{ method, purpose, address, captchaToken? }`), runs at the start of `EmailOtpService.send`, `PhoneOtpService.send` and `MagicLinkService.send`, before the address is looked up. Each send takes `SendCodeOptions` (`{ captchaToken? }`) as a new last argument; `POST /otp-challenges` takes a `captchaToken` attribute on every channel and answers `400` when the captcha refuses; the client's `magicLink.send`, `emailOtp.send` and `phoneOtp.send` take `captchaToken`. `CaptchaPlugin` has a new `"sendCode"` endpoint, which guards that hook.
- **Unkeyed attempts.** An unknown or expired second-factor challenge (TOTP, backup code, OTP second factor), magic-link token or passkey challenge, and an unknown passkey credential, now fire `beforeAuthenticate` with no `identifier` before failing, so `IPRateLimitPlugin` counts them. The per-account plugins let such an attempt through.
- **Coverage.** `EmailOtpService.check` (every purpose, method `"email-otp"`) and `WebAuthnService.verifyAuthentication` (new method `"passkey"`, keyed on the credential's user, before the signature is checked) fire `beforeAuthenticate`.
- **Impersonation.** `AccountLockoutPlugin` leaves the counts standing when `AdminService.impersonateUser` issues a session; a new `isImpersonationSession(session)` names such a session (`attributes.impersonatedBy`).

**Breaking:**

- `CaptchaPlugin`'s default `endpoints` is now `["signUp", "signIn", "sendCode"]`: with the defaults, every code and link send needs a `captchaToken` that verifies. Pass `endpoints: ["signUp", "signIn"]` to keep the sends unguarded.
- `AuthenticateAttempt.identifier` is optional (absent for an unkeyed attempt), and `authenticationSubject` returns `string | undefined`. A custom `beforeAuthenticate` plugin that reads either must handle the unkeyed case.
- `AuthenticationMethod` adds `"passkey"`. A plugin that matches on the method exhaustively must handle it.
- `WebAuthnService.layer` / `make` require `Hooks` (provide `Hooks.Default` for no plugins), and `verifyAuthentication` can fail with a `HookError`.
- `EmailOtpService.check` and the three sends can fail with a `HookError`, and a hand-written `Hooks` implementation needs `beforeSendCode`.
- `AccountLockoutPlugin` no longer locks out or counts email OTP, phone OTP and magic-link attempts.
