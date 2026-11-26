---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-svelte": minor
---

`CaptchaPlugin` checks what a token was minted for, not only `success: true`: new options `expectedHostname` (one or several), `expectedAction` (one, or one per endpoint) and `minScore` (0 to 1), and `recaptchaVersion: 2 | 3`. reCAPTCHA v3 answers `success: true` for every genuine token, bots included, so `recaptchaVersion: 3` without `minScore` makes the layer build die with the new `CaptchaConfigError`, and a token carrying a `score` that no `minScore` judges is refused. The siteverify answer is decoded with `Schema`, and the client address goes along as `remoteip` when the request has one.

`PasswordResetService.requestPasswordReset(email, options?)` fires `beforeSendCode` (`method: "password-reset"`, the new `SendCodeMethod`) with `options.captchaToken`, before the address is looked up, so `CaptchaPlugin`'s `"sendCode"` endpoint now guards password-reset requests too. `POST /password-resets` takes an optional `captchaToken` attribute and answers `400` when the captcha refuses, and the client's `passwordResetRequest` takes `captchaToken`. With the default endpoints, a client that sends no token on a password-reset request is now refused: pass one, or leave `"sendCode"` out of `endpoints`.

`PasswordResetRequestForm` takes the `captchaToken` getter `MagicLinkForm` and `EmailOtpForm` take, and sends its token with the request.
