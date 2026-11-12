---
"@thomasfosterau/effect-auth-svelte": minor
---

`MagicLinkForm` and `EmailOtpForm` take a `captchaToken` getter (`SendCaptchaProps`), read when the form submits and sent with the code or link request (#698). Released together with the core's captcha on sends (#678), which `CaptchaPlugin` turns on by default: pass `captchaToken={() => widgetToken}` when the server's `CaptchaPlugin` guards sends.
