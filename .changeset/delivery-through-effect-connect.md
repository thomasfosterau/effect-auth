---
"@thomasfosterau/effect-auth": minor
---

Delivery now goes through [effect-connect](https://github.com/thomasfosterau/effect-connect). The core depends on `@thomasfosterau/effect-connect`, and `EmailSender.layerConnect({ from, render? })` / `SmsSender.layerConnect({ from?, render? })` (and `fromConnect`) build the seams over any effect-connect `EmailService` / `SmsService`; a provider failure is an `AuthError` carrying the provider's error as `cause`. `defaultEmailRender` and `defaultSmsRender` are the purpose-keyed fallback renderers, and `RenderedEmail`, `ConnectEmailSenderConfig` and `ConnectSmsSenderConfig` are exported.

`@thomasfosterau/effect-auth-resend` and `@thomasfosterau/effect-auth-twilio` are discontinued and get no further releases. Replace `Resend.layer({ apiKey, from, render })` with `EmailSender.layerConnect({ from: { email, name }, render })` over `@thomasfosterau/effect-connect-resend`'s `layer({ apiKey })`, and `Twilio.layer({ accountSid, authToken, from, render })` with `SmsSender.layerConnect({ render })` over `@thomasfosterau/effect-connect-twilio`'s `layer({ accountSid, authToken, from })`, providing `FetchHttpClient.layer` beneath them.
