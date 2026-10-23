---
"@thomasfosterau/effect-auth-client": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Widen the optional option fields to `?: T | undefined` so callers under `exactOptionalPropertyTypes` can forward their own optional values: `AuthClientOptions` (`fetch`, `headers`, `refresh`) and `RefreshOptions` (`intervalMs`, `onFocus`, `crossTab`) in the client, and the `render` / `baseUrl` / `fetch` fields of `ResendEmailSenderConfig` and `TwilioSmsSenderConfig`.
