---
"@thomasfosterau/effect-auth": patch
---

Share the error mapping that repeated across the legacy session endpoints and sign-in services. An SSO callback refused by a rate limit now answers its `429` with the `RATE_LIMIT_EXCEEDED` code, as every other sign-in does; nothing else changes.
