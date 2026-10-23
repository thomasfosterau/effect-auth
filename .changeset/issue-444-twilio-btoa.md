---
"@thomasfosterau/effect-auth-twilio": patch
---

Build the Basic auth header with `btoa` instead of the Node `Buffer` global, so the sender runs on Workers without `nodejs_compat`.
