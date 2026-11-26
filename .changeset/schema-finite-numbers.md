---
"@thomasfosterau/effect-auth": patch
---

The HTTP tier's schemas, the session cookie cache, the CAPTCHA answer and policy attribute values decode numbers with `Schema.Finite`, so `NaN` and the infinities (and their string encodings) are refused, and the OpenAPI document describes those fields as plain JSON numbers.
