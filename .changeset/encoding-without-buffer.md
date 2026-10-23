---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-resend": patch
---

Drop the remaining Node `Buffer` uses in the OAuth module and the SQL stores, in favour of `effect/encoding`, `Schema`'s base64 codecs and `TextEncoder`, so they no longer rely on a Node global in Workers and browsers. `RenderedEmail.html` and `.text` in effect-auth-resend are now `?: string | undefined`, so a renderer can forward an optional value under `exactOptionalPropertyTypes`.
