---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-sql": patch
---

Export the `EmailAddress`, `Attributes` (from the HTTP schemas) and `ApiKeyRateLimit` types alongside their schemas. effect-auth-sql mints row ids with `globalThis.crypto.randomUUID()` instead of importing `node:crypto`.
