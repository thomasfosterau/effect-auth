---
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-sveltekit": patch
"@thomasfosterau/effect-auth-twilio": patch
"@thomasfosterau/effect-auth": patch
---

Import Effect's helper modules (`Array`, `Option`, `Predicate`, `Record`, `Schema`, `String`) from their own entry points (`effect/Array`, …) rather than the `effect` barrel. The emitted `dist/` and `.d.ts` change their import specifiers only; no API or behaviour changes.
