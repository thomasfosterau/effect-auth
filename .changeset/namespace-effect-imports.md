---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-sveltekit": patch
---

Import every Effect module from its own entry point (`effect/Effect`, `effect/Layer`, …) rather than the `effect` barrel. The emitted `dist/` and `.d.ts` change their import specifiers only; no API or behaviour changes.
