---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-sveltekit": patch
"@thomasfosterau/effect-auth-twilio": patch
---

The `effect` peer range is now `^4.1.0` (was `>=4.1.0`), and effect-auth-alchemy-postgres's `@effect/sql-pg` peer is `^4.1.0` too. The floor is unchanged: the packages need `effect/crypto`, which first shipped in Effect 4.1. The caret form stops the range from claiming a future Effect 5 it was never tested against.
