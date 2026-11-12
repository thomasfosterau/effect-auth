---
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-svelte": patch
"@thomasfosterau/effect-auth-sveltekit": patch
"@thomasfosterau/effect-auth-twilio": patch
---

**Security hardening (#631):** every adapter now depends on `@thomasfosterau/effect-auth` through a caret range (`^0.x.y`) instead of an exact pin. A consumer who upgrades the core within a minor (say, for a security patch) gets one copy of it, and no adapter keeps running a nested, unpatched core of its own. Under 0.x a caret range covers one minor, so the adapters are released with every core minor.

**effect-auth-drizzle (#635):** the `drizzle-orm` peer range is bounded to the tested lines, `>=0.44.0 <0.46.0 || >=1.0.0-rc.5 <2`, and a new drizzle minor joins it once CI has run against it. The unused optional `@types/pg` peer is dropped.
