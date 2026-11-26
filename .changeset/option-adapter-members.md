---
"@thomasfosterau/effect-auth-sveltekit": minor
"@thomasfosterau/effect-auth-drizzle": minor
"@thomasfosterau/effect-auth-argon2": minor
"@thomasfosterau/effect-auth-alchemy-cloudflare": minor
---

**Breaking:** options objects spell an optional member `readonly x?: T`, without `| undefined`, as in the core. Under `exactOptionalPropertyTypes`, a caller holding a value that may be `undefined` leaves the key out instead of passing `x: undefined`. This covers the SvelteKit `handle` and credential-action options, the Drizzle column maps and store options, the Argon2 cost options and the D1 client's `spanAttributes`.
