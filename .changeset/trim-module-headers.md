---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-alchemy-cloudflare": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-svelte": patch
"@thomasfosterau/effect-auth-sveltekit": patch
---

Shorten the module doc comments to a few lines each. Consumer detail they held now sits on the export it describes: the `SamlVerifier` checks, what a `defineSchema` table must satisfy, and runnable examples on `Guard.requireSystem`, `OwnedAccess.make`, `Delivery`, `TrustedDevice`, `Messages`, `OrganizationEntities` and `RateLimitPersistence`.
