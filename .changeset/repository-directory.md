---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-svelte": patch
---

The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
