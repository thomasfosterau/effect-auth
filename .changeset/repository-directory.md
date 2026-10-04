---
"@thomasfosterau/effect-auth-client": patch
"@thomasfosterau/effect-auth-react": patch
"@thomasfosterau/effect-auth-solid": patch
"@thomasfosterau/effect-auth-svelte": patch
"@thomasfosterau/effect-auth-vue": patch
---

The package manifest sets `repository.directory`, as the other effect-auth packages already do, so npm resolves the README's relative links against the package's own directory rather than the repository root, and they no longer 404 on npmjs.com (#265).
