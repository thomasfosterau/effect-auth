---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-argon2": patch
"@thomasfosterau/effect-auth-client": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-react": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-saml": patch
"@thomasfosterau/effect-auth-solid": patch
"@thomasfosterau/effect-auth-sql": patch
"@thomasfosterau/effect-auth-svelte": patch
"@thomasfosterau/effect-auth-twilio": patch
"@thomasfosterau/effect-auth-vue": patch
---

Publish from the library tooling standard (#222). Every package now takes its dependency versions
from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
published by `pnpm publish` through npm OIDC trusted publishing, so every tarball carries a
provenance attestation. The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
(`build`, `test:unit`, `check`), so the published manifests no longer carry them.
