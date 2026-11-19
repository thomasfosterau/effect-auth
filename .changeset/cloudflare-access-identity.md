---
"@thomasfosterau/effect-auth": minor
---

Add `CloudflareAccess`, a verifier for the identity Cloudflare Access forwards. `CloudflareAccessVerifier` checks the `Cf-Access-Jwt-Assertion` header (and, opt-in, the `CF_Authorization` cookie) against the team's key set: RS256 only, a published `kid`, the team's `iss`, the application's AUD tag in `aud`, and `exp` / `nbf` within a clock tolerance. Keys are cached and refetched on rotation at most once per interval. `findUser` maps a verified user identity to the owner of a verified email identifier, and `userContextLayer` provides it as `CurrentUser`, `CurrentPrincipal` and `CurrentCredential` (service tokens are `machine`).
