---
"@thomasfosterau/effect-auth": minor
---

Harden the OAuth client and fix the presets that read an email address.

- A provider profile with no account id now fails with `OAuthProviderError` instead of becoming the account `(provider, "")`.
- `verifyIdToken` requires a numeric `exp` and a JWKS key of the header's algorithm (`RSA` for RS256, `EC` P-256 for ES256, `OKP` Ed25519 for EdDSA, and a matching `alg` when the key declares one). New `Cipher.jwkSuitsAlgorithm` is the check.
- A provider with `getUserInfoFromIdToken` must set `issuer`; without it, every sign-in fails.
- `GoogleProvider` reads Google's `verified_email`, so a Google-verified address auto-links. `MicrosoftProvider` maps Graph's `mail` (else an address-shaped `userPrincipalName`) and `displayName`, unverified. `GitHubProvider` takes the primary address and its verification from `/user/emails`, so a private address works. A string `email_verified` (Apple's `"true"`) reads as a boolean.
- `TwitterProvider`, `RedditProvider`, `TikTokProvider` and `RobloxProvider` are documented as link-only: they return no email, so they link to a signed-in account and then sign it in, but never create one.
