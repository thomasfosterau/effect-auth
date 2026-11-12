---
"@thomasfosterau/effect-auth": minor
---

`redeemOneTimeTokenForSession` now refuses a token whose subject `UserStore` no longer finds (a deleted user), with the same `OneTimeTokenError` as an unknown token, instead of minting a session for it; it therefore requires `UserStore` (which `SessionService.layer` already needs). The "Deleting a user" README section now lists one-time tokens and by-email organization invitations among the records left to expire, and says what happens to a store missing from the deleting layer's context and to a deletion that fails after the identifiers are gone (#601).
