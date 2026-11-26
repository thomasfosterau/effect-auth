---
"@thomasfosterau/effect-auth": patch
---

A replayed OIDC refresh token now revokes its family the same way a lost rotation race does, revocation marker first, so a rotation still in flight when the replay arrives loses its new tokens too.
