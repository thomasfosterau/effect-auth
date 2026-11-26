---
"@thomasfosterau/effect-auth": minor
---

Breaking for bring-your-own `OidcTokenStore`s: refresh-token reuse detection now lives in the store, and grants are revoked when their user or client goes.

- A rotated refresh token leaves a `kind: "rotated"` record in the `OidcTokenStore` (under a key derived from its digest, expiring with the family), replacing the per-process map. Presenting it again revokes the whole family on any instance and after a restart.
- `OidcTokenStore` drops the optional `listByFamily` and gains two required methods: `deleteByFamily(familyId)` and `deleteByClientId(clientId)`. `Testing.oidcTokenStoreConformance` checks both.
- Every access token carries its grant's `familyId`, so a detected replay revokes the family's access tokens too.
- Every code and refresh grant loads the user, including a refresh down-scoped to drop `openid`. A user who is gone, banned or SCIM-deactivated gets `invalid_grant`, and `/oauth2/userinfo` refuses their access tokens. A refused banned or deactivated user's OIDC tokens are deleted, so a lapsed ban restores none.
- `/oauth2/userinfo` refuses an access token whose client is disabled or deleted, and `deleteClient` deletes the client's tokens.
- Discovery no longer advertises `end_session_endpoint`, which no route served.
- `/oauth2/token` answers Basic credentials with a malformed percent-escape as `invalid_client` (401) instead of a 500.
