---
"@thomasfosterau/effect-auth": patch
---

A provider response body that can't be read or isn't what it must be now fails with `OAuthProviderError` instead of dying. That covers a non-JSON 2xx token, user info, JWKS or OIDC discovery body, and a failed read of an error body. The token endpoint's response (code exchange and refresh) is decoded rather than cast: `access_token` is required, `expires_in` may be a number or a numeric string, `scope` a string or an array (joined with spaces), optional members may be `null`, and a missing `token_type` reads as `Bearer`. A 2xx token body without `access_token` is now refused instead of flowing on with `undefined` fields.
